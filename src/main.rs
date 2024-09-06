use clap::Parser;
use http_auth_basic::Credentials;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls_pemfile::{certs, private_key};
use serde::Deserialize;
use std::fs::File;
use std::io;
use std::io::{BufReader, ErrorKind};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

mod http_proxy;

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

fn load_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    Ok(private_key(&mut BufReader::new(File::open(path)?))
        .unwrap()
        .ok_or(io::Error::new(
            ErrorKind::Other,
            "no private key found".to_string(),
        ))?)
}

/// Run a https proxy server
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Location of config file
    #[arg(short, long)]
    config: PathBuf,
    /// Location of certs file, will override config file
    #[arg(short = 'e', long, env)]
    certs_file: Option<PathBuf>,
    /// Location of config file
    #[arg(short, long, env)]
    private_key_file: Option<PathBuf>,
}

#[derive(Deserialize)]
struct Config {
    certs_file: Option<PathBuf>,
    private_key_file: Option<PathBuf>,
    addr: Arc<str>,
    username: Arc<str>,
    password: Arc<str>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), io::Error> {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Args::parse();

    let config_file = File::open(&args.config)
        .expect(format!("Failed to read config file {:?}", &args.config).as_str());
    let config = serde_yml::from_reader::<_, Config>(config_file)
        .expect(format!("Failed to read config file {:?}", &args.config).as_str());

    let cert_files = args
        .certs_file
        .or(config.certs_file)
        .expect("Certs file need to be either in config file, as argument or environment variable");
    let private_key_file = args.private_key_file.or(config.private_key_file).expect(
        "Private key file need to be either in config file, as argument or environment variable",
    );

    let certs = load_certs(&cert_files).expect("Failed to load certificate");
    let key = load_key(&private_key_file).expect("Failed to load private key");

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(ErrorKind::InvalidInput, err))?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(config.addr.deref()).await?;

    let cred = Arc::new(Credentials::new(
        config.username.deref(),
        config.password.deref(),
    ));

    info!("Listening on {}", config.addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let stream = acceptor.accept(stream).await;
                match stream {
                    Ok(stream) => {
                        let io = TokioIo::new(stream);
                        let cred = cred.clone();

                        tokio::task::spawn(async move {
                            let service =
                                service_fn(move |req| http_proxy::proxy(req, addr, cred.clone()));
                            info!("Processing request from {}", addr);
                            if let Err(err) = http1::Builder::new()
                                .preserve_header_case(true)
                                .title_case_headers(true)
                                .serve_connection(io, service)
                                .with_upgrades()
                                .await
                            {
                                error!("Failed to serve connection: {:?}", err);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Tls connection fail for {addr}: {e}")
                    }
                }
            }
            Err(e) => {
                error!("Tls connection fail for {}: {}", config.addr, e)
            }
        }
    }
}
