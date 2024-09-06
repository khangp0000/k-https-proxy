use clap::Parser;
use http_auth_basic::Credentials;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls_pemfile::{certs, private_key};
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
    /// Location of certificate
    #[arg(short, long, env)]
    certs_file: PathBuf,
    /// Location of private key
    #[arg(short, long, env)]
    private_key_file: PathBuf,
    /// Address to bind to
    #[arg(env)]
    addr: Arc<str>,
    /// username to authenticate proxy request
    #[arg(short, long, env)]
    username: Arc<str>,
    /// password to authenticate proxy request
    #[arg(short = 's', long, env)]
    password: Arc<str>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), io::Error> {
    let subscriber = tracing_subscriber::FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Args::parse();

    let certs = load_certs(&args.certs_file).expect("Failed to load certificate");
    let key = load_key(&args.private_key_file).expect("Failed to load private key");

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(ErrorKind::InvalidInput, err))?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(args.addr.deref()).await?;

    let cred = Arc::new(Credentials::new(
        args.username.deref(),
        args.password.deref(),
    ));

    info!("Listening on {}", args.addr);

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
                error!("Tls connection fail for {}: {}", args.addr, e)
            }
        }
    }
}
