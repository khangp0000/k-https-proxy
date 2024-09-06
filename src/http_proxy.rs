use http_auth_basic::Credentials;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::upgrade::Upgraded;
use hyper::{client, http, Method, Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

#[instrument(skip_all,fields(id = Uuid::new_v4().to_string(), client_ip = client_addr.ip().to_canonical().to_string(), http.uri = req.uri().to_string(), http.method = req.method().to_string()))]
pub async fn proxy(
    mut req: Request<Incoming>,
    client_addr: SocketAddr,
    expect_cred: Arc<Credentials>,
) -> Result<Response<Either<BoxBody<Bytes, hyper::Error>, Incoming>>, hyper::Error> {
    let proxy_auth = req.headers_mut().remove(hyper::header::PROXY_AUTHORIZATION);

    let auth_result: Result<(), &str> = proxy_auth
        .ok_or("Missing Proxy-Authorization header")
        .and_then(|proxy_auth| {
            proxy_auth
                .to_str()
                .ok()
                .map(|s| s.parse().ok())
                .flatten()
                .ok_or("Invalid Proxy-Authorization header")
        })
        .and_then(|cred: Credentials| {
            if &cred == expect_cred.deref() {
                Ok(())
            } else {
                Err("Mismatch Proxy-Authorization header")
            }
        });

    if let Err(err) = auth_result {
        warn!("Unauthorized access: {}", err);
        let mut resp = Response::new(Either::Left(empty()));
        *resp.status_mut() = http::StatusCode::UNAUTHORIZED;
        return Ok(resp);
    }

    if Method::CONNECT == req.method() {
        info!("Proxying HTTPS");

        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        if let Some(addr) = req
            .uri()
            .authority()
            .and_then(|auth| Some(auth.to_string()))
        {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr).await {
                            warn!("server io error: {}", e);
                        };
                    }
                    Err(e) => warn!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(Either::Left(empty())))
        } else {
            error!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(Either::Left(full("CONNECT must be to a socket address")));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        info!("Proxying HTTP");
        let host = req.uri().host();
        if host.is_none() {
            let mut resp = Response::new(Either::Left(full("Invalid uri in host")));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;
            return Ok(resp);
        }
        let host = host.unwrap();
        let port = req.uri().port_u16().unwrap_or(80);

        let stream = TcpStream::connect((host, port)).await.unwrap();
        let io = TokioIo::new(stream);

        let (mut sender, conn) = client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await?;

        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                error!("Connection failed: {:?}", err);
            }
        });

        let resp = sender.send_request(req).await?;
        Ok(resp.map(|b| Either::Right(b)))
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);

    // Proxying data
    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    // Print message when done
    info!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}
