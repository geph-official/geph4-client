use crate::address::{host_addr, Address};
use crate::http_client;
use crate::socks5;
use http::{
    uri::{Authority, Scheme, Uri},
    Method,
};
use http::{HeaderMap, HeaderValue, Version};
use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Request, Response,
};
use log::{debug, error, trace};
use std::convert::Infallible;
use std::net::SocketAddr;
pub async fn run(listen_addr: SocketAddr, proxy_address: SocketAddr) -> std::io::Result<()> {
    let shared_server: SharedProxyServer = ProxyServer::new_shared(proxy_address);
    let make_service = make_service_fn(|socket: &AddrStream| {
        let client_addr = socket.remote_addr();
        let cloned_server = shared_server.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                server_dispatch(req, client_addr, cloned_server.clone())
            }))
        }
    });
    let server = hyper::Server::bind(&listen_addr)
        .http1_only(true)
        .serve(make_service);
    if let Err(err) = server.await {
        use std::io::Error;
        return Err(Error::new(std::io::ErrorKind::Other, err));
    }
    Ok(())
}

use std::str::FromStr;
async fn server_dispatch(
    mut req: Request<Body>,
    client_addr: SocketAddr,
    proxy_server: SharedProxyServer,
) -> std::io::Result<Response<Body>> {
    let host = match host_addr(req.uri()) {
        None => {
            if req.uri().authority().is_some() {
                error!(
                    "HTTP {} URI {} doesn't have a valid host",
                    req.method(),
                    req.uri()
                );
                return make_bad_request();
            } else {
                trace!(
                    "HTTP {} URI {} doesn't have a valid host",
                    req.method(),
                    req.uri()
                );
            }
            match req.headers().get("Host") {
                None => {
                    return make_bad_request();
                }
                Some(hhost) => match hhost.to_str() {
                    Err(..) => {
                        return make_bad_request();
                    }
                    Ok(shost) => {
                        match Authority::from_str(shost) {
                            Ok(authority) => {
                                match authority_addr(req.uri().scheme_str(), &authority) {
                                    Some(host) => {
                                        trace!(
                                            "HTTP {} URI {} got host from header: {}",
                                            req.method(),
                                            req.uri(),
                                            host
                                        );

                                        // Reassemble URI
                                        let mut parts = req.uri().clone().into_parts();
                                        if parts.scheme.is_none() {
                                            // Use http as default.
                                            parts.scheme = Some(Scheme::HTTP);
                                        }
                                        parts.authority = Some(authority);

                                        // Replaces URI
                                        *req.uri_mut() =
                                            Uri::from_parts(parts).expect("Reassemble URI failed");

                                        debug!("Reassembled URI from \"Host\", {}", req.uri());

                                        host
                                    }
                                    None => {
                                        error!(
                                            "HTTP {} URI {} \"Host\" header invalid, value: {}",
                                            req.method(),
                                            req.uri(),
                                            shost
                                        );

                                        return make_bad_request();
                                    }
                                }
                            }
                            Err(..) => {
                                error!(
                                    "HTTP {} URI {} \"Host\" header is not an Authority, value: {:?}",
                                    req.method(),
                                    req.uri(),
                                    hhost
                                );

                                return make_bad_request();
                            }
                        }
                    }
                },
            }
        }
        Some(h) => h,
    };
    if Method::CONNECT == req.method() {
        let addr: SocketAddr = proxy_server.addr;
        let stream = socks5::connect(&host, &addr).await?;
        debug!(
            "CONNECT relay connected {} <-> {} ({})",
            client_addr, addr, host
        );
        tokio::spawn(async move {
            match req.into_body().on_upgrade().await {
                Ok(upgraded) => {
                    trace!(
                        "CONNECT tunnel upgrade success, {} <-> {} ({})",
                        client_addr,
                        addr,
                        host
                    );
                    establish_connect_tunnel(upgraded, stream, &addr, client_addr, host).await
                }
                Err(e) => {
                    error!(
                        "Failed to upgrade TCP tunnel {} <-> {} ({}), error: {}",
                        client_addr, addr, host, e
                    );
                }
            }
        });
        let resp = Response::builder().body(Body::empty()).unwrap();
        return Ok(resp);
    } else {
        let method = req.method().clone();
        debug!("HTTP {} {}", method, host);
        let conn_keep_alive = check_keep_alive(req.version(), req.headers(), true);
        clear_hop_headers(req.headers_mut());
        set_conn_keep_alive(req.version(), req.headers_mut(), conn_keep_alive);
        let mut res: Response<Body> = match proxy_server.client.request(req).await {
            Ok(res) => res,
            Err(err) => {
                error!(
                    "HTTP {} {} <-> {} ({}) relay failed, error: {}",
                    method, client_addr, "127.0.0.1:1080", host, err
                );
                let mut resp = Response::new(Body::from(format!("Relay failed to {}", host)));
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(resp);
            }
        };
        let res_keep_alive =
            conn_keep_alive && check_keep_alive(res.version(), res.headers(), false);
        clear_hop_headers(res.headers_mut());
        set_conn_keep_alive(res.version(), res.headers_mut(), res_keep_alive);
        Ok(res)
    }
}
use futures::future::{self, Either};
use hyper::{upgrade::Upgraded, StatusCode};
use std::io::ErrorKind;
use tokio::net::TcpStream;
async fn establish_connect_tunnel(
    upgraded: Upgraded,
    mut stream: TcpStream,
    svr_addr: &SocketAddr,
    client_addr: SocketAddr,
    addr: Address,
) {
    use tokio::io::{copy, split};

    let (mut r, mut w) = split(upgraded);
    let (mut svr_r, mut svr_w) = stream.split();

    let rhalf = copy(&mut r, &mut svr_w);
    let whalf = copy(&mut svr_r, &mut w);

    debug!(
        "CONNECT relay established {} <-> {} ({})",
        client_addr, svr_addr, addr
    );

    match future::select(rhalf, whalf).await {
        Either::Left((Ok(..), _)) => trace!(
            "CONNECT relay {} -> {} ({}) closed",
            client_addr,
            svr_addr,
            addr
        ),
        Either::Left((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!(
                    "CONNECT relay {} -> {} ({}) closed with error {}",
                    client_addr,
                    svr_addr,
                    addr,
                    err,
                );
            } else {
                error!(
                    "CONNECT relay {} -> {} ({}) closed with error {}",
                    client_addr, svr_addr, addr, err,
                );
            }
        }
        Either::Right((Ok(..), _)) => trace!(
            "CONNECT relay {} <- {} ({}) closed",
            client_addr,
            svr_addr,
            addr
        ),
        Either::Right((Err(err), _)) => {
            if let ErrorKind::TimedOut = err.kind() {
                trace!(
                    "CONNECT relay {} <- {} ({}) closed with error {}",
                    client_addr,
                    svr_addr,
                    addr,
                    err,
                );
            } else {
                error!(
                    "CONNECT relay {} <- {} ({}) closed with error {}",
                    client_addr, svr_addr, addr, err,
                );
            }
        }
    }

    debug!(
        "CONNECT relay {} <-> {} ({}) closed",
        client_addr, svr_addr, addr
    );
}

fn make_bad_request() -> std::io::Result<Response<Body>> {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::BAD_REQUEST;
    Ok(resp)
}

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
fn authority_addr(scheme_str: Option<&str>, authority: &Authority) -> Option<Address> {
    // RFC7230 indicates that we should ignore userinfo
    // https://tools.ietf.org/html/rfc7230#section-5.3.3

    // Check if URI has port
    let port = match authority.port_u16() {
        Some(port) => port,
        None => {
            match scheme_str {
                None => 80, // Assume it is http
                Some("http") => 80,
                Some("https") => 443,
                _ => return None, // Not supported
            }
        }
    };

    let host_str = authority.host();

    // RFC3986 indicates that IPv6 address should be wrapped in [ and ]
    // https://tools.ietf.org/html/rfc3986#section-3.2.2
    //
    // Example: [::1] without port
    if host_str.starts_with('[') && host_str.ends_with(']') {
        // Must be a IPv6 address
        let addr = &host_str[1..host_str.len() - 1];
        match addr.parse::<Ipv6Addr>() {
            Ok(a) => Some(Address::from(SocketAddr::new(IpAddr::V6(a), port))),
            // Ignore invalid IPv6 address
            Err(..) => None,
        }
    } else {
        // It must be a IPv4 address
        match host_str.parse::<Ipv4Addr>() {
            Ok(a) => Some(Address::from(SocketAddr::new(IpAddr::V4(a), port))),
            // Should be a domain name, or a invalid IP address.
            // Let DNS deal with it.
            Err(..) => Some(Address::DomainNameAddress(host_str.to_owned(), port)),
        }
    }
}
fn check_keep_alive(version: Version, headers: &HeaderMap<HeaderValue>, check_proxy: bool) -> bool {
    let mut conn_keep_alive = match version {
        Version::HTTP_10 => false,
        Version::HTTP_11 => true,
        _ => unimplemented!("HTTP Proxy only supports 1.0 and 1.1"),
    };

    if check_proxy {
        // Modern browers will send Proxy-Connection instead of Connection
        // for HTTP/1.0 proxies which blindly forward Connection to remote
        //
        // https://tools.ietf.org/html/rfc7230#appendix-A.1.2
        for value in headers.get_all("Proxy-Connection") {
            if let Ok(value) = value.to_str() {
                if value.eq_ignore_ascii_case("close") {
                    conn_keep_alive = false;
                } else {
                    for part in value.split(',') {
                        let part = part.trim();
                        if part.eq_ignore_ascii_case("keep-alive") {
                            conn_keep_alive = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    // Connection will replace Proxy-Connection
    //
    // But why client sent both Connection and Proxy-Connection? That's not standard!
    for value in headers.get_all("Connection") {
        if let Ok(value) = value.to_str() {
            if value.eq_ignore_ascii_case("close") {
                conn_keep_alive = false;
            } else {
                for part in value.split(',') {
                    let part = part.trim();

                    if part.eq_ignore_ascii_case("keep-alive") {
                        conn_keep_alive = true;
                        break;
                    }
                }
            }
        }
    }

    conn_keep_alive
}

fn clear_hop_headers(headers: &mut HeaderMap<HeaderValue>) {
    // Clear headers indicated by Connection and Proxy-Connection
    let mut extra_headers = Vec::new();

    for connection in headers.get_all("Connection") {
        if let Ok(conn) = connection.to_str() {
            if !conn.eq_ignore_ascii_case("close") {
                for header in conn.split(',') {
                    let header = header.trim();

                    if !header.eq_ignore_ascii_case("keep-alive") {
                        extra_headers.push(header.to_owned());
                    }
                }
            }
        }
    }

    for connection in headers.get_all("Proxy-Connection") {
        if let Ok(conn) = connection.to_str() {
            if !conn.eq_ignore_ascii_case("close") {
                for header in conn.split(',') {
                    let header = header.trim();

                    if !header.eq_ignore_ascii_case("keep-alive") {
                        extra_headers.push(header.to_owned());
                    }
                }
            }
        }
    }

    for header in extra_headers {
        while let Some(..) = headers.remove(&header) {}
    }

    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
    const HOP_BY_HOP_HEADERS: [&str; 9] = [
        "Keep-Alive",
        "Transfer-Encoding",
        "TE",
        "Connection",
        "Trailer",
        "Upgrade",
        "Proxy-Authorization",
        "Proxy-Authenticate",
        "Proxy-Connection", // Not standard, but many implementations do send this header
    ];

    for header in &HOP_BY_HOP_HEADERS {
        while let Some(..) = headers.remove(*header) {}
    }
}

fn set_conn_keep_alive(version: Version, headers: &mut HeaderMap<HeaderValue>, keep_alive: bool) {
    match version {
        Version::HTTP_10 => {
            // HTTP/1.0 close connection by default
            if keep_alive {
                headers.insert("Connection", HeaderValue::from_static("keep-alive"));
            }
        }
        Version::HTTP_11 => {
            // HTTP/1.1 keep-alive connection by default
            if !keep_alive {
                headers.insert("Connection", HeaderValue::from_static("close"));
            }
        }
        _ => unimplemented!("HTTP Proxy only supports 1.0 and 1.1"),
    }
}
#[derive(Clone)]
pub struct ProxyServer {
    client: http_client::SocksClient,
    addr: SocketAddr,
}
pub type SharedProxyServer = std::sync::Arc<ProxyServer>;
impl ProxyServer {
    fn new(addr: SocketAddr) -> ProxyServer {
        let connector = http_client::SocksConnector::new(addr);
        let proxy_client: http_client::SocksClient = hyper::Client::builder().build(connector);
        ProxyServer {
            addr,
            client: proxy_client,
        }
    }
    fn new_shared(addr: SocketAddr) -> SharedProxyServer {
        std::sync::Arc::new(ProxyServer::new(addr))
    }
}
