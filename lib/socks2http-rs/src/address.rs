use super::consts;
use super::socks5::{Error, Reply};
use bytes::{buf::BufExt, Buf, BufMut, BytesMut};
use std::{
    fmt::{self, Debug},
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};
use tokio::prelude::*;
/// SOCKS5 protocol error

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Address {
    SocketAddress(SocketAddr),
    DomainNameAddress(String, u16),
}

impl Address {
    pub async fn read_from<R>(stream: &mut R) -> Result<Address, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut addr_type_buf = [0u8; 1];
        let _ = stream.read_exact(&mut addr_type_buf).await?;
        let addr_type = addr_type_buf[0];
        match addr_type {
            consts::SOCKS5_ADDR_TYPE_IPV4 => {
                let mut buf = BytesMut::with_capacity(6);
                buf.resize(6, 0);
                let _ = stream.read_exact(&mut buf).await?;
                let mut cursor = buf.to_bytes();
                let v4addr = Ipv4Addr::new(
                    cursor.get_u8(),
                    cursor.get_u8(),
                    cursor.get_u8(),
                    cursor.get_u8(),
                );
                let port = cursor.get_u16();
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
                    v4addr, port,
                ))))
            }
            consts::SOCKS5_ADDR_TYPE_IPV6 => {
                let mut buf = [0u8; 18];
                let _ = stream.read_exact(&mut buf).await?;
                let mut cursor = Cursor::new(&buf);
                let v6addr = Ipv6Addr::new(
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                );
                let port = cursor.get_u16();
                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    v6addr, port, 0, 0,
                ))))
            }
            consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                let mut length_buf = [0u8; 1];
                let _ = stream.read_exact(&mut length_buf).await?;
                let length = length_buf[0] as usize;

                let buf_length = length + 2;
                let mut buf = BytesMut::with_capacity(buf_length);
                buf.resize(buf_length, 0);
                let _ = stream.read_exact(&mut buf).await?;
                let mut cursor = buf.to_bytes();
                let mut raw_addr = Vec::with_capacity(length);
                raw_addr.put(&mut BufExt::take(&mut cursor, length));
                let addr = match String::from_utf8(raw_addr) {
                    Ok(addr) => addr,
                    Err(..) => {
                        return Err(Error::new(
                            Reply::GeneralFailure,
                            "invalid address encoding",
                        ))
                    }
                };
                let port = cursor.get_u16();

                Ok(Address::DomainNameAddress(addr, port))
            }
            _ => Err(Error::new(
                Reply::AddressTypeNotSupported,
                format!("not supported addres type {:#x}", addr_type),
            )),
        }
    }
    // #[inline]
    // pub async fn write_to<W>(&self, writer: &mut W) -> io::Result<()>
    // where
    //     W: AsyncWrite + Unpin,
    // {
    //     let mut buf = BytesMut::with_capacity(self.serialized_len());
    //     self.write_to_buf(&mut buf);
    //     writer.write_all(&buf).await
    // }
    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        write_address(self, buf)
    }
    #[inline]
    pub fn serialized_len(&self) -> usize {
        get_addr_len(self)
    }
}
impl Debug for Address {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{} {}", addr, port),
        }
    }
}
impl fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}
impl std::net::ToSocketAddrs for Address {
    type Iter = std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> io::Result<std::vec::IntoIter<SocketAddr>> {
        match self.clone() {
            Address::SocketAddress(addr) => Ok(vec![addr].into_iter()),
            Address::DomainNameAddress(addr, port) => (&addr[..], port).to_socket_addrs(),
        }
    }
}
impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Address {
        Address::SocketAddress(s)
    }
}
impl From<(String, u16)> for Address {
    fn from((dn, port): (String, u16)) -> Address {
        Address::DomainNameAddress(dn, port)
    }
}
#[inline]
fn get_addr_len(atyp: &Address) -> usize {
    match *atyp {
        Address::SocketAddress(SocketAddr::V4(..)) => 1 + 4 + 2,
        Address::SocketAddress(SocketAddr::V6(..)) => 1 + 8 * 2 + 2,
        Address::DomainNameAddress(ref dmname, _) => 1 + 1 + dmname.len() + 2,
    }
}
fn write_domain_name_address<B: BufMut>(dnaddr: &str, port: u16, buf: &mut B) {
    assert!(dnaddr.len() <= u8::max_value() as usize);

    buf.put_u8(consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME);
    buf.put_u8(dnaddr.len() as u8);
    buf.put_slice(dnaddr[..].as_bytes());
    buf.put_u16(port);
}
fn write_ipv4_address<B: BufMut>(addr: &SocketAddrV4, buf: &mut B) {
    buf.put_u8(consts::SOCKS5_ADDR_TYPE_IPV4); // Address type
    buf.put_slice(&addr.ip().octets()); // Ipv4 bytes
    buf.put_u16(addr.port()); // Port
}

fn write_ipv6_address<B: BufMut>(addr: &SocketAddrV6, buf: &mut B) {
    buf.put_u8(consts::SOCKS5_ADDR_TYPE_IPV6); // Address type
    for seg in &addr.ip().segments() {
        buf.put_u16(*seg); // Ipv6 bytes
    }
    buf.put_u16(addr.port()); // Port
}
fn write_socket_address<B: BufMut>(addr: &SocketAddr, buf: &mut B) {
    match *addr {
        SocketAddr::V4(ref addr) => write_ipv4_address(addr, buf),
        SocketAddr::V6(ref addr) => write_ipv6_address(addr, buf),
    }
}
fn write_address<B: BufMut>(addr: &Address, buf: &mut B) {
    match *addr {
        Address::SocketAddress(ref addr) => write_socket_address(addr, buf),
        Address::DomainNameAddress(ref dnaddr, ref port) => {
            write_domain_name_address(dnaddr, *port, buf)
        }
    }
}

pub fn host_addr(uri: &hyper::Uri) -> Option<Address> {
    match uri.authority() {
        None => None,
        Some(authority) => {
            // NOTE: Authority may include authentication info (user:password)
            // Although it is already deprecated, but some very old application may still depending on it
            //
            // But ... We won't be compatible with it. :)

            // Check if URI has port
            match authority.port_u16() {
                Some(port) => {
                    // Well, it has port!
                    // 1. Maybe authority is a SocketAddr (127.0.0.1:1234, [::1]:1234)
                    // 2. Otherwise, it must be a domain name (google.com:443)

                    match authority.as_str().parse::<SocketAddr>() {
                        Ok(saddr) => Some(Address::from(saddr)),
                        Err(..) => Some(Address::DomainNameAddress(
                            authority.host().to_owned(),
                            port,
                        )),
                    }
                }
                None => {
                    // Ok, we don't have port
                    // 1. IPv4 Address 127.0.0.1
                    // 2. IPv6 Address: https://tools.ietf.org/html/rfc2732 , [::1]
                    // 3. Domain name

                    // Uses default port
                    let port = match uri.scheme_str() {
                        None => 80, // Assume it is http
                        Some("http") => 80,
                        Some("https") => 443,
                        _ => return None, // Not supported
                    };

                    // RFC2732 indicates that IPv6 address should be wrapped in [ and ]
                    let authority_str = authority.as_str();
                    if authority_str.starts_with('[') && authority_str.ends_with(']') {
                        // Must be a IPv6 address
                        let addr = authority_str.trim_start_matches('[').trim_end_matches(']');
                        match addr.parse::<std::net::IpAddr>() {
                            Ok(a) => Some(Address::from(SocketAddr::new(a, port))),
                            // Ignore invalid IPv6 address
                            Err(..) => None,
                        }
                    } else {
                        // Maybe it is a IPv4 address, or a non-standard IPv6
                        match authority_str.parse::<std::net::IpAddr>() {
                            Ok(a) => Some(Address::from(SocketAddr::new(a, port))),
                            // Should be a domain name, or a invalid IP address.
                            // Let DNS deal with it.
                            Err(..) => {
                                Some(Address::DomainNameAddress(authority_str.to_owned(), port))
                            }
                        }
                    }
                }
            }
        }
    }
}
