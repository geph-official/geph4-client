use crate::address::Address;
use crate::consts;
use bytes::{BufMut, BytesMut};
use std::{
    error,
    fmt::{self, Debug},
    io,
};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::prelude::*;
#[derive(Clone, Debug, Copy)]
pub enum Command {
    /// CONNECT command (TCP tunnel)
    TcpConnect,
}
impl Command {
    #[inline]
    fn as_u8(self) -> u8 {
        match self {
            Command::TcpConnect => consts::SOCKS5_CMD_TCP_CONNECT,
        }
    }
    // #[inline]
    // fn from_u8(code: u8) -> Option<Command> {
    //     match code {
    //         consts::SOCKS5_CMD_TCP_CONNECT => Some(Command::TcpConnect),
    //         consts::SOCKS5_CMD_TCP_BIND => Some(Command::TcpBind),
    //         consts::SOCKS5_CMD_UDP_ASSOCIATE => Some(Command::UdpAssociate),
    //         _ => None,
    //     }
    // }
}
#[derive(Clone, Debug)]
pub struct TcpRequestHeader {
    /// SOCKS5 command
    pub command: Command,
    /// Remote address
    pub address: Address,
}

pub async fn connect<S: tokio::net::ToSocketAddrs>(
    addr: &Address,
    proxy: &S,
) -> io::Result<TcpStream> {
    let mut client_stream = TcpStream::connect(proxy).await?;
    // handshake
    let handshake_request = HandshakeRequest::new(vec![consts::SOCKS5_AUTH_METHOD_NONE]);
    handshake_request.write_to(&mut client_stream).await?;
    client_stream.flush().await?;
    let handshake_respone = HandshakeResponse::read_from(&mut client_stream).await?;
    assert_eq!(
        handshake_respone.chosen_method,
        consts::SOCKS5_AUTH_METHOD_NONE
    );

    // connect
    let tcp_req_header = TcpRequestHeader::new(Command::TcpConnect, addr.clone());
    tcp_req_header.write_to(&mut client_stream).await?;
    client_stream.flush().await?;

    let tcp_res_header = TcpResponseHeader::read_from(&mut client_stream).await?;
    match tcp_res_header.reply {
        Reply::Succeeded => {}
        r => {
            let err = io::Error::new(io::ErrorKind::Other, format!("{}", r));
            return Err(err);
        }
    }
    Ok(client_stream)
}

impl TcpRequestHeader {
    pub fn new(cmd: Command, addr: Address) -> TcpRequestHeader {
        TcpRequestHeader {
            command: cmd,
            address: addr,
        }
    }
    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let TcpRequestHeader {
            ref address,
            ref command,
        } = *self;

        buf.put_slice(&[consts::SOCKS5_VERSION, command.as_u8(), 0x00]);
        address.write_to_buf(buf);
    }
    /// Length in bytes
    #[inline]
    pub fn serialized_len(&self) -> usize {
        self.address.serialized_len() + 3
    }
}
#[derive(Clone, Debug)]
pub struct HandshakeRequest {
    pub methods: Vec<u8>,
}
impl HandshakeRequest {
    /// Creates a handshake request
    pub fn new(methods: Vec<u8>) -> HandshakeRequest {
        HandshakeRequest { methods }
    }
    /// Write to a writer
    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = BytesMut::with_capacity(self.serialized_len());
        self.write_to_buf(&mut buf);
        w.write_all(&buf).await
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        let HandshakeRequest { ref methods } = *self;
        buf.put_slice(&[consts::SOCKS5_VERSION, methods.len() as u8]);
        buf.put_slice(&methods);
    }

    /// Get length of bytes
    pub fn serialized_len(&self) -> usize {
        2 + self.methods.len()
    }
}
#[derive(Clone, Debug, Copy)]
pub struct HandshakeResponse {
    pub chosen_method: u8,
}
impl HandshakeResponse {
    /// Creates a handshake response
    // pub fn new(cm: u8) -> HandshakeResponse {
    //     HandshakeResponse { chosen_method: cm }
    // }

    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> io::Result<HandshakeResponse>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 2];
        let _ = r.read_exact(&mut buf).await?;

        let ver = buf[0];
        let met = buf[1];

        if ver != consts::SOCKS5_VERSION {
            use std::io::{Error, ErrorKind};
            let err = Error::new(
                ErrorKind::InvalidData,
                format!("unsupported socks version {:#x}", ver),
            );
            Err(err)
        } else {
            Ok(HandshakeResponse { chosen_method: met })
        }
    }
}
#[derive(Clone, Debug)]
pub struct TcpResponseHeader {
    /// SOCKS5 reply
    pub reply: Reply,
    /// Reply address
    pub address: Address,
}
impl TcpResponseHeader {

    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> Result<TcpResponseHeader, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 3];
        let _ = r.read_exact(&mut buf).await?;
        let ver = buf[0];
        let reply_code = buf[1];

        if ver != consts::SOCKS5_VERSION {
            return Err(Error::new(
                Reply::ConnectionRefused,
                format!("unsupported socks version {:#x}", ver),
            ));
        }
        let address = Address::read_from(r).await?;
        Ok(TcpResponseHeader {
            reply: Reply::from_u8(reply_code),
            address,
        })
    }
}
#[derive(Clone, Debug, Copy)]
pub enum Reply {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,

    OtherReply(u8),
}
impl Reply {
    #[inline]
    #[rustfmt::skip]
    fn from_u8(code: u8) -> Reply {
        match code {
            consts::SOCKS5_REPLY_SUCCEEDED                  => Reply::Succeeded,
            consts::SOCKS5_REPLY_GENERAL_FAILURE            => Reply::GeneralFailure,
            consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED     => Reply::ConnectionNotAllowed,
            consts::SOCKS5_REPLY_NETWORK_UNREACHABLE        => Reply::NetworkUnreachable,
            consts::SOCKS5_REPLY_HOST_UNREACHABLE           => Reply::HostUnreachable,
            consts::SOCKS5_REPLY_CONNECTION_REFUSED         => Reply::ConnectionRefused,
            consts::SOCKS5_REPLY_TTL_EXPIRED                => Reply::TtlExpired,
            consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED      => Reply::CommandNotSupported,
            consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => Reply::AddressTypeNotSupported,
            _                                               => Reply::OtherReply(code),
        }
    }
}
impl fmt::Display for Reply {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Reply::Succeeded               => write!(f, "Succeeded"),
            Reply::AddressTypeNotSupported => write!(f, "Address type not supported"),
            Reply::CommandNotSupported     => write!(f, "Command not supported"),
            Reply::ConnectionNotAllowed    => write!(f, "Connection not allowed"),
            Reply::ConnectionRefused       => write!(f, "Connection refused"),
            Reply::GeneralFailure          => write!(f, "General failure"),
            Reply::HostUnreachable         => write!(f, "Host unreachable"),
            Reply::NetworkUnreachable      => write!(f, "Network unreachable"),
            Reply::OtherReply(u)           => write!(f, "Other reply ({})", u),
            Reply::TtlExpired              => write!(f, "TTL expired"),
        }
    }
}

#[derive(Clone)]
pub struct Error {
    /// Reply code
    pub reply: Reply,
    /// Error message
    pub message: String,
}
impl Error {
    pub fn new<S>(reply: Reply, message: S) -> Error
    where
        S: Into<String>,
    {
        Error {
            reply,
            message: message.into(),
        }
    }
}
impl Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl error::Error for Error {}
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::new(Reply::GeneralFailure, err.to_string())
    }
}
impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        io::Error::new(io::ErrorKind::Other, err.message)
    }
}
