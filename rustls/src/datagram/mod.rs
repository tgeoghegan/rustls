//! Implements parts of Datagram TLS (DTLS), specified in [RFC 6347][1] (DTLS
//! 1.2) and [RFC 9147][2] (DTLS 1.3).
//!
//! [1]: https://datatracker.ietf.org/doc/html/rfc6347
//! [2]: https://datatracker.ietf.org/doc/html/rfc9147

use std::boxed::Box;
use std::fmt::Debug;
use std::net::UdpSocket;
use std::sync::Arc;

use pki_types::ServerName;

use crate::client::ClientSide;
use crate::common_state::{Output, Protocol};
use crate::conn::{ConnectionCommon, ConnectionCore};
use crate::msgs::{ClientExtensionsInput, Message, U48};
use crate::{ClientConfig, SideData};

/// Errors encountered while sending or receiving data on a `DtlsSocket`.
#[derive(Debug)]
pub enum Error {
    Other(Box<dyn std::error::Error>),
}

pub struct ClientDtlsSocket<SocketLike> {
    inner: DtlsSocket<SocketLike, ClientSide>,
}

impl<SocketLike: UdpSocketLike> ClientDtlsSocket<SocketLike> {
    pub fn new(
        config: ClientConfig,
        server_name: ServerName<'static>,
        inner: SocketLike,
    ) -> Result<Self, Error> {
        let connection_core = ConnectionCore::for_client(
            Arc::new(config),
            server_name,
            // TODO client extensions? Probably need something akin to ConnectionBuilder
            ClientExtensionsInput {
                transport_parameters: None,
                protocols: None,
            },
            // Never QUIC since this is UDP
            None,
            Protocol::Udp,
        )
        .map_err(|e| Error::Other(e.into()))?;
        Ok(Self {
            inner: DtlsSocket::new(inner, connection_core),
        })
    }

    /// API used by crate clients to send plaintext bytes.
    ///
    /// Under the covers we'll do handshake as needed and also encrypt content
    /// into EncodedMessage.
    ///
    /// Returns number of bytes transmitted, not including DTLS overhead.
    fn send<B: AsRef<[u8]>>(&mut self, bytes: B) -> Result<usize, Error> {
        self.inner.send(bytes)
    }

    /// API used by crate clients to receive plaintext bytes.
    ///
    /// Under the covers we'll do handshake as needed and also encrypt content
    /// into EncodedMessage.
    ///
    /// Returns number of bytes transmitted, not including DTLS overhead.
    fn recv<B: AsMut<[u8]>>(&mut self, bytes: B) -> Result<usize, Error> {
        self.inner.recv(bytes)
    }
}

/// Wraps a [`std::net::UdpSocket`] with the timeout and retransmission logic
/// for handshake messages.
pub(crate) struct DtlsSocket<SocketLike, Side: SideData> {
    /// Current epoch.
    epoch: u16,
    /// Current sequence number.
    sequence: U48,
    /// Inner socket on which messages will be received and sent.
    inner: SocketLike,
    /// Connection internals
    core: ConnectionCore<Side>,
}

impl<SocketLike: UdpSocketLike, Side: SideData> DtlsSocket<SocketLike, Side> {
    fn new(inner: SocketLike, core: ConnectionCore<Side>) -> Self {
        Self {
            epoch: 0,
            sequence: U48(0),
            inner,
            core,
        }
    }

    /// API used by crate clients to send plaintext bytes.
    ///
    /// Under the covers we'll do handshake as needed and also encrypt content
    /// into EncodedMessage.
    ///
    /// Returns number of bytes transmitted, not including DTLS overhead.
    fn send<B: AsRef<[u8]>>(&mut self, bytes: B) -> Result<usize, Error> {
        todo!()
    }

    /// API used by crate clients to receive plaintext bytes.
    ///
    /// Under the covers we'll do handshake as needed and also encrypt content
    /// into EncodedMessage.
    ///
    /// Returns number of bytes transmitted, not including DTLS overhead.
    fn recv<B: AsMut<[u8]>>(&mut self, bytes: B) -> Result<usize, Error> {
        todo!()
    }
}

/// Something akin to a UDP socket which can send and receive data, but does not
/// implement [`std::io::Write`] or [`std::io::Read`].
pub(crate) trait UdpSocketLike {
    type Error: std::error::Error;

    /// Send data.
    fn send<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<usize, Self::Error>;

    /// Receive data.
    fn recv<B: AsMut<[u8]>>(&mut self, buf: B) -> Result<usize, Self::Error>;
}

impl UdpSocketLike for UdpSocket {
    type Error = std::io::Error;

    fn send<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<usize, Self::Error> {
        UdpSocket::send(&self, buf.as_ref())
    }

    fn recv<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<usize, Self::Error> {
        UdpSocket::recv(&self, buf.as_mut())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;
    use std::println;
    use std::sync::Arc;
    use std::vec::Vec;

    use crate::RootCertStore;
    use crate::client::hs::ClientState;
    use crate::crypto::TEST_PROVIDER;
    use crate::msgs::hex;

    use super::*;

    #[derive(Debug, Clone)]
    struct InMemoryBuffersError(&'static str);

    impl Display for InMemoryBuffersError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            Display::fmt(self.0, f)
        }
    }

    impl std::error::Error for InMemoryBuffersError {}

    #[derive(Clone, Debug, Default)]
    struct InMemoryBuffers {
        send: Vec<u8>,
        receive: Vec<u8>,
        receive_position: usize,
    }

    impl UdpSocketLike for InMemoryBuffers {
        type Error = InMemoryBuffersError;

        fn send<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<usize, Self::Error> {
            let slice = buf.as_ref();

            self.send.extend_from_slice(slice);

            Ok(slice.len())
        }

        fn recv<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<usize, Self::Error> {
            let mut slice = buf.as_mut();

            let remaining_receive_bytes = self.receive.len() - self.receive_position;

            slice[..remaining_receive_bytes]
                .copy_from_slice(&self.receive[self.receive_position..remaining_receive_bytes]);

            Ok(remaining_receive_bytes)
        }
    }

    #[test]
    fn client() {
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };

        let mut config = ClientConfig::builder(Arc::new(TEST_PROVIDER.clone()))
            .with_root_certificates(root_store)
            .with_no_client_auth()
            .unwrap();

        // This is where we might instantiate an std::net::UdpSocket bound to a particular host
        // socketaddr and connecting to a particular other socketaddr. In the test we use in memory
        // buffers to simulate transmission.
        let transport = InMemoryBuffers::default();

        let mut client_socket =
            ClientDtlsSocket::new(config, "example.org".try_into().unwrap(), transport).unwrap();

        let state = client_socket
            .inner
            .core
            .state
            .as_ref()
            .unwrap();
        match state {
            ClientState::ServerHello(_) => println!("server hello"),
            ClientState::ServerHelloOrHelloRetryRequest(_) => {
                println!("ServerHelloOrHelloRetryRequest")
            }
            ClientState::Tls12(_) => panic!("Tls12"),
            ClientState::Tls13(_) => panic!("Tls13"),
        }

        let send_peek = client_socket
            .inner
            .core
            .common
            .send
            .sendable_tls
            .peek()
            .unwrap();

        println!("send path chunk vec buffer: ");
        hex_dump(&send_peek);

        client_socket
            .send(b"some bytes here")
            .unwrap();

        // Not sure what to check on in transport.
    }

    fn hex_dump<B: AsRef<[u8]>>(buf: B) {
        let slice = buf.as_ref();
        for (idx, byte) in slice.iter().enumerate() {
            if idx % 8 == 0 {
                std::print!("\n");
            }
            std::print!("{byte:02x} ");
        }
    }
}
