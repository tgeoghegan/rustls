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
use crate::common_state::Protocol;
use crate::conn::ConnectionCore;
use crate::crypto::cipher::OutboundPlain;
use crate::msgs::{ClientExtensionsInput, ServerExtensionsInput, U48};
use crate::server::ServerSide;
use crate::vecbuf::ChunkVecBuffer;
use crate::{ClientConfig, ServerConfig, SideData};

/// Errors encountered while sending or receiving data on a `DtlsSocket`.
#[derive(Debug)]
pub(crate) enum Error {
    Other(Box<dyn std::error::Error>),
}

pub(crate) struct ClientDtlsSocket<SocketLike> {
    inner: DtlsSocket<SocketLike, ClientSide>,
}

impl<SocketLike: UdpSocketLike> ClientDtlsSocket<SocketLike> {
    pub(crate) fn new(
        config: ClientConfig,
        server_name: ServerName<'static>,
        inner: SocketLike,
    ) -> Result<Self, Error> {
        let connection_core = ConnectionCore::for_client(
            Arc::new(config.clone()),
            server_name,
            ClientExtensionsInput::from_alpn(config.alpn_protocols),
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

pub struct ServerDtlsSocket<SocketLike> {
    inner: DtlsSocket<SocketLike, ServerSide>,
}

impl<SocketLike: UdpSocketLike> ServerDtlsSocket<SocketLike> {
    pub fn new(config: ServerConfig, inner: SocketLike) -> Result<Self, Error> {
        let connection_core = ConnectionCore::for_server(
            Arc::new(config),
            ServerExtensionsInput {
                // Never set transport parameters, that's only for QUIC
                transport_parameters: None,
            },
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
        // TODO: this should do something like the TLS side where it checks for pending handshake
        // messages and sends them
        // TODO(timg): do something smarter with this buffer
        let mut chunks = ChunkVecBuffer::new(None);
        Ok(self
            .core
            .common
            .send
            .buffer_plaintext(OutboundPlain::new(&[bytes.as_ref()]), &mut chunks))
    }

    /// API used by crate clients to receive plaintext bytes.
    ///
    /// Under the covers we'll do handshake as needed and also encrypt content
    /// into EncodedMessage.
    ///
    /// Returns number of bytes transmitted, not including DTLS overhead.
    fn recv<B: AsMut<[u8]>>(&mut self, _bytes: B) -> Result<usize, Error> {
        // TODO: this should try to pump the handshake state machine
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
    use core::hash::Hasher;
    use std::cmp::min;
    use std::collections::VecDeque;
    use std::fmt::Display;
    use std::io::Read;
    use std::sync::{Arc, Mutex};
    use std::vec::Vec;
    use std::{print, println, vec};

    use crate::RootCertStore;
    use crate::client::danger::{ServerIdentity, SignatureVerificationInput};
    use crate::client::hs::ClientState;
    use crate::crypto::{Identity, SignatureScheme, TEST_PROVIDER};
    use crate::msgs::{Delocator, VecInput, hex};
    use crate::server::hs::ServerState;
    use crate::verify::{HandshakeSignatureValid, PeerVerified, ServerVerifier};

    use pki_types::pem::PemObject;
    use pki_types::{CertificateDer, PrivateKeyDer};

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
        send: Arc<Mutex<VecDeque<Vec<u8>>>>,
        receive: Arc<Mutex<VecDeque<Vec<u8>>>>,
        receive_position: usize,
    }

    impl InMemoryBuffers {
        fn pair() -> (Self, Self) {
            let client_receive = Arc::new(Mutex::new(VecDeque::new()));
            let server_receive = Arc::new(Mutex::new(VecDeque::new()));

            (
                InMemoryBuffers {
                    send: server_receive.clone(),
                    receive: client_receive.clone(),
                    receive_position: 0,
                },
                InMemoryBuffers {
                    send: client_receive,
                    receive: server_receive,
                    receive_position: 0,
                },
            )
        }
    }

    impl UdpSocketLike for InMemoryBuffers {
        type Error = InMemoryBuffersError;

        fn send<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<usize, Self::Error> {
            let slice = buf.as_ref();

            self.send
                .lock()
                .unwrap()
                .push_back(slice.to_vec());

            Ok(slice.len())
        }

        fn recv<B: AsMut<[u8]>>(&mut self, mut buf: B) -> Result<usize, Self::Error> {
            let mut read_into = buf.as_mut();

            let mut receive_queue = self.receive.lock().unwrap();

            if let Some(received) = receive_queue.pop_front() {
                let remaining_receive_bytes = received.len() - self.receive_position;
                let bytes_read = min(remaining_receive_bytes, read_into.len());

                read_into[..bytes_read].copy_from_slice(
                    &received[self.receive_position..self.receive_position + bytes_read],
                );

                self.receive_position += bytes_read;

                if self.receive_position == received.len() {
                    self.receive_position = 0;
                } else {
                    // Put buffer back in receive queue for later read
                    receive_queue.push_front(received);
                }

                Ok(bytes_read)
            } else {
                // No buffers in queue
                return Ok(0);
            }
        }
    }

    fn server_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/ecdsa-p256/end.key").as_slice(),
        )
        .unwrap()
    }

    fn server_identity() -> Arc<Identity<'static>> {
        Arc::new(
            Identity::from_cert_chain(vec![
                CertificateDer::from(&include_bytes!("../../../test-ca/ecdsa-p256/end.der")[..]),
                CertificateDer::from(&include_bytes!("../../../test-ca/ecdsa-p256/inter.der")[..]),
            ])
            .unwrap(),
        )
    }

    #[derive(Debug, Clone)]
    struct AcceptsEverythingServerVerifier {}

    impl ServerVerifier for AcceptsEverythingServerVerifier {
        fn verify_identity(
            &self,
            identity: &ServerIdentity<'_>,
        ) -> Result<PeerVerified, crate::Error> {
            Ok(PeerVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            input: &SignatureVerificationInput<'_>,
        ) -> Result<HandshakeSignatureValid, crate::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            input: &SignatureVerificationInput<'_>,
        ) -> Result<HandshakeSignatureValid, crate::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            Vec::from([
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
            ])
        }

        fn request_ocsp_response(&self) -> bool {
            false
        }

        fn hash_config(&self, h: &mut dyn Hasher) {}
    }

    #[test]
    fn in_memory_buffer() {
        let (mut client, mut server) = InMemoryBuffers::pair();

        assert_eq!(
            client
                .send("hello from client")
                .unwrap(),
            17
        );

        let mut buf = [0u8; 1024];
        assert_eq!(server.recv(&mut buf).unwrap(), 17);
        assert_eq!(&buf[..17], b"hello from client");
        assert_eq!(server.recv(&mut buf).unwrap(), 0);

        assert_eq!(
            server
                .send("hello back from server")
                .unwrap(),
            22
        );

        assert_eq!(client.recv(&mut buf).unwrap(), 22);
        assert_eq!(&buf[..22], b"hello back from server");
        assert_eq!(client.recv(&mut buf).unwrap(), 0);

        // queue up multiple messages in server receive buffers
        let messages = [b"message 1", b"message 2"];

        for message in messages {
            assert_eq!(client.send(message).unwrap(), message.len());
        }

        // partial read of a message
        assert_eq!(server.recv(&mut buf[..4]).unwrap(), 4);
        assert_eq!(&buf[..4], b"mess");
        assert_eq!(server.recv(&mut buf[4..]).unwrap(), 5);
        assert_eq!(&buf[..9], messages[0]);
        // read second message
        assert_eq!(server.recv(&mut buf).unwrap(), 9);
        assert_eq!(&buf[..9], messages[1]);
    }

    #[test]
    fn dtls_12_full_handshake_and_application_data() {
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };

        let client_config = ClientConfig::builder(Arc::new(TEST_PROVIDER.clone()))
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptsEverythingServerVerifier {}))
            .with_no_client_auth()
            .unwrap();

        // This is where we might instantiate an std::net::UdpSocket bound to a particular host
        // socketaddr and connecting to a particular other socketaddr. In the test we use in memory
        // buffers to simulate transmission.
        let client_transport = InMemoryBuffers::default();

        let mut client_socket = ClientDtlsSocket::new(
            client_config,
            "example.org".try_into().unwrap(),
            client_transport,
        )
        .unwrap();

        let server_config = ServerConfig::builder(Arc::new(TEST_PROVIDER.clone()))
            .with_no_client_auth()
            .with_single_cert(server_identity(), server_key())
            .unwrap();

        let server_transport = InMemoryBuffers::default();

        let mut server_socket = ServerDtlsSocket::new(server_config, server_transport).unwrap();

        let state = client_socket
            .inner
            .core
            .state
            .as_ref()
            .unwrap();
        print!("client state ");
        match state {
            ClientState::ServerHello(_) => println!("ServerHello"),
            ClientState::ServerHelloOrHelloRetryRequest(_) => {
                println!("ServerHelloOrHelloRetryRequest")
            }
            ClientState::Tls12(_) => panic!("Tls12"),
            ClientState::Tls13(_) => panic!("Tls13"),
        }

        print!("server state ");
        let state = server_socket
            .inner
            .core
            .state
            .as_ref()
            .unwrap();
        match state {
            ServerState::ReadClientHello(_) => println!("ReadClientHello"),
            ServerState::ChooseConfig(_) => panic!("ChooseConfig"),
            ServerState::ClientHello(_) => println!("ClientHello"),
            ServerState::Tls12(_) => panic!("Tls12"),
            ServerState::Tls13(_) => panic!("Tls13"),
        }

        let send = client_socket
            .inner
            .core
            .common
            .send
            .sendable_tls
            .take();

        // Send the handshake records (should be a clienthello) to server so it can transition its
        // state machine
        println!("handshake records constructed by client");
        for (idx, record) in send.into_iter().enumerate() {
            println!("client -> server record #{idx}");
            hex_dump(&record);

            let mut vec_input = VecInput::default();
            let read = vec_input
                .read(&mut &record[..])
                .unwrap();
            assert_eq!(read, record.len());
            server_socket
                .inner
                .core
                .process_new_packets(&mut vec_input, None)
                .unwrap();
        }

        print!("server state ");
        let state = server_socket
            .inner
            .core
            .state
            .as_ref()
            .unwrap();
        match state {
            ServerState::ReadClientHello(_) => panic!("ReadClientHello"),
            ServerState::ChooseConfig(_) => panic!("ChooseConfig"),
            ServerState::ClientHello(_) => panic!("ClientHello"),
            ServerState::Tls12(_) => panic!("Tls12"),
            ServerState::Tls13(tls13) => println!("Tls13"),
        }

        let send = server_socket
            .inner
            .core
            .common
            .send
            .sendable_tls
            .take();
        println!("{} handshake records constructed by server", send.len());
        for (idx, record) in send.iter().enumerate() {
            println!("server -> client record #{idx}");
            hex_dump(&record);
        }

        for (_idx, record) in send.iter().enumerate() {
            let mut vec_input = VecInput::default();
            let read = vec_input
                .read(&mut &record[..])
                .unwrap();
            assert_eq!(read, record.len());
            client_socket
                .inner
                .core
                .process_new_packets(&mut vec_input, None)
                .unwrap();
        }

        let state = client_socket
            .inner
            .core
            .state
            .as_ref()
            .unwrap();
        print!("client state ");
        match state {
            ClientState::ServerHello(_) => panic!("ServerHello"),
            ClientState::ServerHelloOrHelloRetryRequest(_) => {
                panic!("ServerHelloOrHelloRetryRequest")
            }
            ClientState::Tls12(_) => panic!("Tls12"),
            ClientState::Tls13(_) => println!("Tls13 (probably expecttraffic)"),
        }

        let send = client_socket
            .inner
            .core
            .common
            .send
            .sendable_tls
            .take();
        for (idx, record) in send.iter().enumerate() {
            println!("client -> server record #{idx}");
            hex_dump(record);

            let mut vec_input = VecInput::default();
            let read = vec_input
                .read(&mut &record[..])
                .unwrap();
            assert_eq!(read, record.len());
            server_socket
                .inner
                .core
                .process_new_packets(&mut vec_input, None)
                .unwrap();
        }

        print!("server state ");
        let state = server_socket
            .inner
            .core
            .state
            .as_ref()
            .unwrap();
        match state {
            ServerState::ReadClientHello(_) => panic!("ReadClientHello"),
            ServerState::ChooseConfig(_) => panic!("ChooseConfig"),
            ServerState::ClientHello(_) => panic!("ClientHello"),
            ServerState::Tls12(_) => panic!("Tls12"),
            ServerState::Tls13(tls13) => println!("Tls13"),
        }

        // Server emits a session ticket which we'll give to the client
        let send = server_socket
            .inner
            .core
            .common
            .send
            .sendable_tls
            .take();
        println!("{} handshake records constructed by server", send.len());
        for (idx, record) in send.iter().enumerate() {
            let mut vec_input = VecInput::default();
            let read = vec_input
                .read(&mut &record[..])
                .unwrap();
            assert_eq!(read, record.len());
            client_socket
                .inner
                .core
                .process_new_packets(&mut vec_input, None)
                .unwrap();
            println!("client accepted ticket");
        }

        // Handshake is finished. Server and client should have nothing to send.
        assert!(
            server_socket
                .inner
                .core
                .common
                .send
                .sendable_tls
                .peek()
                .is_none()
        );
        assert!(
            client_socket
                .inner
                .core
                .common
                .send
                .sendable_tls
                .peek()
                .is_none()
        );

        println!("sending application data client -> server");

        let client_message = b"client sends application data";
        let sent = client_socket
            .send(client_message)
            .unwrap();
        assert_eq!(sent, client_message.len());

        let send = client_socket
            .inner
            .core
            .common
            .send
            .sendable_tls
            .take();
        for (idx, record) in send.iter().enumerate() {
            println!("client -> server record #{idx}");
            hex_dump(record);

            let mut vec_input = VecInput::default();
            let read = vec_input
                .read(&mut &record[..])
                .unwrap();
            assert_eq!(read, record.len());
            let unborrowed = server_socket
                .inner
                .core
                .process_new_packets(&mut vec_input, None)
                .unwrap()
                .unwrap();
            let payload = unborrowed.reborrow(&Delocator::new(vec_input.filled()));

            assert_eq!(payload.bytes(), client_message);
        }

        let server_message = b"server sends application data";
        let sent = server_socket
            .send(server_message)
            .unwrap();
        assert_eq!(sent, server_message.len());

        let send = server_socket
            .inner
            .core
            .common
            .send
            .sendable_tls
            .take();
        for (idx, record) in send.iter().enumerate() {
            let mut vec_input = VecInput::default();
            let read = vec_input
                .read(&mut &record[..])
                .unwrap();
            assert_eq!(read, record.len());
            let unborrowed = client_socket
                .inner
                .core
                .process_new_packets(&mut vec_input, None)
                .unwrap()
                .unwrap();
            let payload = unborrowed.reborrow(&Delocator::new(vec_input.filled()));
            assert_eq!(payload.bytes(), server_message);
        }
    }

    fn hex_dump<B: AsRef<[u8]>>(buf: B) {
        let slice = buf.as_ref();
        for (idx, byte) in slice.iter().enumerate() {
            if idx % 8 == 0 {
                std::print!("\n");
            }
            std::print!("{byte:02x} ");
        }
        std::println!("");
    }
}
