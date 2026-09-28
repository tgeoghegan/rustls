use std::borrow::Cow;
use std::sync::Arc;

use rustls::client::ClientSocket;
use rustls::crypto::{AntiReplay, CryptoProvider};
use rustls::datagram::Socket;
use rustls::enums::ProtocolVersion;
use rustls::server::ServerSocket;
use rustls::{
    AckRecordSequenceNumber, ClientConfig, Epoch, Error, FullRecordSequenceNumber, ServerConfig,
    VecInput,
};
use rustls_test::{KeyType, make_client_config, make_server_config, server_name};

use super::provider;

#[test]
fn versions() {
    // UDP, default, DTLS 1.3
    setup_test_with_versions(&[], &[], Some(ProtocolVersion::DTLSv1_3));

    // UDP, client default, server 1.2 -> 1.2
    setup_test_with_versions(
        &[],
        &[ProtocolVersion::DTLSv1_2],
        Some(ProtocolVersion::DTLSv1_2),
    );

    // UDP, client 1.2, server default -> 1.2
    setup_test_with_versions(
        &[ProtocolVersion::DTLSv1_2],
        &[],
        Some(ProtocolVersion::DTLSv1_2),
    );

    // UDP, client 1.2, server 1.3 -> fail
    setup_test_with_versions(
        &[ProtocolVersion::DTLSv1_2],
        &[ProtocolVersion::DTLSv1_3],
        None,
    );

    // UDP, client 1.3, server 1.2 -> fail
    setup_test_with_versions(
        &[ProtocolVersion::DTLSv1_3],
        &[ProtocolVersion::DTLSv1_2],
        None,
    );

    // UDP, client 1.3, server 1.2+1.3 -> 1.3
    setup_test_with_versions(
        &[ProtocolVersion::DTLSv1_3],
        &[ProtocolVersion::DTLSv1_2, ProtocolVersion::DTLSv1_3],
        Some(ProtocolVersion::DTLSv1_3),
    );

    // UDP, client 1.3, server 1.3 -> 1.3
    setup_test_with_versions(
        &[ProtocolVersion::DTLSv1_3],
        &[ProtocolVersion::DTLSv1_3],
        Some(ProtocolVersion::DTLSv1_3),
    );

    // UDP, client 1.2+1.3, server 1.2 -> 1.2
    setup_test_with_versions(
        &[ProtocolVersion::DTLSv1_3, ProtocolVersion::DTLSv1_2],
        &[ProtocolVersion::DTLSv1_2],
        Some(ProtocolVersion::DTLSv1_2),
    );
}

#[test]
fn anti_replay_dtls_12() {
    anti_replay_test(ProtocolVersion::DTLSv1_2);
}

#[test]
fn anti_replay_dtls_13() {
    anti_replay_test(ProtocolVersion::DTLSv1_3);
}

#[test]
fn handshake_flight_acks() {
    // Force DTLS 1.3 as 1.2 has no ACKs
    let provider = CryptoProvider {
        tls12_cipher_suites: Cow::Borrowed(&[]),
        ..provider::DEFAULT_PROVIDER
    };

    let client_config = make_client_config(KeyType::default(), &provider);
    let server_config = make_server_config(KeyType::default(), &provider);

    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) =
        make_pair_for_configs(client_config, server_config, &mut client_output);
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    assert_eq!(client.protocol_version(), None);
    assert_eq!(server.protocol_version(), None);

    assert!(
        client
            .records_acked_by_peer()
            .is_empty()
    );
    assert!(
        server
            .records_acked_by_peer()
            .is_empty()
    );

    let mut server_received = Vec::new();
    let mut client_received = Vec::new();

    // Client sends ClientHello, server responds with ServerHello-Finished flight. We expect no ACKs.
    transfer(&mut client_output, &mut server_input);
    server
        .read_tls(&mut server_input, &mut server_output)
        .handle_all(&mut server_received)
        .unwrap();
    transfer(&mut server_output, &mut client_input);
    client
        .read_tls(&mut client_input, &mut client_output)
        .handle_all(&mut client_received)
        .unwrap();

    assert!(
        client
            .records_acked_by_peer()
            .is_empty()
    );
    assert!(
        server
            .records_acked_by_peer()
            .is_empty()
    );

    // Client sends Finished, server ACKs that flight.
    transfer(&mut client_output, &mut server_input);
    server
        .read_tls(&mut server_input, &mut server_output)
        .handle_all(&mut server_received)
        .unwrap();
    transfer(&mut server_output, &mut client_input);
    client
        .read_tls(&mut client_input, &mut client_output)
        .handle_all(&mut client_received)
        .unwrap();

    assert_eq!(
        client.records_acked_by_peer(),
        &[AckRecordSequenceNumber {
            epoch: Epoch::EncryptedHandshakeMessages,
            seq: FullRecordSequenceNumber::from(0),
        }]
    );
    assert!(
        server
            .records_acked_by_peer()
            .is_empty()
    );
}

#[test]
fn key_update_ack_client() {
    let TestCase {
        mut client_input,
        mut client_output,
        mut client,
        mut server_input,
        mut server_output,
        mut server,
    } = setup_test(ProtocolVersion::DTLSv1_3);

    // Force client to send KeyUpdate to server.
    client
        .refresh_traffic_keys(&mut client_output)
        .unwrap();
    transfer(&mut client_output, &mut server_input);

    // Server will ACK the KeyUpdate and send a KeyUpdate of its own.
    server
        .read_tls(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    transfer(&mut server_output, &mut client_input);
    // Client will ACK the server's KeyUpdate
    client
        .read_tls(&mut client_input, &mut client_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    assert_eq!(
        client.records_acked_by_peer(),
        &[
            // Finished message from end of handshake
            AckRecordSequenceNumber {
                epoch: Epoch::EncryptedHandshakeMessages,
                seq: FullRecordSequenceNumber::from(0)
            },
            // KeyUpdate
            AckRecordSequenceNumber {
                epoch: Epoch::ApplicationData(3),
                seq: FullRecordSequenceNumber::from(0),
            }
        ]
    );

    // Server will receive client's ACK
    transfer(&mut client_output, &mut server_input);
    server
        .read_tls(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    assert_eq!(
        server.records_acked_by_peer(),
        &[AckRecordSequenceNumber {
            epoch: Epoch::ApplicationData(3),
            seq: FullRecordSequenceNumber::from(1),
        }]
    );
}

#[test]
fn key_update_ack_server() {
    let TestCase {
        mut client_input,
        mut client_output,
        mut client,
        mut server_input,
        mut server_output,
        mut server,
    } = setup_test(ProtocolVersion::DTLSv1_3);

    std::println!(
        "handshake done\nserver acked {:?}\nclient acked: {:?}\n\n\n",
        server.records_acked_by_peer(),
        client.records_acked_by_peer()
    );

    // Force server to send KeyUpdate to client.
    server
        .refresh_traffic_keys(&mut server_output)
        .unwrap();
    transfer(&mut server_output, &mut client_input);
    // Client will ACK the KeyUpdate and send a KeyUpdate of its own.
    client
        .read_tls(&mut client_input, &mut client_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    transfer(&mut client_output, &mut server_input);
    // Server will ACK the client's KeyUpdate
    server
        .read_tls(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    assert_eq!(
        server.records_acked_by_peer(),
        &[AckRecordSequenceNumber {
            epoch: Epoch::ApplicationData(3),
            seq: FullRecordSequenceNumber::from(1),
        }]
    );

    // Client will receive server's ACK
    transfer(&mut server_output, &mut client_input);
    client
        .read_tls(&mut client_input, &mut client_output)
        .handle_all(&mut Vec::new())
        .unwrap();
    assert_eq!(
        client.records_acked_by_peer(),
        &[
            // finished message from end of handshake
            AckRecordSequenceNumber {
                epoch: Epoch::EncryptedHandshakeMessages,
                seq: FullRecordSequenceNumber::from(0),
            },
            // key update
            AckRecordSequenceNumber {
                epoch: Epoch::ApplicationData(3),
                seq: FullRecordSequenceNumber::from(0)
            }
        ],
    );
}

fn anti_replay_test(version: ProtocolVersion) {
    let TestCase {
        mut client_output,
        mut client,
        mut server_input,
        mut server_output,
        mut server,
        ..
    } = setup_test(version);

    let client_message = b"client sends application data";
    client
        .write(client_message.into(), &mut client_output)
        .unwrap();

    // Record contents of client_output so we can replay the message later.
    let mut replayed_message = client_output.clone();

    transfer(&mut client_output, &mut server_input);

    // Server should receive a single datagram consisting of client_message
    let mut server_recv = Vec::new();
    server
        .read_tls(&mut server_input, &mut server_output)
        .handle_all(&mut server_recv)
        .unwrap();

    assert_eq!(server_recv.len(), 1);
    assert_eq!(server_recv[0].as_slice(), &client_message[..]);

    // Replay the recorded message into the server and it should get rejected.
    transfer(&mut replayed_message, &mut server_input);

    let err = server
        .read_tls(&mut server_input, &mut server_output)
        .handle_all(&mut Vec::new())
        .unwrap_err();
    assert_eq!(err, Error::DtlsRecordAntiReplay(AntiReplay::Replay));
}

fn setup_test(desired_version: ProtocolVersion) -> TestCase {
    setup_test_with_versions(
        &[desired_version],
        &[desired_version],
        Some(desired_version),
    )
}

fn setup_test_with_versions(
    client_versions: &[ProtocolVersion],
    server_versions: &[ProtocolVersion],
    desired_version: Option<ProtocolVersion>,
) -> TestCase {
    let provider = provider::DEFAULT_PROVIDER;
    let client_provider = apply_versions(provider.clone(), client_versions);
    let server_provider = apply_versions(provider, server_versions);

    let client_config = make_client_config(KeyType::default(), &client_provider);
    let server_config = make_server_config(KeyType::default(), &server_provider);

    let mut client_output = Vec::new();
    let mut server_output = Vec::new();
    let (mut client, mut server) =
        make_pair_for_configs(client_config, server_config, &mut client_output);
    let mut client_input = VecInput::default();
    let mut server_input = VecInput::default();

    assert_eq!(client.protocol_version(), None);
    assert_eq!(server.protocol_version(), None);

    if desired_version.is_none() {
        let err = do_handshake_until_error(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );
        assert!(err.is_err());
    } else {
        do_handshake(
            &mut client_input,
            &mut client_output,
            &mut client,
            &mut server_input,
            &mut server_output,
            &mut server,
        );
        assert_eq!(client.protocol_version(), desired_version);
        assert_eq!(server.protocol_version(), desired_version);
    }

    return TestCase {
        client_input,
        client_output,
        client,
        server_input,
        server_output,
        server,
    };
}

struct TestCase {
    client_input: VecInput,
    client_output: Vec<Vec<u8>>,
    client: ClientSocket,
    server_input: VecInput,
    server_output: Vec<Vec<u8>>,
    server: ServerSocket,
}

fn apply_versions(provider: CryptoProvider, versions: &[ProtocolVersion]) -> CryptoProvider {
    match versions {
        []
        | [ProtocolVersion::DTLSv1_3, ProtocolVersion::DTLSv1_2]
        | [ProtocolVersion::DTLSv1_2, ProtocolVersion::DTLSv1_3] => provider,
        [ProtocolVersion::DTLSv1_3] => CryptoProvider {
            tls12_cipher_suites: Cow::Borrowed(&[]),
            ..provider
        },
        [ProtocolVersion::DTLSv1_2] => CryptoProvider {
            tls13_cipher_suites: Cow::Borrowed(&[]),
            ..provider
        },
        _ => panic!("unhandled versions {versions:?}"),
    }
}

fn do_handshake(
    client_input: &mut VecInput,
    client_output: &mut Vec<Vec<u8>>,
    client: &mut impl Socket,
    server_input: &mut VecInput,
    server_output: &mut Vec<Vec<u8>>,
    server: &mut impl Socket,
) -> (usize, usize) {
    let (mut to_client, mut to_server) = (0, 0);
    while server.is_handshaking() || client.is_handshaking() {
        to_server += transfer(client_output, server_input);
        server
            .read_tls(server_input, server_output)
            .handle_all(&mut Vec::new())
            .unwrap();
        to_client += transfer(server_output, client_input);
        client
            .read_tls(client_input, client_output)
            .handle_all(&mut Vec::new())
            .unwrap();
    }
    (to_server, to_client)
}

#[derive(PartialEq, Debug)]
enum ErrorFromPeer {
    Client(Error),
    Server(Error),
}

fn do_handshake_until_error(
    client_input: &mut VecInput,
    client_output: &mut Vec<Vec<u8>>,
    client: &mut ClientSocket,
    server_input: &mut VecInput,
    server_output: &mut Vec<Vec<u8>>,
    server: &mut ServerSocket,
) -> Result<(), ErrorFromPeer> {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client_output, server_input);
        server
            .read_tls(server_input, server_output)
            .handle_all(&mut Vec::new())
            .map_err(ErrorFromPeer::Server)?;
        transfer(server_output, client_input);
        client
            .read_tls(client_input, client_output)
            .handle_all(&mut Vec::new())
            .map_err(ErrorFromPeer::Client)?;
    }

    Ok(())
}

fn make_pair_for_configs(
    client_config: ClientConfig,
    server_config: ServerConfig,
    client_output: &mut Vec<Vec<u8>>,
) -> (ClientSocket, ServerSocket) {
    (
        ClientSocket::connect(server_name("localhost"), client_config, client_output).unwrap(),
        ServerSocket::new(Arc::new(server_config.clone())).unwrap(),
    )
}

fn transfer(left_output: &mut Vec<Vec<u8>>, right_input: &mut VecInput) -> usize {
    let left_output_flat: Vec<u8> = left_output
        .clone()
        .into_iter()
        .flatten()
        .collect();
    let total = left_output_flat.len();
    let mut offs = 0;
    while offs < total {
        let from_buf: &mut dyn std::io::Read = &mut &left_output_flat[offs..];
        offs += right_input.read(from_buf).unwrap();
    }

    left_output.clear();
    total
}
