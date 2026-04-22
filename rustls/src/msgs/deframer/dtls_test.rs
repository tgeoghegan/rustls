use crate::enums::HandshakeType;
use crate::msgs::{
    ClientExtensions, ClientHelloPayload, Codec, Compression, DTLS_HANDSHAKE_HEADER_EXTRA,
    DTLS_HEADER_SIZE, HandshakeMessagePayload, HandshakePayload, Message, MessageFragmenter,
    MessagePayload, Random, ServerNamePayload, SessionId,
};
use crate::{EpochAndSequence, crypto::CipherSuite};

use pki_types::DnsName;

use super::*;
use std::boxed::Box;
use std::vec;

#[test]
fn single_dtls_handshake_fragment() {
    let handshake = Message {
        version: ProtocolVersion::DTLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ClientHello(
            ClientHelloPayload {
                client_version: ProtocolVersion::DTLSv1_2,
                random: Random::from([1; 32]),
                session_id: SessionId::from([2; 32]),
                cipher_suites: vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
                compression_methods: vec![Compression::Null],
                extensions: Box::new(ClientExtensions {
                    server_name: Some(ServerNamePayload::from(
                        &DnsName::try_from("hello").unwrap(),
                    )),
                    ..Default::default()
                }),
            },
        ))),
    };
    let record = handshake.encoded_message(Some(EpochAndSequence::new(0, 0)));

    let fragments: Vec<_> = MessageFragmenter::default()
        .fragment_dtls_handshake_message(
            EpochAndSequence::new(0, 0),
            HandshakeType::ClientHello,
            0,
            &record.payload.bytes(),
        )
        .collect();
    assert_eq!(fragments.len(), 1);

    let mut record_wire_bytes = EncodedMessage {
        typ: fragments[0].typ,
        version: fragments[0].version,
        epoch_and_sequence: fragments[0].epoch_and_sequence,
        payload: fragments[0]
            .payload
            .get_encoding()
            .as_slice()
            .into(),
    }
    .to_unencrypted_opaque()
    .encode();
    let record_wire_bytes_len = record_wire_bytes.len();

    // Deframe the record to parse its header and get the body as an InboundOpaque
    let mut deframer = Deframer::default();

    let Deframed { message, bounds } = deframer
        .deframe(&mut record_wire_bytes)
        .unwrap()
        .unwrap();

    // The bounds of the deframed message should span the entire encoded message
    assert_eq!(bounds.start, 0);
    assert_eq!(bounds.end, record_wire_bytes_len);

    let message = message.into_plain_message();

    // Feed the record payload into the deframer. It should be a complete span.
    deframer
        .input_message_dtls(message, bounds.clone())
        .unwrap();

    // Coalescing should be a no-op with only one span
    deframer
        .coalesce_dtls(&mut record_wire_bytes)
        .unwrap();
    let message_span = deframer.complete_span().unwrap();

    // We should get the whole handshake message out of the deframer
    let handshake_message = deframer.message(message_span, &record_wire_bytes);
    assert_eq!(handshake_message.typ, ContentType::Handshake);
    assert_eq!(handshake_message.version, ProtocolVersion::DTLSv1_2);
    assert_eq!(handshake_message.epoch_and_sequence, None);
    assert_eq!(
        handshake_message.payload.len(),
        record_wire_bytes_len - DTLS_HEADER_SIZE
    );

    let message = Message::try_from(handshake_message).unwrap();
    std::println!("message: {message:?}");
}

#[test]
fn multiple_dtls_handshake_fragment() {
    let handshake = Message {
        version: ProtocolVersion::DTLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ClientHello(
            ClientHelloPayload {
                client_version: ProtocolVersion::DTLSv1_2,
                random: Random::from([1; 32]),
                session_id: SessionId::from([2; 32]),
                cipher_suites: vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
                compression_methods: vec![Compression::Null],
                extensions: Box::new(ClientExtensions {
                    server_name: Some(ServerNamePayload::from(
                        &DnsName::try_from("hello").unwrap(),
                    )),
                    ..Default::default()
                }),
            },
        ))),
    };
    let record = handshake.encoded_message(Some(EpochAndSequence::new(0, 0)));
    std::println!(
        "recordbytes: {} {:?}",
        record.payload.bytes().len(),
        record.payload.bytes()
    );

    let mut message_fragmenter = MessageFragmenter::default();
    message_fragmenter
        .set_max_fragment_size(Some(48))
        .unwrap();
    let fragments: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            EpochAndSequence::new(5, 222),
            HandshakeType::ClientHello,
            0,
            &record.payload.bytes(),
        )
        .collect();
    assert_eq!(fragments.len(), 4);

    let mut encoded_fragments = Vec::new();

    for fragment in &fragments {
        encoded_fragments.extend_from_slice(
            EncodedMessage {
                typ: fragment.typ,
                version: fragment.version,
                epoch_and_sequence: fragment.epoch_and_sequence,
                payload: fragment
                    .payload
                    .get_encoding()
                    .as_slice()
                    .into(),
            }
            .to_unencrypted_opaque()
            .encode()
            .as_slice(),
        );
    }

    std::println!(
        "concatenated fragments: {} {encoded_fragments:?}",
        encoded_fragments.len()
    );

    let mut deframer = Deframer::default();

    // Deframe records and feed messages into the deframer to be coalesced. We should not
    // get a complete span until 3 fragments are fed in.
    for fragment_idx in 0..fragments.len() {
        let Deframed { message, bounds } = deframer
            .deframe(&mut encoded_fragments)
            .unwrap()
            .unwrap();

        std::println!(
            "deframer processed: {} bounds: {bounds:?}",
            deframer.processed
        );

        // Simulate in-place decryption
        let message = message.into_plain_message();

        deframer
            .input_message_dtls(message, bounds)
            .unwrap();
        std::println!("deframer spans after input_message: {:?}", deframer.spans);

        std::println!("coalescing fragment {fragment_idx}");
        deframer
            .coalesce_dtls(&mut encoded_fragments)
            .unwrap();
        std::println!("coalesced fragment {fragment_idx}");

        if fragment_idx < fragments.len() - 1 {
            assert!(deframer.complete_span().is_none());
        } else {
            let message_span = deframer.complete_span().unwrap();

            // We should get the whole handshake message out of the deframer
            let reassembled_handshake_message = deframer.message(message_span, &encoded_fragments);
            assert_eq!(reassembled_handshake_message.typ, ContentType::Handshake);
            assert_eq!(
                reassembled_handshake_message.version,
                ProtocolVersion::DTLSv1_2
            );
            assert_eq!(reassembled_handshake_message.epoch_and_sequence, None);
            std::println!(
                "reassembled handshake message payload: {} {:?}",
                reassembled_handshake_message
                    .payload
                    .len(),
                reassembled_handshake_message.payload
            );
            assert_eq!(
                reassembled_handshake_message
                    .payload
                    .len(),
                record.payload.bytes().len() + DTLS_HANDSHAKE_HEADER_EXTRA
            );
            let message = Message::try_from(reassembled_handshake_message).unwrap();
            std::println!("message: {message:?}");
        }
    }
}

#[test]
fn multiple_dtls_handshake_fragment_out_of_order_and_more_than_one_seq() {
    let handshake = Message {
        version: ProtocolVersion::DTLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ClientHello(
            ClientHelloPayload {
                client_version: ProtocolVersion::DTLSv1_2,
                random: Random::from([1; 32]),
                session_id: SessionId::read(&mut Reader::new(&[2; 32])).unwrap(),
                cipher_suites: vec![CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
                compression_methods: vec![Compression::Null],
                extensions: Box::new(ClientExtensions {
                    server_name: Some(ServerNamePayload::from(
                        &DnsName::try_from("hello").unwrap(),
                    )),
                    ..Default::default()
                }),
            },
        ))),
    };
    let record = handshake.encoded_message(Some(EpochAndSequence::new(0, 0)));

    let mut message_fragmenter = MessageFragmenter::default();
    message_fragmenter
        .set_max_fragment_size(Some(48))
        .unwrap();
    let fragments: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            EpochAndSequence::new(0, 0),
            HandshakeType::ClientHello,
            0,
            &record.payload.bytes(),
        )
        .collect();
    assert_eq!(fragments.len(), 3);

    todo!("send fragments in out of order and make sure a valid handshake comes out")
}

#[test]
fn dtls_single_fragment_not_handshake() {
    todo!("send a single application data and make sure it comes out")
}

#[test]
fn dtls_multiple_fragments_not_handshake() {
    todo!("send multiple application data fragments and make sure they each come out")
}

#[test]
fn dtls_multiple_fragments_not_handshake_out_of_order() {
    todo!(
        "send multiple application data fragments and make sure they come out... in order? Maybe pointless test"
    )
}
