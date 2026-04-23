use crate::EpochAndSequence;
use crate::crypto::CipherSuite;
use crate::enums::HandshakeType;
use crate::msgs::{
    ClientExtensions, ClientHelloPayload, Codec, Compression, DTLS_HANDSHAKE_HEADER_EXTRA,
    DTLS_HANDSHAKE_HEADER_SIZE, DTLS_HEADER_SIZE, HANDSHAKE_HEADER_SIZE, HandshakeMessagePayload,
    HandshakePayload, Message, MessageFragmenter, MessagePayload, Payload, Random,
    ServerNamePayload, SessionId,
};

use pki_types::DnsName;

use super::*;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

fn test_handshake_message<'a>() -> Message<'a> {
    Message {
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
    }
}

fn check_reassembled_message(
    original_message: &EncodedMessage<Payload<'_>>,
    reassembled_message: &EncodedMessage<&[u8]>,
) {
    assert_eq!(reassembled_message.typ, original_message.typ);
    assert_eq!(reassembled_message.version, original_message.version);
    assert_eq!(reassembled_message.epoch_and_sequence, None);
    assert_eq!(
        reassembled_message.payload.len(),
        original_message.payload.bytes().len() + DTLS_HANDSHAKE_HEADER_EXTRA,
    );
    // The record we encoded had a TLS handshake header on it, but the one we get back has a *DTLS*
    // handshake header. Check that the payloads are equal.
    assert_eq!(
        &original_message.payload.bytes()[HANDSHAKE_HEADER_SIZE..],
        &reassembled_message.payload[DTLS_HANDSHAKE_HEADER_SIZE..]
    );

    // Make sure we can parse the handshake message, but we already checked that the bytes are as
    // expected so no need to examine the fields of the message.
    Message::try_from(reassembled_message.clone()).unwrap();
}

#[test]
fn single_handshake_fragment() {
    let record = test_handshake_message().encoded_message(Some(EpochAndSequence::new(0, 0)));

    let fragments: Vec<_> = MessageFragmenter::default()
        .fragment_dtls_handshake_message(
            EpochAndSequence::new(0, 0),
            HandshakeType::ClientHello,
            0,
            record.payload.bytes(),
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

    // Simulate decryption
    let message = message.into_plain_message();
    let bounds = bounds.start + DTLS_HEADER_SIZE..bounds.end;

    // Feed the record payload into the deframer. It should be a complete span.
    deframer
        .input_message_dtls(message, bounds)
        .unwrap();

    // Coalescing should be a no-op with only one span
    deframer.coalesce_dtls(&mut record_wire_bytes);
    let message_span = deframer.complete_span().unwrap();

    // We should get the whole handshake message out of the deframer
    let reassembled_message = deframer.message(message_span, &record_wire_bytes);
    check_reassembled_message(&record, &reassembled_message);
}

#[test]
fn multiple_handshake_fragment_in_order() {
    let record = test_handshake_message().encoded_message(Some(EpochAndSequence::new(0, 0)));

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

    let mut deframer = Deframer::default();

    // Deframe records and feed messages into the deframer to be coalesced. We should not
    // get a complete span until all fragments are fed in.
    for fragment_idx in 0..fragments.len() {
        let Deframed { message, bounds } = deframer
            .deframe(&mut encoded_fragments)
            .unwrap()
            .unwrap();

        // Simulate in-place decryption
        let message = message.into_plain_message();
        let bounds = bounds.start + DTLS_HEADER_SIZE..bounds.end;

        deframer
            .input_message_dtls(message, bounds)
            .unwrap();
        deframer.coalesce_dtls(&mut encoded_fragments);

        if fragment_idx < fragments.len() - 1 {
            assert!(deframer.complete_span().is_none());
        } else {
            let message_span = deframer.complete_span().unwrap();

            // We should get the whole handshake message out of the deframer
            let reassembled_handshake_message = deframer.message(message_span, &encoded_fragments);
            check_reassembled_message(&record, &reassembled_handshake_message);
        }
    }
}

#[test]
fn multiple_handshake_fragment_overlapping() {
    let record = test_handshake_message().encoded_message(Some(EpochAndSequence::new(0, 0)));

    let mut message_fragmenter = MessageFragmenter::default();
    message_fragmenter
        .set_max_fragment_size(Some(48))
        .unwrap();
    let mut fragments: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            EpochAndSequence::new(5, 222),
            HandshakeType::ClientHello,
            0,
            &record.payload.bytes(),
        )
        .collect();
    assert_eq!(fragments.len(), 4);

    // Grow one of the fragments so that it overlaps with part of the fragment before it and then
    // all of the fragment after it.
    let fragment_0_portion = 11;
    assert!(
        fragment_0_portion as usize
            <= fragments[0]
                .payload
                .fragment
                .bytes()
                .len()
    );
    let fragment_2_portion = fragments[2].payload.fragment_length.0;
    fragments[1].payload.fragment_length =
        U24(fragments[1].payload.fragment_length.0 + fragment_0_portion + fragment_2_portion);
    fragments[1].payload.fragment_offset =
        U24(fragments[1].payload.fragment_offset.0 - fragment_0_portion);
    let mut grown_payload = fragments[0]
        .payload
        .fragment
        .bytes()
        .last_chunk::<11>()
        .unwrap()
        .to_vec();
    grown_payload.extend(fragments[1].payload.fragment.bytes());
    grown_payload.extend(fragments[2].payload.fragment.bytes());
    fragments[1].payload.fragment = Payload::new(grown_payload);

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

    let mut deframer = Deframer::default();

    // Deframe records and feed messages into the deframer to be coalesced. We should not
    // get a complete span until all fragments are fed in.
    for fragment_idx in 0..fragments.len() {
        let Deframed { message, bounds } = deframer
            .deframe(&mut encoded_fragments)
            .unwrap()
            .unwrap();

        // Simulate in-place decryption
        let message = message.into_plain_message();
        let bounds = bounds.start + DTLS_HEADER_SIZE..bounds.end;

        deframer
            .input_message_dtls(message, bounds)
            .unwrap();
        deframer.coalesce_dtls(&mut encoded_fragments);

        if fragment_idx < fragments.len() - 1 {
            assert!(deframer.complete_span().is_none());
        } else {
            let message_span = deframer.complete_span().unwrap();

            // We should get the whole handshake message out of the deframer
            let reassembled_handshake_message = deframer.message(message_span, &encoded_fragments);
            check_reassembled_message(&record, &reassembled_handshake_message);
        }
    }
}

#[test]
fn multiple_handshake_fragment_out_of_order_and_more_than_one_seq_1() {
    let first_record = test_handshake_message().encoded_message(Some(EpochAndSequence::new(0, 0)));
    let second_record = test_handshake_message().encoded_message(Some(EpochAndSequence::new(0, 0)));

    let mut message_fragmenter = MessageFragmenter::default();
    message_fragmenter
        .set_max_fragment_size(Some(48))
        .unwrap();
    let fragments: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            EpochAndSequence::new(5, 222),
            HandshakeType::ClientHello,
            666, // [2, 154]
            &first_record.payload.bytes(),
        )
        .chain(message_fragmenter.fragment_dtls_handshake_message(
            EpochAndSequence::new(5, 223),
            HandshakeType::ClientHello,
            667, // [2, 155]
            &second_record.payload.bytes(),
        ))
        .collect();
    assert_eq!(fragments.len(), 8);

    // Interleave the fragments of the two handshake messages to simulate UDP messages arriving out
    // of order. Even though we receive all the fragments of the second message at index 5, we can't
    // get any messages out of the deframer until all fragments of the first message arrive.
    let mut encoded_fragments = Vec::new();
    for index in [4, 2, 7, 3, 6, 5, 1, 0] {
        encoded_fragments.extend_from_slice(
            EncodedMessage {
                typ: fragments[index].typ,
                version: fragments[index].version,
                epoch_and_sequence: fragments[index].epoch_and_sequence,
                payload: fragments[index]
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

    let mut deframer = Deframer::default();

    // Deframe records and feed messages into the deframer to be coalesced.
    let mut saw_first_message = false;
    for _ in 0..fragments.len() {
        let Deframed { message, bounds } = deframer
            .deframe(&mut encoded_fragments)
            .unwrap()
            .unwrap();

        // Simulate in-place decryption
        let message = message.into_plain_message();
        let bounds = bounds.start + DTLS_HEADER_SIZE..bounds.end;

        deframer
            .input_message_dtls(message, bounds)
            .unwrap();
        deframer.coalesce_dtls(&mut encoded_fragments);

        if let Some(span) = deframer.complete_span() {
            // Because of how we laid out encoded_fragments, no message will be available until the
            // last iteration of this loop, at which point both will be in the buffer, ordered by
            // handshake seq.
            let reassembled_handshake_message = deframer.message(span, &encoded_fragments);
            check_reassembled_message(&first_record, &reassembled_handshake_message);

            saw_first_message = true;

            let span = deframer.complete_span().unwrap();
            let reassembled_handshake_message = deframer.message(span, &encoded_fragments);
            check_reassembled_message(&second_record, &reassembled_handshake_message);
        }
    }

    assert!(saw_first_message);
}

#[test]
fn multiple_handshake_fragment_out_of_order_and_more_than_one_seq_2() {
    let first_record = test_handshake_message().encoded_message(Some(EpochAndSequence::new(0, 0)));
    let second_record = test_handshake_message().encoded_message(Some(EpochAndSequence::new(0, 0)));

    let mut message_fragmenter = MessageFragmenter::default();
    message_fragmenter
        .set_max_fragment_size(Some(48))
        .unwrap();
    let fragments: Vec<_> = message_fragmenter
        .fragment_dtls_handshake_message(
            EpochAndSequence::new(5, 222),
            HandshakeType::ClientHello,
            666, // [2, 154]
            &first_record.payload.bytes(),
        )
        .chain(message_fragmenter.fragment_dtls_handshake_message(
            EpochAndSequence::new(5, 223),
            HandshakeType::ClientHello,
            667, // [2, 155]
            &second_record.payload.bytes(),
        ))
        .collect();
    assert_eq!(fragments.len(), 8);

    // Interleave the fragments of the two handshake messages to simulate UDP messages arriving out
    // of order. We receive all fragments of the first message at index 5, so the deframer should
    // yield that message then, but the second message has to wait until all 8 fragments arrive.
    let mut encoded_fragments = Vec::new();
    for index in [4, 2, 7, 3, 1, 0, 6, 5] {
        encoded_fragments.extend_from_slice(
            EncodedMessage {
                typ: fragments[index].typ,
                version: fragments[index].version,
                epoch_and_sequence: fragments[index].epoch_and_sequence,
                payload: fragments[index]
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

    let mut deframer = Deframer::default();

    // Deframe records and feed messages into the deframer to be coalesced.
    let mut saw_first_message = false;
    let mut saw_second_message = false;
    for _ in 0..fragments.len() {
        let Deframed { message, bounds } = deframer
            .deframe(&mut encoded_fragments)
            .unwrap()
            .unwrap();

        // Simulate in-place decryption
        let message = message.into_plain_message();
        let bounds = bounds.start + DTLS_HEADER_SIZE..bounds.end;

        deframer
            .input_message_dtls(message, bounds)
            .unwrap();
        deframer.coalesce_dtls(&mut encoded_fragments);

        if let Some(span) = deframer.complete_span() {
            let reassembled_handshake_message = deframer.message(span, &encoded_fragments);
            if !saw_first_message {
                check_reassembled_message(&first_record, &reassembled_handshake_message);
                saw_first_message = true;
            } else {
                check_reassembled_message(&second_record, &reassembled_handshake_message);
                saw_second_message = true;
            }
        }
    }

    assert!(saw_first_message);
    assert!(saw_second_message);
}

#[test]
fn multiple_fragments_application_data() {
    let first_record = Message {
        version: ProtocolVersion::DTLSv1_2,
        payload: MessagePayload::new(
            ContentType::ApplicationData,
            ProtocolVersion::DTLSv1_2,
            &[1; 32],
        )
        .unwrap(),
    }
    .encoded_message(Some(EpochAndSequence::new(5, 11)))
    .into_unencrypted_opaque();

    let encoded_first_record = first_record.clone().encode();
    let encoded_first_record_len = encoded_first_record.len();

    let second_record = Message {
        version: ProtocolVersion::DTLSv1_2,
        payload: MessagePayload::new(
            ContentType::ApplicationData,
            ProtocolVersion::DTLSv1_2,
            &[4; 92],
        )
        .unwrap(),
    }
    .encoded_message(Some(EpochAndSequence::new(5, 12)))
    .into_unencrypted_opaque();

    let encoded_second_record = second_record.clone().encode();
    let encoded_second_record_len = encoded_second_record.len();

    let mut wire_bytes = Vec::new();
    wire_bytes.extend(encoded_first_record);
    wire_bytes.extend(encoded_second_record);

    let mut deframer = Deframer::default();

    for (record, expect_start, expect_end) in [
        (first_record, 0, encoded_first_record_len),
        (
            second_record,
            encoded_first_record_len,
            encoded_first_record_len + encoded_second_record_len,
        ),
    ] {
        let Deframed { message, bounds } = deframer
            .deframe(&mut wire_bytes)
            .unwrap()
            .unwrap();

        assert_eq!(bounds.start, expect_start);
        assert_eq!(bounds.end, expect_end);

        let message = message.into_plain_message();
        assert_eq!(message.typ, record.typ);
        assert_eq!(message.version, record.version);
        assert_eq!(message.epoch_and_sequence, record.epoch_and_sequence);
        assert_eq!(message.payload, record.payload.as_ref());
    }
}
