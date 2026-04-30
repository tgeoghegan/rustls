#[cfg(feature = "dtls")]
use alloc::vec::Vec;
#[cfg(feature = "dtls")]
use core::cmp::min;
#[cfg(feature = "dtls")]
use core::mem;

use crate::Error;
use crate::crypto::cipher::{EncodedMessage, OutboundPlain, Payload};
#[cfg(feature = "dtls")]
use crate::enums::HandshakeType;
use crate::enums::{ContentType, ProtocolVersion};
use crate::msgs::HEADER_SIZE;
#[cfg(feature = "dtls")]
use crate::msgs::{
    Codec, DTLS_HANDSHAKE_HEADER_SIZE, DTLS_HEADER_SIZE, DtlsHandshakeFragment, EpochAndSequence,
    U24,
};

pub(crate) const MAX_FRAGMENT_LEN: usize = 16384;
pub(crate) const MAX_FRAGMENT_SIZE: usize = MAX_FRAGMENT_LEN + HEADER_SIZE;

pub(crate) struct MessageFragmenter {
    max_frag: usize,
}

impl Default for MessageFragmenter {
    fn default() -> Self {
        Self {
            max_frag: MAX_FRAGMENT_LEN,
        }
    }
}

impl MessageFragmenter {
    /// Take `msg` and fragment it into new messages with the same type and version.
    ///
    /// Each returned message size is no more than `max_frag`.
    ///
    /// Return an iterator across those messages.
    ///
    /// Payloads are borrowed from `msg`.
    ///
    /// Should not be used for DTLS messages. See [`Self::fragment_dtls_handshake_message`].
    pub(crate) fn fragment_message<'a>(
        &self,
        msg: &'a EncodedMessage<Payload<'_>>,
    ) -> impl Iterator<Item = EncodedMessage<OutboundPlain<'a>>> + 'a {
        self.fragment_payload(msg.typ, msg.version, None, msg.payload.bytes().into())
    }

    /// Take a DTLS handshake message and fragment it into multiple unencrypted outbound messages,
    /// each consisting of a DTLSPlaintext ([1]). Other DTLS messages may not be fragmented.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc9147#appendix-A.1
    #[cfg(feature = "dtls")]
    pub(crate) fn fragment_dtls_handshake_message<'a>(
        &self,
        epoch_and_sequence: EpochAndSequence,
        msg_type: HandshakeType,
        handshake_sequence_number: u16,
        handshake_payload: &'a [u8],
    ) -> impl Iterator<Item = EncodedMessage<DtlsHandshakeFragment<'a>>> + 'a {
        // handshake_payload will have been encoded as a TLS handshake message, so we discard the
        // front 4 bytes (1 byte of handshake type plus 3 bytes of length) so that we can re-encode
        // as a DTLS handshake fragment.
        let handshake_payload = &handshake_payload[4..];
        assert!(handshake_payload.len() <= U24::MAX as usize);
        let length = U24(handshake_payload.len() as u32);
        let mut fragment_offset = 0;

        Chunker::new(
            handshake_payload.into(),
            self.max_fragment_size(ProtocolVersion::DTLSv1_2) - DTLS_HANDSHAKE_HEADER_SIZE,
        )
        .enumerate()
        .map(move |(sequence, payload)| {
            assert!(fragment_offset <= U24::MAX);
            assert!(payload.len() <= U24::MAX as usize);
            let payload_len = payload.len() as u32;

            let fragment = match payload {
                OutboundPlain::Single(buf) => Payload::Borrowed(buf),
                OutboundPlain::Multiple { .. } => {
                    panic!("should never construct OutboundPlain::Multiple from a Payload")
                }
            };

            let fragment = DtlsHandshakeFragment {
                msg_type,
                length,
                message_seq: handshake_sequence_number,
                fragment_offset: U24(fragment_offset),
                fragment_length: U24(payload_len),
                fragment,
            };

            fragment_offset += payload_len;

            EncodedMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::DTLSv1_2,
                epoch_and_sequence: Some(
                    epoch_and_sequence.add_sequence_increment(sequence as u64),
                ),
                payload: fragment,
            }
        })
    }

    // handshake_sequence_number is the sequence number for the first message in this flight
    // handshake_messages is the handshake message type and encoded handshake message
    #[cfg(feature = "dtls")]
    pub(crate) fn fragment_dtls_handshake_message_flight<'a>(
        &self,
        mut epoch_and_sequence: EpochAndSequence,
        mut handshake_sequence_number: u16,
        handshake_messages: &'a [(HandshakeType, Vec<u8>)],
    ) -> Vec<EncodedMessage<Payload<'a>>> {
        let mut records = Vec::new();
        // The current record we are packing with the handshake flight. Does not include record
        // header.
        let record_capacity = self.max_fragment_size(ProtocolVersion::DTLSv1_2);
        let mut curr_record = Vec::with_capacity(record_capacity);

        let mut finish_record = |curr_record: &mut Vec<u8>| {
            let finished_record = mem::replace(curr_record, Vec::with_capacity(record_capacity));
            records.push(EncodedMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::DTLSv1_2,
                epoch_and_sequence: Some(epoch_and_sequence),
                payload: Payload::new(finished_record),
            });
            epoch_and_sequence = epoch_and_sequence.add_sequence_increment(1);
        };

        for (idx, (handshake_type, handshake_payload)) in handshake_messages.iter().enumerate() {
            // handshake_payload will have been encoded as a TLS handshake message, so we discard the
            // front 4 bytes (1 byte of handshake type plus 3 bytes of length) so that we can re-encode
            // as a DTLS handshake fragment.
            let handshake_payload = &handshake_payload[4..];
            assert!(handshake_payload.len() <= U24::MAX as usize);
            let length = U24(handshake_payload.len() as u32);

            let mut fragment_offset = 0;
            while fragment_offset < handshake_payload.len() {
                if record_capacity - curr_record.len() <= DTLS_HANDSHAKE_HEADER_SIZE {
                    // There's no room left in the current record for a handshake fragment. Start a
                    // new record.
                    finish_record(&mut curr_record);
                }
                // Fill fragment with either remainder of the handshake payload or the remaining
                // capacity of the record.
                let fragment_length = min(
                    record_capacity - curr_record.len() - DTLS_HANDSHAKE_HEADER_SIZE,
                    handshake_payload.len() - fragment_offset,
                );

                let fragment = DtlsHandshakeFragment {
                    msg_type: *handshake_type,
                    length,
                    message_seq: handshake_sequence_number,
                    fragment_offset: U24(fragment_offset.try_into().unwrap()),
                    fragment_length: U24(fragment_length.try_into().unwrap()),
                    fragment: Payload::Borrowed(
                        &handshake_payload[fragment_offset..fragment_offset + fragment_length],
                    ),
                };

                fragment_offset += fragment_length;

                fragment.encode(&mut curr_record);

                // Make sure we didn't accidentally grow the record
                assert_eq!(
                    curr_record.capacity(),
                    record_capacity,
                    "record len: {}",
                    curr_record.len()
                );

                // If we have filled the current record or if this is the last fragment of the last
                // handshake message, construct a record
                if curr_record.len() == curr_record.capacity()
                    || (idx + 1 == handshake_messages.len()
                        && fragment_offset == handshake_payload.len())
                {
                    finish_record(&mut curr_record);
                }
            }

            handshake_sequence_number += 1;
        }

        records
    }

    /// Take `payload` and fragment it into new messages with given type and version.
    ///
    /// Each returned message size is no more than `max_frag`.
    ///
    /// Return an iterator across those messages.
    ///
    /// Payloads are borrowed from `payload`.
    pub(crate) fn fragment_payload<'a>(
        &self,
        typ: ContentType,
        version: ProtocolVersion,
        #[cfg(feature = "dtls")] epoch_and_sequence: Option<EpochAndSequence>,
        payload: OutboundPlain<'a>,
    ) -> impl ExactSizeIterator<Item = EncodedMessage<OutboundPlain<'a>>> {
        assert!(
            !version.is_datagram_tls(),
            "To fragment a DTLS handshake message, use fragment_dtls_handshake_message. \
            Other DTLS messages may not be fragmented.",
        );
        Chunker::new(payload, self.max_fragment_size(version))
            .enumerate()
            .map(move |(sequence, payload)| EncodedMessage {
                typ,
                version,
                #[cfg(feature = "dtls")]
                epoch_and_sequence: epoch_and_sequence
                    .map(|es| es.add_sequence_increment(sequence as u64)),
                payload,
            })
    }

    /// Set the maximum fragment size that will be produced.
    ///
    /// This includes overhead. A `max_fragment_size` of 10 will produce TLS fragments
    /// up to 10 bytes long.
    ///
    /// A `max_fragment_size` of `None` sets the highest allowable fragment size.
    ///
    /// Returns BadMaxFragmentSize if the size is smaller than 32 or larger than 16389.
    pub(crate) fn set_max_fragment_size(
        &mut self,
        max_fragment_size: Option<usize>,
    ) -> Result<(), Error> {
        self.max_frag = match max_fragment_size {
            Some(sz @ 32..=MAX_FRAGMENT_SIZE) => sz,
            None => MAX_FRAGMENT_LEN,
            _ => return Err(Error::BadMaxFragmentSize),
        };
        Ok(())
    }

    fn max_fragment_size(&self, version: ProtocolVersion) -> usize {
        match version {
            #[cfg(feature = "dtls")]
            ProtocolVersion::DTLSv1_2 | ProtocolVersion::DTLSv1_3 => {
                self.max_frag - DTLS_HEADER_SIZE
            }
            _ => self.max_frag - HEADER_SIZE,
        }
    }
}

/// An iterator over borrowed fragments of a payload
struct Chunker<'a> {
    payload: OutboundPlain<'a>,
    limit: usize,
}

impl<'a> Chunker<'a> {
    fn new(payload: OutboundPlain<'a>, limit: usize) -> Self {
        Self { payload, limit }
    }
}

impl<'a> Iterator for Chunker<'a> {
    type Item = OutboundPlain<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.is_empty() {
            return None;
        }

        let (before, after) = self.payload.split_at(self.limit);
        self.payload = after;
        Some(before)
    }
}

impl ExactSizeIterator for Chunker<'_> {
    fn len(&self) -> usize {
        self.payload.len().div_ceil(self.limit)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use std::vec;

    use super::MessageFragmenter;
    use crate::crypto::cipher::{EncodedMessage, OutboundPlain, Payload};
    use crate::enums::{ContentType, HandshakeType, ProtocolVersion};
    use crate::msgs::codec::Codec;
    use crate::msgs::{
        DTLS_HANDSHAKE_HEADER_SIZE, DTLS_HEADER_SIZE, DtlsHandshakeFragment, EpochAndSequence,
        HEADER_SIZE, HandshakeMessagePayload, HandshakePayload, Reader, U24,
    };

    fn msg_eq(
        m: &EncodedMessage<OutboundPlain<'_>>,
        total_len: usize,
        typ: &ContentType,
        version: &ProtocolVersion,
        bytes: &[u8],
    ) {
        assert_eq!(&m.typ, typ);
        assert_eq!(&m.version, version);
        assert_eq!(m.payload.to_vec(), bytes);

        let buf = m.to_unencrypted_opaque().encode();

        assert_eq!(total_len, buf.len());
    }

    #[test]
    fn smoke() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let data: Vec<u8> = (1..70u8).collect();
        let m = EncodedMessage {
            typ,
            version,
            #[cfg(feature = "dtls")]
            epoch_and_sequence: None,
            payload: Payload::new(data),
        };

        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment_message(&m)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 3);
        msg_eq(
            &q[0],
            32,
            &typ,
            &version,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27,
            ],
        );
        msg_eq(
            &q[1],
            32,
            &typ,
            &version,
            &[
                28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                49, 50, 51, 52, 53, 54,
            ],
        );
        msg_eq(
            &q[2],
            20,
            &typ,
            &version,
            &[55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69],
        );
    }

    #[test]
    fn non_fragment() {
        let m = EncodedMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            // TODO(timg): we can assume this is always None if this fragmenter is only used for
            // TLS/QUIC
            #[cfg(feature = "dtls")]
            epoch_and_sequence: None,
            payload: Payload::new(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
        };

        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment_message(&m)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 1);
        msg_eq(
            &q[0],
            HEADER_SIZE + 8,
            &ContentType::Handshake,
            &ProtocolVersion::TLSv1_2,
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
        );
    }

    #[test]
    fn fragment_multiple_slices() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let payload_owner: Vec<&[u8]> = vec![&[b'a'; 8], &[b'b'; 12], &[b'c'; 32], &[b'd'; 20]];
        let borrowed_payload = OutboundPlain::new(&payload_owner);
        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(37)) // 32 + packet overhead
            .unwrap();

        let fragments = frag
            .fragment_payload(
                typ,
                version,
                #[cfg(feature = "dtls")]
                None,
                borrowed_payload,
            )
            .collect::<Vec<_>>();
        assert_eq!(fragments.len(), 3);
        msg_eq(
            &fragments[0],
            37,
            &typ,
            &version,
            b"aaaaaaaabbbbbbbbbbbbcccccccccccc",
        );
        msg_eq(
            &fragments[1],
            37,
            &typ,
            &version,
            b"ccccccccccccccccccccdddddddddddd",
        );
        msg_eq(&fragments[2], 13, &typ, &version, b"dddddddd");
    }

    #[test]
    fn dtls() {
        let encoded_handshake = &[b'a'; 104];
        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32 + DTLS_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE))
            .unwrap();

        let fragments: Vec<_> = frag
            .fragment_dtls_handshake_message(
                EpochAndSequence::new(1, 101),
                HandshakeType::ClientHello,
                11,
                encoded_handshake,
            )
            .collect();
        assert_eq!(fragments.len(), 4);

        for (
            index,
            (
                EncodedMessage {
                    typ,
                    version,
                    epoch_and_sequence,
                    payload:
                        DtlsHandshakeFragment {
                            msg_type,
                            length,
                            message_seq,
                            fragment_offset,
                            fragment_length,
                            fragment,
                        },
                },
                (expected_fragment_offset, expected_fragment_length),
            ),
        ) in fragments
            .into_iter()
            .zip([(0, 32), (32, 32), (64, 32), (96, 4)])
            .enumerate()
        {
            assert_eq!(typ, ContentType::Handshake, "fragment {index}");
            assert_eq!(version, ProtocolVersion::DTLSv1_2, "fragment {index}");
            assert_eq!(
                epoch_and_sequence,
                Some(EpochAndSequence::new(1, 101 + index as u64)),
                "fragment {index}"
            );
            assert_eq!(msg_type, HandshakeType::ClientHello, "fragment {index}");
            assert_eq!(length, U24(100), "fragment {index}");
            assert_eq!(message_seq, 11, "fragment {index}");
            assert_eq!(
                fragment_offset,
                U24(expected_fragment_offset),
                "fragment {index}"
            );
            assert_eq!(
                fragment_length,
                U24(expected_fragment_length),
                "fragment {index}"
            );
            assert_eq!(
                fragment.bytes(),
                vec![b'a'; expected_fragment_length as usize].as_slice(),
                "fragment {index}"
            );
        }
    }

    fn check_handshake_fragment(
        idx: usize,
        got: &DtlsHandshakeFragment<'_>,
        expected: &DtlsHandshakeFragment<'_>,
    ) {
        // Payload::Owned and Payload::Borrowed are not equal even if the contained bytes are
        // identical so we provide this helper
        assert_eq!(got.msg_type, expected.msg_type, "idx {idx}");
        assert_eq!(got.length, expected.length, "idx {idx}");
        assert_eq!(got.message_seq, expected.message_seq, "idx {idx}");
        assert_eq!(got.fragment_offset, expected.fragment_offset, "idx {idx}");
        assert_eq!(got.fragment_length, expected.fragment_length, "idx {idx}");
        assert_eq!(got.fragment.bytes(), expected.fragment.bytes(), "idx {idx}");
    }

    #[test]
    fn dtls_flight_handshake_fragments_flush_with_record() {
        // Message lengths are chosen so that the first two each occupy an entire record and the
        // last partially. Where r indicates 13 bytes of record header, h indicates 12 bytes of
        // handshake header and H[x] indicates x bytes of handshake payload, we will get records:
        //
        // rhH[32]
        // rhH[32]
        // rhH[16] <-- last record is smaller than fragment size
        let messages = [vec![6u8; 32], vec![7; 32], vec![8; 16]];
        let message_flight: Vec<_> = messages
            .iter()
            .map(|m| {
                (
                    HandshakeType::Finished,
                    HandshakeMessagePayload(HandshakePayload::Finished(Payload::new(m.clone())))
                        .get_encoding(),
                )
            })
            .collect();

        let mut fragmenter = MessageFragmenter::default();
        fragmenter
            .set_max_fragment_size(Some(32 + DTLS_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE))
            .unwrap();

        let records = fragmenter.fragment_dtls_handshake_message_flight(
            EpochAndSequence::new(11, 255),
            17,
            &message_flight,
        );
        assert_eq!(records.len(), 3);

        for (idx, (record, message)) in records.iter().zip(messages).enumerate() {
            assert_eq!(record.typ, ContentType::Handshake);
            assert_eq!(record.version, ProtocolVersion::DTLSv1_2);
            assert_eq!(
                record.epoch_and_sequence,
                Some(EpochAndSequence::new(11, 255 + idx as u64)),
            );
            assert_eq!(
                record.payload.bytes().len(),
                message.len() + DTLS_HANDSHAKE_HEADER_SIZE
            );
            // read_bytes ensures that there are no trailing bytes in the payload, i.e. that each
            // record contains exactly one handshake fragment.
            let handshake_fragment =
                DtlsHandshakeFragment::read_bytes(record.payload.bytes()).unwrap();
            check_handshake_fragment(
                idx,
                &handshake_fragment,
                &DtlsHandshakeFragment {
                    msg_type: HandshakeType::Finished,
                    length: U24(message.len().try_into().unwrap()),
                    message_seq: 17 + idx as u16,
                    fragment_offset: U24(0),
                    fragment_length: U24(message.len().try_into().unwrap()),
                    fragment: Payload::Borrowed(message.as_slice()),
                },
            );
        }
    }

    #[test]
    fn dtls_flight_handshake_fragments_span_record() {
        // Message lengths are chosen so that the first occupies the entire first record and part of
        // the second, and the second occupies part of the second record and part of the third.
        // Using notation from dtls_flight_handshake_fragments_flush_with_record, we will get
        // records:
        //
        // rhH[32]      <-- first 32 bytes of first message
        // rhH[4]hH[16] <-- last 4 bytes of first message plus first 16 bytes of second message
        // rhH[16]      <-- last 16 bytes of second message; last record is smaller than fragment
        //                  size
        let messages = [vec![6u8; 36], vec![7; 32]];
        let message_flight: Vec<_> = messages
            .iter()
            .map(|m| {
                (
                    HandshakeType::Finished,
                    HandshakeMessagePayload(HandshakePayload::Finished(Payload::new(m.clone())))
                        .get_encoding(),
                )
            })
            .collect();

        let mut fragmenter = MessageFragmenter::default();
        fragmenter
            .set_max_fragment_size(Some(32 + DTLS_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE))
            .unwrap();

        let records = fragmenter.fragment_dtls_handshake_message_flight(
            EpochAndSequence::new(11, 255),
            17,
            &message_flight,
        );
        assert_eq!(records.len(), 3);

        let mut handshake_fragments = Vec::new();

        for (idx, record) in records.iter().enumerate() {
            assert_eq!(record.typ, ContentType::Handshake);
            assert_eq!(record.version, ProtocolVersion::DTLSv1_2);
            assert_eq!(
                record.epoch_and_sequence,
                Some(EpochAndSequence::new(11, 255 + idx as u64)),
            );
            if idx < 2 {
                assert_eq!(
                    record.payload.bytes().len(),
                    32 + DTLS_HANDSHAKE_HEADER_SIZE
                );
            } else {
                assert_eq!(
                    record.payload.bytes().len(),
                    16 + DTLS_HANDSHAKE_HEADER_SIZE
                );
            }

            let mut reader = Reader::new(record.payload.bytes());
            while reader.any_left() {
                handshake_fragments.push(DtlsHandshakeFragment::read(&mut reader).unwrap());
            }
        }

        let expected_fragments = [
            DtlsHandshakeFragment {
                msg_type: HandshakeType::Finished,
                length: U24(36),
                message_seq: 17,
                fragment_offset: U24(0),
                fragment_length: U24(32),
                fragment: Payload::new([6; 32]),
            },
            DtlsHandshakeFragment {
                msg_type: HandshakeType::Finished,
                length: U24(36),
                message_seq: 17,
                fragment_offset: U24(32),
                fragment_length: U24(4),
                fragment: Payload::new([6; 4]),
            },
            DtlsHandshakeFragment {
                msg_type: HandshakeType::Finished,
                length: U24(32),
                message_seq: 18,
                fragment_offset: U24(0),
                fragment_length: U24(16),
                fragment: Payload::new([7; 16]),
            },
            DtlsHandshakeFragment {
                msg_type: HandshakeType::Finished,
                length: U24(32),
                message_seq: 18,
                fragment_offset: U24(16),
                fragment_length: U24(16),
                fragment: Payload::new([7; 16]),
            },
        ];
        assert_eq!(handshake_fragments.len(), expected_fragments.len());

        for (idx, (handshake_fragment, expected_fragment)) in handshake_fragments
            .iter()
            .zip(expected_fragments)
            .enumerate()
        {
            check_handshake_fragment(idx, handshake_fragment, &expected_fragment);
        }
    }

    #[test]
    fn dtls_flight_partially_filled_record() {
        // Message lengths are chosen so that the first occupies most of the first record, but
        // leaves less than DTLS_HANDSHAKE_HEADER_SIZE bytes remaining, such that the second message
        // gets pushed out to the second record.
        // Using notation from dtls_flight_handshake_fragments_flush_with_record, we will get
        // records:
        //
        // rhH[28]      <-- all 28 bytes of first message
        // rhH[4]hH[16] <-- 4 bytes of second message plus 16 bytes of third message
        let messages = [vec![6u8; 28], vec![7; 4], vec![8; 16]];
        let record_lens = [
            28 + DTLS_HANDSHAKE_HEADER_SIZE,
            4 + DTLS_HANDSHAKE_HEADER_SIZE + 16 + DTLS_HANDSHAKE_HEADER_SIZE,
        ];
        let message_flight: Vec<_> = messages
            .iter()
            .map(|m| {
                (
                    HandshakeType::Finished,
                    HandshakeMessagePayload(HandshakePayload::Finished(Payload::new(m.clone())))
                        .get_encoding(),
                )
            })
            .collect();

        let mut fragmenter = MessageFragmenter::default();
        fragmenter
            .set_max_fragment_size(Some(32 + DTLS_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_SIZE))
            .unwrap();

        let records = fragmenter.fragment_dtls_handshake_message_flight(
            EpochAndSequence::new(11, 255),
            17,
            &message_flight,
        );
        assert_eq!(records.len(), 2);

        let mut handshake_fragments = Vec::new();

        for (idx, (record, expected_record_len)) in records
            .iter()
            .zip(record_lens)
            .enumerate()
        {
            assert_eq!(record.typ, ContentType::Handshake);
            assert_eq!(record.version, ProtocolVersion::DTLSv1_2);
            assert_eq!(
                record.epoch_and_sequence,
                Some(EpochAndSequence::new(11, 255 + idx as u64)),
            );
            assert_eq!(record.payload.bytes().len(), expected_record_len);

            let mut reader = Reader::new(record.payload.bytes());
            while reader.any_left() {
                handshake_fragments.push(DtlsHandshakeFragment::read(&mut reader).unwrap());
            }
        }

        let expected_fragments = [
            DtlsHandshakeFragment {
                msg_type: HandshakeType::Finished,
                length: U24(28),
                message_seq: 17,
                fragment_offset: U24(0),
                fragment_length: U24(28),
                fragment: Payload::new([6; 28]),
            },
            DtlsHandshakeFragment {
                msg_type: HandshakeType::Finished,
                length: U24(4),
                message_seq: 18,
                fragment_offset: U24(0),
                fragment_length: U24(4),
                fragment: Payload::new([7; 4]),
            },
            DtlsHandshakeFragment {
                msg_type: HandshakeType::Finished,
                length: U24(16),
                message_seq: 19,
                fragment_offset: U24(0),
                fragment_length: U24(16),
                fragment: Payload::new([8; 16]),
            },
        ];
        assert_eq!(handshake_fragments.len(), expected_fragments.len());

        for (idx, (handshake_fragment, expected_fragment)) in handshake_fragments
            .iter()
            .zip(expected_fragments)
            .enumerate()
        {
            check_handshake_fragment(idx, handshake_fragment, &expected_fragment);
        }
    }
}
