use crate::Error;
use crate::crypto::cipher::{EncodedMessage, OutboundPlain, Payload};
#[cfg(feature = "dtls")]
use crate::enums::HandshakeType;
use crate::enums::{ContentType, ProtocolVersion};
#[cfg(feature = "dtls")]
use crate::msgs::{DtlsHandshakeFragment, EpochAndSequence, U24};

pub(crate) const MAX_FRAGMENT_LEN: usize = 16384;
pub(crate) const PACKET_OVERHEAD: usize = 1 + 2 + 2;
#[cfg(feature = "dtls")]
pub(crate) const DTLS_PACKET_OVERHEAD: usize = PACKET_OVERHEAD
    // Epoch
    + 2
    // Sequence number
     + 6;
#[cfg(feature = "dtls")]
pub(crate) const DTLS_HANDSHAKE_OVERHEAD: usize =
    // Handshake type
    1
    // Length
    + 3
    // Message sequence
    + 2
    // Fragment offset
    + 3
    // Fragment length
    + 3;
pub(crate) const MAX_FRAGMENT_SIZE: usize = MAX_FRAGMENT_LEN + PACKET_OVERHEAD;

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
    /// TODO(timg): handshake flights?
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
            self.max_fragment_size(ProtocolVersion::DTLSv1_2) - DTLS_HANDSHAKE_OVERHEAD,
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

            // Stuck here: I want to write this DTLS handshake message, but
            // HandshakeMessagepayload::payload_encode already does it without my new fields
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
                self.max_frag - DTLS_PACKET_OVERHEAD
            }
            _ => self.max_frag - PACKET_OVERHEAD,
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

/// An iterator over

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use std::vec;

    use super::{MessageFragmenter, PACKET_OVERHEAD};
    use crate::crypto::cipher::{EncodedMessage, OutboundPlain, Payload};
    use crate::enums::{ContentType, HandshakeType, ProtocolVersion};
    use crate::msgs::DtlsHandshakeFragment;
    use crate::msgs::fragmenter::{DTLS_HANDSHAKE_OVERHEAD, DTLS_PACKET_OVERHEAD};
    #[cfg(feature = "dtls")]
    use crate::msgs::{EpochAndSequence, U24};

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
            PACKET_OVERHEAD + 8,
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
        let content_type = ContentType::Handshake;
        let encoded_handshake = &[b'a'; 104];
        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32 + DTLS_PACKET_OVERHEAD + DTLS_HANDSHAKE_OVERHEAD))
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
            assert_eq!(typ, content_type, "fragment {index}");
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
}
