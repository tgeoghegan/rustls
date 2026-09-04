//! Message definitions specific to DTLS 1.2 [1] and 1.3 [2].
//!
//! [1]: https://www.rfc-editor.org/info/rfc6347
//! [2]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02

use alloc::boxed::Box;
use alloc::vec::Vec;

use core::cmp::min_by_key;

use crate::Epoch;
use crate::crypto::cipher::{EncodingContext, Payload, RecordError, RecordSequenceNumberEncrypter};
use crate::enums::{ContentType, ContentTypeName, HandshakeType, ProtocolVersion};
use crate::error::InvalidMessage;
use crate::msgs::{
    Codec, HANDSHAKE_HEADER_SIZE, HEADER_SIZE, HandshakeSequenceNumber, ListLength, MAX_PAYLOAD,
    Reader, TlsListElement, U48, codec::U24,
};

pub(crate) fn read_dtls_record_header(
    r: &mut Reader<'_>,
) -> Result<DtlsMessageHeader, RecordError> {
    let typ = ContentType::read(r).map_err(|_| RecordError::TooShortForHeader)?;
    // Don't accept any new content-types.
    if ContentTypeName::try_from(typ).is_err() {
        return Err(RecordError::InvalidContentType);
    }

    let version = ProtocolVersion::read(r).map_err(|_| RecordError::TooShortForHeader)?;
    // Accept only versions 0x03XX (TLS) or 0xfe (DTLS) for any XX
    let allowed_version_high_bytes = [0x0300, 0xfe00].as_slice();
    if !allowed_version_high_bytes.contains(&(version.0 & 0xff00)) {
        return Err(RecordError::UnknownProtocolVersion);
    }

    // Epoch numbers are encoded as 16 bits in plaintext record headers.
    let epoch = Epoch::new(
        u16::read(r).map_err(|_| RecordError::TooShortForHeader)? as u64,
        version,
    );
    // Record sequence numbers are encoded as 48 bits in plaintext record headers.
    let sequence = FullRecordSequenceNumber::from(
        U48::read(r)
            .map_err(|_| RecordError::TooShortForHeader)?
            .0,
    );

    let len = u16::read(r).map_err(|_| RecordError::TooShortForHeader)?;

    // Reject undersize messages
    //  implemented per section 5.1 of RFC 9846 (TLSv1.3)
    //              per section 6.2.1 of RFC 5246 (TLSv1.2)
    if typ != ContentType::ApplicationData && len == 0 {
        return Err(RecordError::InvalidEmptyPayload);
    }

    // Reject oversize messages
    if len >= MAX_PAYLOAD {
        return Err(RecordError::MessageTooLarge);
    }

    Ok(DtlsMessageHeader {
        typ,
        version,
        epoch,
        sequence,
        len,
    })
}

pub(crate) struct DtlsMessageHeader {
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) epoch: Epoch,
    pub(crate) sequence: FullRecordSequenceNumber,
    pub(crate) len: u16,
}

#[derive(Debug)]
pub(crate) struct AckPayload {
    pub(crate) record_numbers: Vec<AckRecordSequenceNumber>,
}

impl Codec<'_> for AckPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.record_numbers.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        r.all("Ack", |r| {
            let record_numbers = Vec::<AckRecordSequenceNumber>::read(r)?;

            Ok(Self { record_numbers })
        })
    }
}

/// `RecordNumber` structure defined in [DTLS 1.3 section 4][1].
///
/// This is a 128 bit value consisting of the record epoch and sequence numbers. It is used
/// exclusively in [`Ack`] messages ([2]). Epoch and sequence numbers in record headers are
/// represented differently based on protocol version.
///
/// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4
/// [2]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-7
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct AckRecordSequenceNumber {
    pub epoch: Epoch,
    pub seq: FullRecordSequenceNumber,
}

impl Codec<'_> for AckRecordSequenceNumber {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // Be careful to encode epoch number as 64 bits, not 16 bits as in plaintext record header.
        self.epoch.number().encode(bytes);
        u64::from(self.seq).encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        // Epoch is serialized as 64 bits in struct RecordNumber, though it is 16 bits elsewhere.
        // ACKs are only sent in DTLS 1.3, so we can interpret the epoch in that context.
        let epoch = Epoch::new(u64::read(r)?, ProtocolVersion::DTLSv1_3);
        let seq = FullRecordSequenceNumber::from(u64::read(r)?);

        Ok(Self { epoch, seq })
    }
}

impl TlsListElement for AckRecordSequenceNumber {
    const SIZE_LEN: ListLength = ListLength::U16;
}

/// Fragment of a DTLS handshake message used in [Datagram TLS 1.2][1] and [1.3][2].
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.2
/// [2]: https://datatracker.ietf.org/doc/html/rfc9147#section-5.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DtlsHandshakeFragment<'a> {
    pub(crate) msg_type: HandshakeType,
    /// Total length of the message this is a fragment of. The value will be the same in all
    /// fragments of a given message.
    pub(crate) length: U24,
    /// Sequence number of the message this is a fragment of. The value will be the same in all
    /// fragments of a given message.
    pub(crate) message_seq: HandshakeSequenceNumber,
    /// The offset into the original message where this fragment begins. Equivalently, the sum of
    /// the lengths of all previous fragments.
    pub(crate) fragment_offset: U24,
    /// The length of this fragment.
    pub(crate) fragment_length: U24,
    /// The fragment. Its length must be equal to `fragment_length`.
    pub(crate) fragment: Payload<'a>,
}

impl<'a> Codec<'a> for DtlsHandshakeFragment<'a> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.msg_type.encode(bytes);
        self.length.encode(bytes);
        self.message_seq.encode(bytes);
        self.fragment_offset.encode(bytes);
        self.fragment_length.encode(bytes);
        self.fragment.encode(bytes);
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, InvalidMessage> {
        let msg_type = HandshakeType::read(r)?;
        let length = U24::read(r)?;
        let message_seq = HandshakeSequenceNumber::read(r)?;
        let fragment_offset = U24::read(r)?;
        let fragment_len = U24::read(r)?;
        let fragment = Payload::Borrowed(
            r.take(fragment_len.into())
                .ok_or_else(|| InvalidMessage::MessageTooShort)?,
        );

        Ok(Self {
            msg_type,
            length,
            message_seq,
            fragment_offset,
            fragment_length: fragment_len,
            fragment,
        })
    }
}

/// DTLS 1.3 unified record header, specified in [RFC 9157 section 4][1].
///
/// The first byte of the unified header is a bitfield describing the remainder of the
/// header:
///
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+
/// |0|0|1|C|S|L|E E|
/// +-+-+-+-+-+-+-+-+
///
///
/// The first three bits are 001 to distinguish from content type fields of records in other
/// protocols.
/// "C" bit indicates whether the connection ID is present in the header. Its length will have
/// previously been negotiated during the handshake.
/// "S" bit indicates size of the sequence number.
/// "L" bit indicates whether length is present.
/// "EE" bits are low two bits of the epoch of the encrypted message.
///
/// [1]: https://datatracker.ietf.org/doc/html/rfc9147#section-4
#[derive(Debug, Clone)]
pub(crate) struct UnifiedHeader<S> {
    /// An absent connection ID is represented by an empty `Vec`.
    // TODO: implement connection IDs. We assume them to be 0 length/absent for now.
    connection_id: Vec<u8>,
    pub(crate) epoch: Epoch,
    pub(crate) sequence: S,
    pub(crate) length: Option<u16>,
}

impl<S> UnifiedHeader<S> {
    pub(crate) fn encoded_len(&self) -> Option<[u8; 2]> {
        self.length.map(|l| l.to_be_bytes())
    }
}

impl<S: Copy> UnifiedHeader<S> {
    pub(crate) fn sequence(&self) -> S {
        self.sequence
    }
}

impl UnifiedHeader<TruncatedRecordSequenceNumber> {
    pub(crate) fn new(len: u16, cx: EncodingContext) -> Self {
        // truncate epoch to 2 bits
        let epoch_low_bits = Epoch::new(cx.epoch.number() & 0b11, ProtocolVersion::DTLSv1_3);
        Self {
            connection_id: Vec::new(),
            epoch: epoch_low_bits,
            sequence: cx.record_seq.truncate(),
            length: Some(len),
        }
    }

    pub(crate) fn encode(&self, bytes: &mut [u8]) {
        bytes[0] = UNIFIED_HEADER_FIXED_BITS;

        if self.connection_id.len() > 0 {
            panic!("connection ID should always be empty for now");
            // bitmask |= Self::C_BIT_MASK;
            // header.extend(self.connection_id);
        }

        // Always encode sequence number as 2 bytes for simplicity
        bytes[0] |= UNIFIED_HEADER_S_BIT_MASK;
        self.sequence.encode(&mut bytes[1..3]);
        if let Some(length) = self.encoded_len() {
            bytes[0] |= UNIFIED_HEADER_L_BIT_MASK;
            bytes[3..5].copy_from_slice(&length);
        }

        debug_assert!(self.epoch.number() <= UNIFIED_HEADER_EE_BITS_MASK as u64);
        bytes[0] |= self.epoch.number() as u8;
    }
}

impl UnifiedHeader<ProtectedRecordSequenceNumber> {
    /// Read a unified header from `r`.
    ///
    /// `current_epoch` is the epoch messages are expected to be in. `highest_seq` is the highest
    /// observed record sequence number observed in that epoch. These are used to reconstruct the
    /// full sequence number based on [RFC 9147 section 4.2.2][1].
    ///
    /// [1]: https://www.rfc-editor.org/info/rfc9147/#section-4.2.2
    pub(crate) fn read(r: &mut Reader<'_>, current_epoch: Epoch) -> Result<Self, InvalidMessage> {
        let bitfield = u8::read(r)?;

        if bitfield & UNIFIED_HEADER_FIXED_BITS_MASK != UNIFIED_HEADER_FIXED_BITS {
            return Err(InvalidMessage::InvalidDtls13UnifiedHeader);
        }

        if bitfield & UNIFIED_HEADER_C_BIT_MASK > 0 {
            panic!("connection ID should never be set for now");
            // TODO: handle connection ID properly. How do we figure out how long it should be, and
            // how do we smuggle that information into a call to `Codec::read`?
        }

        let long_encoding = bitfield & UNIFIED_HEADER_S_BIT_MASK > 0;
        let protected_sequence_number = if long_encoding {
            // bit set: 2 byte seq
            [u8::read(r)?, u8::read(r)?]
        } else {
            // bit clear: 1 byte seq
            [u8::read(r)?, 0]
        };

        let length = if bitfield & UNIFIED_HEADER_L_BIT_MASK > 0 {
            Some(u16::read(r)?)
        } else {
            None
        };

        // Infer the 16 bit epoch based on the low bits in the header and most recently seen epoch.
        let epoch_low_bits = bitfield & UNIFIED_HEADER_EE_BITS_MASK;

        Ok(Self {
            connection_id: Vec::new(),
            length,
            epoch: Epoch::new(
                current_epoch.number() | (epoch_low_bits as u64),
                ProtocolVersion::DTLSv1_3,
            ),
            sequence: ProtectedRecordSequenceNumber {
                protected: protected_sequence_number,
                long_encoding,
            },
        })
    }
}

pub(crate) fn is_unified_header(byte: u8) -> bool {
    byte & UNIFIED_HEADER_FIXED_BITS_MASK == UNIFIED_HEADER_FIXED_BITS
}

const UNIFIED_HEADER_FIXED_BITS: u8 = 0b0010_0000;
const UNIFIED_HEADER_FIXED_BITS_MASK: u8 = 0b1110_0000;
const UNIFIED_HEADER_C_BIT_MASK: u8 = 0b0001_0000;
const UNIFIED_HEADER_S_BIT_MASK: u8 = 0b0000_1000;
const UNIFIED_HEADER_L_BIT_MASK: u8 = 0b0000_0100;
const UNIFIED_HEADER_EE_BITS_MASK: u8 = 0b0000_0011;

/// Protected DTLS record sequence number.
///
/// Exclusively appears in the unified header on a DTLS 1.3 encrypted message.
///
/// <https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4.2.3>
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProtectedRecordSequenceNumber {
    /// The encrypted, truncated sequence number.
    ///
    /// Padded with a single 0 if the original encoded number was 1 byte long.
    pub(crate) protected: [u8; 2],
    /// Whether the sequence number was encoded in the long form.
    ///
    /// The long form is 2 bytes, the short form is 1. DTLS 1.3 unified headers allow either
    /// encoding.
    ///
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4>
    pub(crate) long_encoding: bool,
}

impl ProtectedRecordSequenceNumber {
    /// Deprotect a record sequence number into a truncated sequence number.
    ///
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4.2.3>
    pub(crate) fn deprotect(
        &self,
        encrypter: &Box<dyn RecordSequenceNumberEncrypter>,
        ciphertext: &[u8],
    ) -> TruncatedRecordSequenceNumber {
        let mut truncated = self.protected;
        encrypter
            .transform(&mut truncated, ciphertext)
            .unwrap();

        TruncatedRecordSequenceNumber {
            truncated,
            long_encoding: self.long_encoding,
        }
    }

    pub(crate) fn encode(&self, into: &mut [u8]) {
        let len = if self.long_encoding { 2 } else { 1 };
        into[..len].copy_from_slice(&self.protected[..len]);
    }
}

/// Deprotected, truncated DTLS record sequence number.
///
/// This is the result of deprotecting a [`ProtectedRecordSequenceNumber`] from a DTLS 1.3 unified
/// header and never appears in an encoded message.
///
/// <https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4.2.3>
#[derive(Clone, Copy, Debug)]
pub(crate) struct TruncatedRecordSequenceNumber {
    /// The truncated sequence number.
    ///
    /// Padded with a single 0 if the original encoded number was 1 byte long.
    pub(crate) truncated: [u8; 2],
    /// Whether the sequence number was encoded in the long form.
    ///
    /// The long form is 2 bytes, the short form is 1. DTLS 1.3 unified headers allow either
    /// encoding.
    ///
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4>
    long_encoding: bool,
}

impl TruncatedRecordSequenceNumber {
    /// Encode the truncated sequence number into the provided slice.
    pub(crate) fn encode(&self, into: &mut [u8]) {
        let len = if self.long_encoding { 2 } else { 1 };
        into[..len].copy_from_slice(&self.truncated[..len]);
    }

    /// Reconstruct the truncated sequence number into [`FullRecordSequenceNumber`].
    ///
    /// RFC 9147, section 4.2.2][1]:
    ///
    /// > [I]mplementations SHOULD reconstruct the sequence number by computing the full
    /// > sequence number which is numerically closest to one plus the sequence number of
    /// > the highest successfully deprotected record in the current epoch.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc9147#section-4.2.2
    pub(crate) fn reconstruct(
        &self,
        highest_seq: FullRecordSequenceNumber,
    ) -> FullRecordSequenceNumber {
        let truncated = u16::from_be_bytes(self.truncated) as u64;
        // First candidate: clear low bits of highest sequence we've seen and OR in the truncated
        // sequence number
        let reconstructed_seq_0: u64 = highest_seq.0
            & if self.long_encoding {
                0xffff_ffff_ffff_0000
            } else {
                0xffff_ffff_ffff_ff00
            }
            | truncated;
        // Second candidate: flip the first bit to the left of the truncated portion
        let reconstructed_seq_1 =
            reconstructed_seq_0 ^ if self.long_encoding { 0x1_ffff } else { 0x0100 };
        // Use whichever is closest to latest_seq+1
        FullRecordSequenceNumber(min_by_key(reconstructed_seq_0, reconstructed_seq_1, |v| {
            v.abs_diff(highest_seq.0 + 1)
        }))
    }

    /// Protect (encrypt) a truncated sequence number.
    pub(crate) fn protect(
        &self,
        encrypter: &Box<dyn RecordSequenceNumberEncrypter>,
        ciphertext: &[u8],
    ) -> ProtectedRecordSequenceNumber {
        let mut protected = self.truncated;
        encrypter
            .transform(&mut protected, ciphertext)
            .unwrap();

        ProtectedRecordSequenceNumber {
            protected,
            long_encoding: self.long_encoding,
        }
    }
}

/// Full DTLS record sequence number.
///
/// Appears in record headers for DTLS 1.2 ([1]) and unencrypted DTLS 1.3 (e.g., early handshake
/// messages or ACK).
///
/// This can also be obtained by reconstructing a sequence number from the encrypted, truncated
/// sequence number in a DTLS 1.3 unified header ([3]).
///
/// [1]: https://www.rfc-editor.org/info/rfc6347/#section-4.1
/// [2]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4
/// [3]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4.2.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct FullRecordSequenceNumber(u64);

impl FullRecordSequenceNumber {
    pub(crate) fn increment(&mut self) {
        self.0 += 1;
    }
}

impl FullRecordSequenceNumber {
    pub(crate) fn truncate(&self) -> TruncatedRecordSequenceNumber {
        TruncatedRecordSequenceNumber {
            // truncate sequence number to 16 bits
            truncated: ((self.0 & 0xffff) as u16).to_be_bytes(),
            // for now, rustls always uses the long encoding of sequence number
            long_encoding: true,
        }
    }

    pub(crate) fn encode(&self, into: &mut [u8]) {
        into.copy_from_slice(&self.0.to_be_bytes()[2..]);
    }
}

impl From<FullRecordSequenceNumber> for u64 {
    fn from(value: FullRecordSequenceNumber) -> Self {
        value.0
    }
}

impl From<u64> for FullRecordSequenceNumber {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// Sequence number of a DTLS record, possibly encrypted.
///
/// Not to be confused with a [`HandshakeSequenceNumber`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordSequenceNumber {
    /// Encrypted, truncated sequence number in a unified header ([DTLS 1.3 section 4.2.3][1]).
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-rfc9147bis-02#section-4.2.3
    Protected(ProtectedRecordSequenceNumber),
    Full(FullRecordSequenceNumber),
}

/// Length of the header on a full DTLS record.
///
/// This header is used for all DTLS 1.2 records and unencrypted DTLS 1.3 records that don't use a
/// unified header.
///
/// TLS header size plus epoch (2 bytes) and sequence number (6 bytes).
pub(crate) const DTLS_12_HEADER_SIZE: usize = HEADER_SIZE + 2 + 6;

/// Length of the unified header on an encrypted DTLS 1.3 record.
pub(crate) const DTLS_13_UNIFIED_HEADER_SIZE: usize = 1 + // bitmask
            0 + // Assume no connection IDs for now
            2 + // Always 2 bytes for seq. TODO(DTLS): truncate to 1 byte if seq is small enough
            2; // 2 bytes for length. TODO(DTLS): can we ever omit length?

/// Length of extra fields in the handshake header for DTLS.
///
/// Message sequence (2 bytes), fragment offset (3 bytes) and fragment length (3 bytes).
pub(crate) const DTLS_HANDSHAKE_HEADER_EXTRA: usize = 2 + 3 + 3;

/// Length of the header on a DTLS handshake message.
///
/// Does not include the record layer header.
pub(crate) const DTLS_HANDSHAKE_HEADER_SIZE: usize =
    HANDSHAKE_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_EXTRA;
