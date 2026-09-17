use alloc::boxed::Box;

use crate::crypto::cipher::{
    ContiguousRecordEncryptionProvider, EncryptBuffer, InboundOpaque, Iv, Nonce, OutboundPlain,
    Record, RecordDecrypter, RecordDecryptionProvider, RecordEncrypter, RecordEncryptionProvider,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::Error;

/// A [`RecordEncrypter`] implementing TLS 1.3.
///
/// This struct implements TLS 1.3 protocol-level details but relies on implementations of
/// [`RecordEncryptionProvider`] and [`ContiguousRecordEncryptionprovider`] for crypto primitives.
pub struct Tls13RecordEncrypter {
    provider: Box<dyn RecordEncryptionProvider<TLS13_AAD_SIZE>>,
    contiguous_provider: Option<Box<dyn ContiguousRecordEncryptionProvider<TLS13_AAD_SIZE>>>,
    iv: Iv,
}

impl Tls13RecordEncrypter {
    /// Create a new [`TlsRecordEncrypter`] from the providers and IV.
    ///
    /// Values should be created using [`Tls13AeadAlgorithm::record_encrypter`] instead of calling
    /// this directly.
    pub(crate) fn new(
        provider: Box<dyn RecordEncryptionProvider<TLS13_AAD_SIZE>>,
        contiguous_provider: Option<Box<dyn ContiguousRecordEncryptionProvider<TLS13_AAD_SIZE>>>,
        iv: Iv,
    ) -> Self {
        Self {
            provider,
            contiguous_provider,
            iv,
        }
    }
}

impl RecordEncrypter for Tls13RecordEncrypter {
    fn encrypt<'a>(
        &mut self,
        record: Record<OutboundPlain<'_>>,
        seq: u64,
        out: &'a mut [u8],
    ) -> Result<Record<&'a [u8]>, Error> {
        let total_len = self.encrypted_payload_len(record.payload.len());

        let typ = ContentType::ApplicationData;
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(typ, record.version.encode(), total_len);

        let payload = match (
            record.payload.single_chunk(),
            self.contiguous_provider.as_mut(),
        ) {
            // Fast path: plaintext is contiguous and the provider has a special case for it.
            (Some(contiguous_plain), Some(fast_path)) => fast_path.encrypt_contiguous(
                nonce,
                aad,
                contiguous_plain,
                &record.typ.to_array(),
                out,
                total_len,
            )?,
            // Slow path: either plaintext is not contiguous or the provider has no special support.
            // Gather plaintext into a buffer and seal it in-place.
            _ => {
                let mut payload = EncryptBuffer::new(out, total_len)?;
                payload.extend_from_chunks(&record.payload);
                payload.extend_from_slice(&record.typ.to_array());
                self.provider
                    .encrypt(nonce, aad, &mut payload)?;
                payload.into_written()
            }
        };

        Ok(Record {
            typ,
            version: record.version,
            payload,
        })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.provider.tag_len()
    }
}

/// A [`RecordDecrypter`] implementing TLS 1.3.
///
/// This struct implements TLS 1.3 protocol-level details but relies on implementations of
/// [`RecordDecryptionProvider`] for crypto primitives.
pub struct Tls13RecordDecrypter {
    provider: Box<dyn RecordDecryptionProvider<TLS13_AAD_SIZE>>,
    iv: Iv,
}

impl Tls13RecordDecrypter {
    /// Create a new `Tls13RecordDecrypter`.
    ///
    /// Values should be created via [`Tls13AeadAlgorithm::decrypter`] instead of call this
    /// directly.
    pub(crate) fn new(provider: Box<dyn RecordDecryptionProvider<TLS13_AAD_SIZE>>, iv: Iv) -> Self {
        Self { provider, iv }
    }
}

impl RecordDecrypter for Tls13RecordDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, Error> {
        let payload = &mut record.payload;
        if payload.len() < self.provider.tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(record.typ, record.version.version(), payload.len());

        let plain_len = self
            .provider
            .decrypt(nonce, aad, payload.as_mut(), 0..)?;

        payload.truncate(plain_len);
        record.into_tls13_unpadded_record()
    }
}

/// Returns a TLS1.3 `additional_data` encoding.
///
/// For decryption, the parameters should be those that were received on the wire.
/// For encryption, the parameters should be those that will be put on the wire.
///
/// See RFC 9846 s5.2 for the `additional_data` definition.
#[inline]
fn make_tls13_aad(
    typ: ContentType,
    version: ProtocolVersion,
    payload_len: usize,
) -> [u8; TLS13_AAD_SIZE] {
    let version = version.to_array();
    [
        typ.into(),
        version[0],
        version[1],
        (payload_len >> 8) as u8,
        (payload_len & 0xff) as u8,
    ]
}

/// TLS 1.3 AAD length.
///
/// 1 byte for content type, two bytes for version, two bytes for payload length.
pub const TLS13_AAD_SIZE: usize = 1 + 2 + 2;
