use alloc::boxed::Box;

use crate::crypto::cipher::{
    ContiguousRecordEncryptionProvider, EncryptBuffer, InboundOpaque, Iv, NONCE_LEN, Nonce,
    OutboundPlain, Record, RecordDecrypter, RecordDecryptionProvider, RecordEncrypter,
    RecordEncryptionProvider,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{ApiMisuse, Error};
use crate::msgs::{MAX_FRAGMENT_LEN, put_u16, put_u64};

/// A [`RecordEncrypter`] implementing AES-GCM suites for TLS 1.2.
///
/// This struct implements TLS 1.2 protocol-level details but relies on implementations of
/// [`RecordEncryptionProvider`] and [`ContiguousRecordEncryptionprovider`] for crypto primitives.
pub struct Tls12GcmRecordEncrypter {
    provider: Box<dyn RecordEncryptionProvider<TLS12_AAD_SIZE>>,
    contiguous_provider: Option<Box<dyn ContiguousRecordEncryptionProvider<TLS12_AAD_SIZE>>>,
    iv: Iv,
}

impl Tls12GcmRecordEncrypter {
    /// Create a new [`TlsRecordEncrypter`] from the providers and IV.
    ///
    /// Values should be created using [`Tls12AeadAlgorithm::record_encrypter`] instead of calling
    /// this directly.
    pub fn new(
        provider: Box<dyn RecordEncryptionProvider<TLS12_AAD_SIZE>>,
        contiguous_provider: Option<Box<dyn ContiguousRecordEncryptionProvider<TLS12_AAD_SIZE>>>,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Self {
        Self {
            provider,
            contiguous_provider,
            iv: gcm_iv(write_iv, explicit),
        }
    }
}

impl RecordEncrypter for Tls12GcmRecordEncrypter {
    fn encrypt<'a>(
        &mut self,
        record: Record<OutboundPlain<'_>>,
        seq: u64,
        _header: &'a [u8],
        out: &'a mut [u8],
    ) -> Result<Record<&'a [u8]>, Error> {
        let total_len = self.encrypted_payload_len(record.payload.len());
        std::println!("total len: {total_len}");

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(
            seq,
            record.typ,
            record.version.encode(),
            record.payload.len(),
        );

        let payload = match (
            record.payload.single_chunk(),
            self.contiguous_provider.as_mut(),
        ) {
            // Fast path: plaintext is contiguous and the provider has a special case for it.
            (Some(contiguous_plain), Some(fast_path)) => {
                let record = record_region(out, total_len)?;
                {
                    let (explicit_nonce, sealed) = record.split_at_mut(GCM_EXPLICIT_NONCE_LEN);
                    explicit_nonce.copy_from_slice(&nonce.as_ref()[4..]);
                    fast_path.encrypt_contiguous(
                        nonce,
                        aad,
                        contiguous_plain,
                        // no extra plaintext for TLS 1.2
                        &[],
                        sealed,
                        total_len - GCM_EXPLICIT_NONCE_LEN,
                    )?;
                }
                &*record
            }
            // Slow path: either plaintext is not contiguous or the provider has no special support.
            // Gather plaintext into a buffer and seal it in-place.
            _ => {
                // For AES-GCM suites, prefix plaintext with explicit nonce
                // <https://www.rfc-editor.org/info/rfc5246/#section-6.2.3.3>
                out[..GCM_EXPLICIT_NONCE_LEN].copy_from_slice(&nonce.as_ref()[4..]);

                {
                    // this scope forces payload to be dropped so we can borrow
                    // out again
                    let mut payload = EncryptBuffer::new(
                        &mut out[GCM_EXPLICIT_NONCE_LEN..],
                        total_len - GCM_EXPLICIT_NONCE_LEN,
                    )?;
                    payload.extend_from_chunks(&record.payload);
                    self.provider
                        .encrypt(nonce, aad, &mut payload)?;
                }

                out
            }
        };

        Ok(Record {
            typ: record.typ,
            version: record.version,
            payload,
        })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LEN + self.provider.tag_len()
    }

    fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::TLSv1_2
    }
}

/// A [`RecordDecrypter`] implementing AES-GCM suites for TLS 1.2.
///
/// This struct implements TLS 1.2 protocol-level details but relies on implementations of
/// [`RecordDecryptionProvider`] for crypto primitives.
pub struct Tls12GcmRecordDecrypter {
    provider: Box<dyn RecordDecryptionProvider<TLS12_AAD_SIZE>>,
    dec_salt: [u8; 4],
}

impl Tls12GcmRecordDecrypter {
    /// Create a new `Tls13RecordDecrypter`.
    ///
    /// Values should be created via [`Tls12AeadAlgorithm::decrypter`] instead of call this
    /// directly.
    pub fn new(provider: Box<dyn RecordDecryptionProvider<TLS12_AAD_SIZE>>, dec_iv: &[u8]) -> Self {
        let mut ret = Self {
            provider,
            dec_salt: [0u8; 4],
        };

        debug_assert_eq!(dec_iv.len(), 4);
        ret.dec_salt.copy_from_slice(dec_iv);

        ret
    }
}

impl RecordDecrypter for Tls12GcmRecordDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, Error> {
        let payload = &mut record.payload;
        if payload.len() < GCM_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce = {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&self.dec_salt);
            nonce[4..].copy_from_slice(&payload[..8]);
            Nonce::from(nonce)
        };

        let aad = make_tls12_aad(
            seq,
            record.typ,
            record.version.version(),
            payload.len() - GCM_OVERHEAD,
        );

        std::println!(
            "sending slice {:?} into decrypter",
            &mut payload.as_mut()[GCM_EXPLICIT_NONCE_LEN..]
        );
        let plain_len =
            self.provider
                .decrypt(nonce, aad, &mut payload.as_mut(), GCM_EXPLICIT_NONCE_LEN..)?;
        std::println!("decrypted: {:?}", payload.as_ref());

        if plain_len > MAX_FRAGMENT_LEN.get() {
            return Err(Error::PeerSentOversizedRecord);
        }

        payload.truncate(plain_len);
        Ok(record.into_plain_record())
    }
}

/// A [`RecordEncrypter`] implementing ChaCha20Poly1305 suites for TLS 1.2.
///
/// This struct implements TLS 1.2 protocol-level details but relies on implementations of
/// [`RecordEncryptionProvider`] and [`ContiguousRecordEncryptionprovider`] for crypto primitives.
pub struct Tls12ChaCha20Poly1305RecordEncrypter {
    provider: Box<dyn RecordEncryptionProvider<TLS12_AAD_SIZE>>,
    contiguous_provider: Option<Box<dyn ContiguousRecordEncryptionProvider<TLS12_AAD_SIZE>>>,
    iv: Iv,
}

impl Tls12ChaCha20Poly1305RecordEncrypter {
    /// Create a new [`TlsRecordEncrypter`] from the providers and IV.
    ///
    /// Values should be created using [`Tls12AeadAlgorithm::record_encrypter`] instead of calling
    /// this directly.
    pub fn new(
        provider: Box<dyn RecordEncryptionProvider<TLS12_AAD_SIZE>>,
        contiguous_provider: Option<Box<dyn ContiguousRecordEncryptionProvider<TLS12_AAD_SIZE>>>,
        write_iv: &[u8],
    ) -> Self {
        Self {
            provider,
            contiguous_provider,
            iv: Iv::new(write_iv).expect("IV length validated by key_block_shape"),
        }
    }
}

impl RecordEncrypter for Tls12ChaCha20Poly1305RecordEncrypter {
    fn encrypt<'a>(
        &mut self,
        record: Record<OutboundPlain<'_>>,
        seq: u64,
        _header: &'a [u8],
        out: &'a mut [u8],
    ) -> Result<Record<&'a [u8]>, Error> {
        let total_len = self.encrypted_payload_len(record.payload.len());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(
            seq,
            record.typ,
            record.version.encode(),
            record.payload.len(),
        );

        let payload = match (
            record.payload.single_chunk(),
            self.contiguous_provider.as_mut(),
        ) {
            // Fast path: plaintext is contiguous and the provider has a special case for it.
            (Some(contiguous_plain), Some(fast_path)) => {
                fast_path.encrypt_contiguous(
                    nonce,
                    aad,
                    contiguous_plain,
                    // no extra plaintext for TLS 1.2
                    &[],
                    out,
                    total_len,
                )?
            }
            // Slow path: either plaintext is not contiguous or the provider has no special support.
            // Gather plaintext into a buffer and seal it in-place.
            _ => {
                let mut payload = EncryptBuffer::new(out, total_len)?;
                payload.extend_from_chunks(&record.payload);
                self.provider
                    .encrypt(nonce, aad, &mut payload)?;
                payload.into_written()
            }
        };

        Ok(Record {
            typ: record.typ,
            version: record.version,
            payload,
        })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + self.provider.tag_len()
    }

    fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::TLSv1_2
    }
}

/// A [`RecordDecrypter`] implementing TLS 1.2 for AES-GCM suites.
///
/// This struct implements TLS 1.2 protocol-level details but relies on implementations of
/// [`RecordDecryptionProvider`] for crypto primitives.
pub struct Tls12ChaCha20Poly1305RecordDecrypter {
    provider: Box<dyn RecordDecryptionProvider<TLS12_AAD_SIZE>>,
    dec_offset: Iv,
}

impl Tls12ChaCha20Poly1305RecordDecrypter {
    /// Create a new `Tls13RecordDecrypter`.
    ///
    /// Values should be created via [`Tls13AeadAlgorithm::decrypter`] instead of call this
    /// directly.
    pub fn new(provider: Box<dyn RecordDecryptionProvider<TLS12_AAD_SIZE>>, iv: &[u8]) -> Self {
        Self {
            provider,
            dec_offset: Iv::new(iv).expect("IV length validated by key_block_shape"),
        }
    }
}

impl RecordDecrypter for Tls12ChaCha20Poly1305RecordDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, Error> {
        let payload = &mut record.payload;
        if payload.len() < CHACHAPOLY1305_OVERHEAD {
            return Err(Error::DecryptError);
        }

        let nonce = Nonce::new(&self.dec_offset, seq);
        let aad = make_tls12_aad(
            seq,
            record.typ,
            record.version.version(),
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        );

        let plain_len = self
            .provider
            .decrypt(nonce, aad, payload.as_mut(), 0..)?;

        if plain_len > MAX_FRAGMENT_LEN.get() {
            return Err(Error::PeerSentOversizedRecord);
        }

        payload.truncate(plain_len);
        Ok(record.into_plain_record())
    }
}

/// Returns a TLS1.2 `additional_data` encoding.
///
/// See RFC 5246 s6.2.3.3 for the `additional_data` definition.
#[inline]
fn make_tls12_aad(
    seq: u64,
    typ: ContentType,
    vers: ProtocolVersion,
    len: usize,
) -> [u8; TLS12_AAD_SIZE] {
    let mut out = [0; TLS12_AAD_SIZE];
    put_u64(seq, &mut out[0..]);
    out[8] = typ.into();
    put_u16(vers.into(), &mut out[9..]);
    put_u16(len as u16, &mut out[11..]);
    out
}

fn gcm_iv(write_iv: &[u8], explicit: &[u8]) -> Iv {
    debug_assert_eq!(write_iv.len(), 4);
    debug_assert_eq!(explicit.len(), 8);

    // The GCM nonce is constructed from a 32-bit 'salt' derived
    // from the master-secret, and a 64-bit explicit part,
    // with no specified construction.  Thanks for that.
    //
    // We use the same construction as TLS1.3/ChaCha20Poly1305:
    // a starting point extracted from the key block, xored with
    // the sequence number.
    let mut iv = [0; NONCE_LEN];
    iv[..4].copy_from_slice(write_iv);
    iv[4..].copy_from_slice(explicit);

    Iv::new(&iv).expect("IV length is NONCE_LEN, which is within MAX_LEN")
}

/// The region of `out` that a `len`-byte sealed record payload will occupy.
///
/// If `out` is shorter than `len` bytes, this returns [`ApiMisuse::EncryptBufferTooSmall`].
fn record_region(out: &mut [u8], len: usize) -> Result<&mut [u8], Error> {
    let provided = out.len();
    match out.get_mut(..len) {
        Some(record) => Ok(record),
        None => Err(Error::ApiMisuse(ApiMisuse::EncryptBufferTooSmall {
            required: len,
            provided,
        })
        .into()),
    }
}

pub const TLS12_AAD_SIZE: usize = 8 + 1 + 2 + 2;

/// Length of `explicit_nonce` for GCM suites
///
/// <https://www.rfc-editor.org/info/rfc5246/#section-6.2.3.3>
const GCM_EXPLICIT_NONCE_LEN: usize = 8;

const GCM_OVERHEAD: usize = GCM_EXPLICIT_NONCE_LEN + 16;

const CHACHAPOLY1305_OVERHEAD: usize = 16;
