use core::ops::RangeFrom;

use alloc::boxed::Box;

use aws_lc_rs::{aead, tls_prf};
use pki_types::FipsStatus;
use rustls::crypto::cipher::{
    AeadKey, ContiguousRecordEncryptionProvider, EncryptBuffer, Iv, KeyBlockShape, NONCE_LEN,
    Nonce, RecordDecrypter, RecordDecryptionProvider, RecordEncrypter, RecordEncryptionProvider,
    TLS12_AAD_SIZE, Tls12AeadAlgorithm, Tls12ChaCha20Poly1305RecordDecrypter,
    Tls12ChaCha20Poly1305RecordEncrypter, Tls12GcmRecordDecrypter, Tls12GcmRecordEncrypter,
    UnsupportedOperationError,
};
use rustls::crypto::kx::{ActiveKeyExchange, KeyExchangeAlgorithm, SharedSecret};
use rustls::crypto::tls12::{Prf, PrfSecret};
use rustls::crypto::{CipherSuite, SignatureScheme};
use rustls::enums::ProtocolVersion;
use rustls::error::Error;
use rustls::version::TLS12_VERSION;
use rustls::{CipherSuiteCommon, ConnectionTrafficSecrets, Tls12CipherSuite};
use zeroize::Zeroizing;

use crate::record_region;

/// The TLS1.2 cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_TLS12_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = &[
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(not(feature = "fips"))]
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(not(feature = "fips"))]
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// A list of all the TLS1.2 cipher suites supported by the rustls aws-lc-rs provider.
pub static ALL_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = &[
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS12_VERSION,
    prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &ChaCha20Poly1305,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS12_VERSION,
    prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &ChaCha20Poly1305,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &AES128_GCM,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    prf_provider: &Tls12Prf(&tls_prf::P_SHA384),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    aead_alg: &AES256_GCM,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    prf_provider: &Tls12Prf(&tls_prf::P_SHA256),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &AES128_GCM,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS12_VERSION,
    prf_provider: &Tls12Prf(&tls_prf::P_SHA384),
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    aead_alg: &AES256_GCM,
};

static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

pub(crate) static AES128_GCM: GcmAlgorithm = GcmAlgorithm(&aead::AES_128_GCM);
pub(crate) static AES256_GCM: GcmAlgorithm = GcmAlgorithm(&aead::AES_256_GCM);

pub(crate) struct GcmAlgorithm(&'static aead::Algorithm);

impl Tls12AeadAlgorithm for GcmAlgorithm {
    fn record_decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn RecordDecrypter> {
        Box::new(Tls12GcmRecordDecrypter::new(self.decrypter(key), iv))
    }

    fn decrypter(&self, dec_key: AeadKey) -> Box<dyn RecordDecryptionProvider<TLS12_AAD_SIZE>> {
        // safety: see `encrypter()`.
        let dec_key =
            aead::TlsRecordOpeningKey::new(self.0, aead::TlsProtocolId::TLS12, dec_key.as_ref())
                .unwrap();

        Box::new(GcmRecordDecrypter { dec_key })
    }

    fn record_encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn RecordEncrypter> {
        Box::new(Tls12GcmRecordEncrypter::new(
            self.encrypter(key.clone()),
            self.contiguous_encrypter(key),
            iv,
            extra,
        ))
    }

    fn encrypter(&self, enc_key: AeadKey) -> Box<dyn RecordEncryptionProvider<TLS12_AAD_SIZE>> {
        // safety: `TlsRecordSealingKey::new` fails if
        // - `enc_key`'s length is wrong for `algorithm`.  But the length is defined by
        //   `algorithm.key_len()` in `key_block_shape()`, below.
        // - `algorithm` is not supported: but `AES_128_GCM` and `AES_256_GCM` is.
        // thus, this `unwrap()` is unreachable.
        //
        // `TlsProtocolId::TLS13` is deliberate: we reuse the nonce construction from
        // RFC 7905 and TLS13: a random starting point, XOR'd with the sequence number.  This means
        // `TlsProtocolId::TLS12` (which wants to see a plain sequence number) is unsuitable.
        //
        // The most important property is that nonce is unique per key, which is satisfied by
        // this construction, even if the nonce is not monotonically increasing.
        let enc_key =
            aead::TlsRecordSealingKey::new(self.0, aead::TlsProtocolId::TLS13, enc_key.as_ref())
                .unwrap();
        Box::new(GcmRecordEncrypter { enc_key })
    }

    fn contiguous_encrypter(
        &self,
        enc_key: AeadKey,
    ) -> Option<Box<dyn ContiguousRecordEncryptionProvider<TLS12_AAD_SIZE>>> {
        let enc_key =
            aead::TlsRecordSealingKey::new(self.0, aead::TlsProtocolId::TLS13, enc_key.as_ref())
                .unwrap();
        Some(Box::new(GcmRecordEncrypter { enc_key }))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.0.key_len(),
            fixed_iv_len: 4,
            explicit_nonce_len: 8,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let iv = gcm_iv(write_iv, explicit);
        Ok(match self.0.key_len() {
            16 => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            32 => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            _ => unreachable!(),
        })
    }

    fn fips(&self) -> FipsStatus {
        super::fips()
    }
}

pub(crate) struct ChaCha20Poly1305;

impl Tls12AeadAlgorithm for ChaCha20Poly1305 {
    fn record_decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn RecordDecrypter> {
        Box::new(Tls12ChaCha20Poly1305RecordDecrypter::new(
            self.decrypter(key),
            iv,
        ))
    }

    fn decrypter(&self, dec_key: AeadKey) -> Box<dyn RecordDecryptionProvider<TLS12_AAD_SIZE>> {
        let dec_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, dec_key.as_ref()).unwrap(),
        );
        Box::new(ChaCha20Poly1305RecordDecrypter { dec_key })
    }

    fn record_encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn RecordEncrypter> {
        Box::new(Tls12ChaCha20Poly1305RecordEncrypter::new(
            self.encrypter(key.clone()),
            self.contiguous_encrypter(key),
            iv,
        ))
    }

    fn encrypter(&self, enc_key: AeadKey) -> Box<dyn RecordEncryptionProvider<TLS12_AAD_SIZE>> {
        let enc_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, enc_key.as_ref()).unwrap(),
        );
        Box::new(ChaCha20Poly1305RecordEncrypter { enc_key })
    }

    fn contiguous_encrypter(
        &self,
        enc_key: AeadKey,
    ) -> Option<Box<dyn ContiguousRecordEncryptionProvider<TLS12_AAD_SIZE>>> {
        let enc_key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, enc_key.as_ref()).unwrap(),
        );
        Some(Box::new(ChaCha20Poly1305RecordEncrypter { enc_key }))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // This should always be true because KeyBlockShape and the Iv nonce len are in agreement.
        debug_assert_eq!(aead::NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv).expect("IV length validated by key_block_shape"),
        })
    }

    fn fips(&self) -> FipsStatus {
        FipsStatus::Unvalidated // not FIPS approved
    }
}

/// A `RecordEncrypter` for AES-GCM AEAD ciphersuites. TLS 1.2 only.
struct GcmRecordEncrypter {
    enc_key: aead::TlsRecordSealingKey,
}

/// A `RecordDecrypter` for AES-GCM AEAD ciphersuites.  TLS1.2 only.
struct GcmRecordDecrypter {
    dec_key: aead::TlsRecordOpeningKey,
}

impl<const AAD_SIZE: usize> RecordDecryptionProvider<AAD_SIZE> for GcmRecordDecrypter {
    fn decrypt(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_SIZE],
        payload: &mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<usize, Error> {
        let plain_len = self
            .dec_key
            .open_within(
                aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                aead::Aad::from(aad),
                payload,
                ciphertext_and_tag,
            )
            .map_err(|_| Error::DecryptError)?
            .len();

        Ok(plain_len)
    }

    fn tag_len(&self) -> usize {
        self.dec_key.algorithm().tag_len()
    }
}

impl<const AAD_SIZE: usize> RecordEncryptionProvider<AAD_SIZE> for GcmRecordEncrypter {
    fn encrypt(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_SIZE],
        payload: &mut EncryptBuffer<'_>,
    ) -> Result<(), Error> {
        let tag = self
            .enc_key
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                aead::Aad::from(aad),
                payload.as_mut(),
            )
            .map_err(|_| Error::EncryptError)?;
        payload.extend_from_slice(tag.as_ref());

        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.enc_key.algorithm().tag_len()
    }
}

impl<const AAD_SIZE: usize> ContiguousRecordEncryptionProvider<AAD_SIZE> for GcmRecordEncrypter {
    fn encrypt_contiguous<'a>(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_SIZE],
        plaintext: &[u8],
        extra_plaintext: &[u8],
        ciphertext: &'a mut [u8],
        encrypted_len: usize,
    ) -> Result<&'a [u8], Error> {
        let record = record_region(ciphertext, encrypted_len)?;
        let (ciphertext, tag) = record.split_at_mut(plaintext.len());
        self.enc_key
            .seal_out_of_place_scatter(
                aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                aead::Aad::from(aad),
                plaintext,
                ciphertext,
                extra_plaintext,
                tag,
            )
            .map_err(|_| Error::EncryptError)?;

        Ok(&*record)
    }
}

/// The RFC 7905/RFC 7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `Tls13RecordEncrypter`.
struct ChaCha20Poly1305RecordEncrypter {
    enc_key: aead::LessSafeKey,
}

/// The RFC 7905/RFC 7539 ChaCha20Poly1305 construction.
/// This implementation does the AAD construction required in TLS1.2.
/// TLS1.3 uses `Tls13RecordDecrypter`.
struct ChaCha20Poly1305RecordDecrypter {
    dec_key: aead::LessSafeKey,
}

impl<const AAD_SIZE: usize> RecordDecryptionProvider<AAD_SIZE> for ChaCha20Poly1305RecordDecrypter {
    fn decrypt(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_SIZE],
        payload: &mut [u8],
        _ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<usize, Error> {
        let plain_len = self
            .dec_key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                aead::Aad::from(aad),
                payload,
            )
            .map_err(|_| Error::DecryptError)?
            .len();

        Ok(plain_len)
    }

    fn tag_len(&self) -> usize {
        self.dec_key.algorithm().tag_len()
    }
}

impl<const AAD_SIZE: usize> RecordEncryptionProvider<AAD_SIZE> for ChaCha20Poly1305RecordEncrypter {
    fn encrypt(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_SIZE],
        payload: &mut EncryptBuffer<'_>,
    ) -> Result<(), Error> {
        let tag = self
            .enc_key
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                aead::Aad::from(aad),
                payload.as_mut(),
            )
            .map_err(|_| Error::EncryptError)?;

        payload.extend_from_slice(tag.as_ref());

        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.enc_key.algorithm().tag_len()
    }
}

impl<const AAD_SIZE: usize> ContiguousRecordEncryptionProvider<AAD_SIZE>
    for ChaCha20Poly1305RecordEncrypter
{
    fn encrypt_contiguous<'a>(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_SIZE],
        plaintext: &[u8],
        extra_plaintext: &[u8],
        ciphertext: &'a mut [u8],
        encrypted_len: usize,
    ) -> Result<&'a [u8], Error> {
        let record = record_region(ciphertext, encrypted_len)?;
        let (ciphertext, tag) = record.split_at_mut(plaintext.len());
        self.enc_key
            .seal_out_of_place_scatter(
                aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                aead::Aad::from(aad),
                plaintext,
                ciphertext,
                extra_plaintext,
                tag,
            )
            .map_err(|_| Error::EncryptError)?;

        Ok(&*record)
    }
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

struct Tls12Prf(&'static tls_prf::Algorithm);

impl Prf for Tls12Prf {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error> {
        Tls12PrfSecret {
            alg: self.0,
            secret: Secret::KeyExchange(
                kx.complete_for_tls_version(peer_pub_key, ProtocolVersion::TLSv1_2)?,
            ),
        }
        .prf(output, label, seed);
        Ok(())
    }

    fn new_secret(&self, secret: &[u8; 48]) -> Box<dyn PrfSecret> {
        Box::new(Tls12PrfSecret {
            alg: self.0,
            secret: Secret::Master(Zeroizing::new(*secret)),
        })
    }

    fn fips(&self) -> FipsStatus {
        super::fips()
    }
}

// nb: we can't put a `tls_prf::Secret` in here because it is
// consumed by `tls_prf::Secret::derive()`
struct Tls12PrfSecret {
    alg: &'static tls_prf::Algorithm,
    secret: Secret,
}

impl PrfSecret for Tls12PrfSecret {
    fn prf(&self, output: &mut [u8], label: &[u8], seed: &[u8]) {
        // safety:
        // - [1] is safe because our caller guarantees `secret` is non-empty; this is
        //   the only documented error case.
        // - [2] is safe in practice because the only failure from `derive()` is due
        //   to zero `output.len()`; this is outlawed at higher levels
        let derived = tls_prf::Secret::new(self.alg, self.secret.as_ref())
            .unwrap() // [1]
            .derive(label, seed, output.len())
            .unwrap(); // [2]
        output.copy_from_slice(derived.as_ref());
    }
}

enum Secret {
    Master(Zeroizing<[u8; 48]>),
    KeyExchange(SharedSecret),
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Master(ms) => ms.as_ref(),
            Self::KeyExchange(kx) => kx.secret_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;
    use std::vec::Vec;

    use rustls::crypto::cipher::{EncodableVersion, InboundOpaque, OutboundPlain, Record};
    use rustls::enums::ContentType;

    use super::*;

    /// Test that contiguous plaintext and fragmented plaintext are handled identically.
    #[test]
    fn out_of_place_sealing_matches_in_place() {
        let plain = b"the quick brown fox jumps over the lazy dog";
        let chunks = [&plain[..3], &plain[3..27], &plain[27..]];

        for suite in ALL_TLS12_CIPHER_SUITES {
            // Different `fill` values prove both paths write every output byte.
            let contiguous = seal(suite, OutboundPlain::from(plain), 0x00);
            let fragmented = seal(suite, OutboundPlain::new(&chunks), 0xff);
            assert_eq!(contiguous, fragmented, "{:?}", suite.common.suite);
        }
    }

    /// Sealed records must open through the corresponding decrypter.
    #[test]
    fn sealed_records_open() {
        for suite in ALL_TLS12_CIPHER_SUITES {
            for plain in [&b""[..], b"hello"] {
                let mut sealed = seal(suite, OutboundPlain::from(plain), 0x00);
                let record = Record::new(
                    ContentType::ApplicationData,
                    EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
                    InboundOpaque(&mut sealed),
                );
                let shape = suite.aead_alg.key_block_shape();
                let mut decrypter = suite
                    .aead_alg
                    .record_decrypter(test_key(shape.enc_key_len), &TEST_IV[..shape.fixed_iv_len]);
                let opened = decrypter
                    .decrypt(record, TEST_SEQ)
                    .unwrap();
                assert_eq!(opened.payload, plain, "{:?}", suite.common.suite);
            }
        }
    }

    fn seal(suite: &Tls12CipherSuite, payload: OutboundPlain<'_>, fill: u8) -> Vec<u8> {
        let shape = suite.aead_alg.key_block_shape();
        let mut encrypter = suite.aead_alg.record_encrypter(
            test_key(shape.enc_key_len),
            &TEST_IV[..shape.fixed_iv_len],
            &TEST_EXPLICIT[..shape.explicit_nonce_len],
        );
        let record = Record::new(
            ContentType::ApplicationData,
            EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
            payload,
        );
        let mut out = vec![fill; encrypter.encrypted_payload_len(record.payload.len())];
        encrypter
            .encrypt(record, TEST_SEQ, &mut out)
            .unwrap()
            .payload
            .to_vec()
    }

    fn test_key(len: usize) -> AeadKey {
        match len {
            16 => AeadKey::from([0x22; 16]),
            _ => AeadKey::from([0x22; 32]),
        }
    }

    const GCM_EXPLICIT_NONCE_LEN: usize = 8;
    const TEST_IV: [u8; NONCE_LEN] = [0x55; NONCE_LEN];
    const TEST_EXPLICIT: [u8; GCM_EXPLICIT_NONCE_LEN] = [0x66; GCM_EXPLICIT_NONCE_LEN];
    const TEST_SEQ: u64 = 7;
}
