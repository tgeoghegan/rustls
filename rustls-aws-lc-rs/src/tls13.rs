use alloc::boxed::Box;
use core::ops::RangeFrom;

use aws_lc_rs::hkdf::KeyType;
use aws_lc_rs::{aead, hkdf, hmac};
use pki_types::FipsStatus;
use rustls::crypto::cipher::{
    AeadKey, ContiguousRecordEncryptionProvider, EncryptBuffer, Iv, Nonce,
    RecordDecryptionProvider, RecordEncryptionProvider, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use rustls::crypto::{self, CipherSuite};
use rustls::error::Error;
use rustls::version::TLS13_VERSION;
use rustls::{CipherSuiteCommon, ConnectionTrafficSecrets, Tls13CipherSuite};

use crate::record_region;

/// The TLS1.3 cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_TLS13_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    #[cfg(not(feature = "fips"))]
    TLS13_CHACHA20_POLY1305_SHA256,
];

/// A list of all the TLS1.3 cipher suites supported by the rustls aws-lc-rs provider.
pub static ALL_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
];

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        // ref: <https://www.ietf.org/archive/id/draft-irtf-cfrg-aead-limits-08.html#section-5.2.1>
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
    aead_alg: &Chacha20Poly1305Aead(AeadAlgorithm(&aead::CHACHA20_POLY1305)),
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::CHACHA20_POLY1305,
        header_alg: &aead::quic::CHACHA20,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        confidentiality_limit: u64::MAX,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-6.6>
        integrity_limit: 1 << 36,
    }),
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &super::hash::SHA384,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA384, hmac::HMAC_SHA384),
    aead_alg: &Aes256GcmAead(AeadAlgorithm(&aead::AES_256_GCM)),
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::AES_256_GCM,
        header_alg: &aead::quic::AES_256,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
        confidentiality_limit: 1 << 23,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
        integrity_limit: 1 << 52,
    }),
};

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &AwsLcHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
    aead_alg: &Aes128GcmAead(AeadAlgorithm(&aead::AES_128_GCM)),
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::AES_128_GCM,
        header_alg: &aead::quic::AES_128,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.1>
        confidentiality_limit: 1 << 23,
        // ref: <https://datatracker.ietf.org/doc/html/rfc9001#section-b.1.2>
        integrity_limit: 1 << 52,
    }),
};

struct Chacha20Poly1305Aead(AeadAlgorithm);

impl Chacha20Poly1305Aead {
    fn less_safe_key(&self, key: AeadKey) -> aead::LessSafeKey {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        aead::LessSafeKey::new(aead::UnboundKey::new(self.0.0, key.as_ref()).unwrap())
    }
}

impl Tls13AeadAlgorithm for Chacha20Poly1305Aead {
    fn encrypter(&self, key: AeadKey) -> Box<dyn RecordEncryptionProvider<5>> {
        Box::new(AeadRecordEncryptionProvider {
            enc_key: self.less_safe_key(key),
        })
    }

    fn contiguous_encrypter(
        &self,
        key: AeadKey,
    ) -> Option<Box<dyn ContiguousRecordEncryptionProvider<5>>> {
        Some(Box::new(AeadRecordEncryptionProvider {
            enc_key: self.less_safe_key(key),
        }))
    }

    fn decrypter(&self, key: AeadKey) -> Box<dyn RecordDecryptionProvider<5>> {
        Box::new(AeadRecordDecrypter {
            dec_key: self.less_safe_key(key),
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }

    fn fips(&self) -> FipsStatus {
        FipsStatus::Unvalidated // not FIPS approved
    }
}

struct Aes256GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes256GcmAead {
    fn encrypter(&self, key: AeadKey) -> Box<dyn RecordEncryptionProvider<5>> {
        self.0.encrypter(key)
    }

    fn contiguous_encrypter(
        &self,
        key: AeadKey,
    ) -> Option<Box<dyn ContiguousRecordEncryptionProvider<5>>> {
        self.0.contiguous_encrypter(key)
    }

    fn decrypter(&self, key: AeadKey) -> Box<dyn RecordDecryptionProvider<5>> {
        self.0.decrypter(key)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }

    fn fips(&self) -> FipsStatus {
        super::fips()
    }
}

struct Aes128GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes128GcmAead {
    fn encrypter(&self, key: AeadKey) -> Box<dyn RecordEncryptionProvider<5>> {
        self.0.encrypter(key)
    }

    fn contiguous_encrypter(
        &self,
        key: AeadKey,
    ) -> Option<Box<dyn ContiguousRecordEncryptionProvider<5>>> {
        self.0.contiguous_encrypter(key)
    }

    fn decrypter(&self, key: AeadKey) -> Box<dyn RecordDecryptionProvider<5>> {
        self.0.decrypter(key)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }

    fn fips(&self) -> FipsStatus {
        super::fips()
    }
}

// common encrypter/decrypter/key_len items for above Tls13AeadAlgorithm impls
struct AeadAlgorithm(&'static aead::Algorithm);

impl AeadAlgorithm {
    fn sealing_key(&self, key: AeadKey) -> aead::TlsRecordSealingKey {
        // safety:
        // - the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        // - this function should only be used for `Algorithm::AES_128_GCM` or
        //   `Algorithm::AES_256_GCM`
        aead::TlsRecordSealingKey::new(self.0, aead::TlsProtocolId::TLS13, key.as_ref()).unwrap()
    }

    fn encrypter(&self, key: AeadKey) -> Box<dyn RecordEncryptionProvider<5>> {
        Box::new(GcmRecordEncyptionProvider {
            enc_key: self.sealing_key(key),
        })
    }

    fn contiguous_encrypter(
        &self,
        key: AeadKey,
    ) -> Option<Box<dyn ContiguousRecordEncryptionProvider<5>>> {
        Some(Box::new(GcmRecordEncyptionProvider {
            enc_key: self.sealing_key(key),
        }))
    }

    // using aead::TlsRecordOpeningKey
    fn decrypter(&self, key: AeadKey) -> Box<dyn RecordDecryptionProvider<5>> {
        // safety:
        // - the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        // - this function should only be used for `Algorithm::AES_128_GCM` or `Algorithm::AES_256_GCM`
        Box::new(GcmRecordDecrypter {
            dec_key: aead::TlsRecordOpeningKey::new(
                self.0,
                aead::TlsProtocolId::TLS13,
                key.as_ref(),
            )
            .unwrap(),
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }
}

struct AeadRecordEncryptionProvider {
    enc_key: aead::LessSafeKey,
}

impl<const AAD_LEN: usize> RecordEncryptionProvider<AAD_LEN> for AeadRecordEncryptionProvider {
    fn encrypt(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_LEN],
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

impl<const AAD_LEN: usize> ContiguousRecordEncryptionProvider<AAD_LEN>
    for AeadRecordEncryptionProvider
{
    fn encrypt_contiguous<'a>(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_LEN],
        plaintext: &[u8],
        extra_plaintext: &[u8],
        ciphertext: &'a mut [u8],
        encrypted_len: usize,
    ) -> Result<&'a [u8], Error> {
        // Contiguous plaintext is sealed out-of-place, straight from the borrowed
        // input and the inner content type byte is specified as `extra_in`.
        let record = record_region(ciphertext, encrypted_len)?;
        let (ciphertext, typ_and_tag) = record.split_at_mut(plaintext.len());
        self.enc_key
            .seal_out_of_place_scatter(
                aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                aead::Aad::from(aad),
                plaintext,
                ciphertext,
                extra_plaintext,
                typ_and_tag,
            )
            .map_err(|_| Error::EncryptError)?;

        Ok(&*record)
    }
}

struct AeadRecordDecrypter {
    dec_key: aead::LessSafeKey,
}

impl<const AAD_LEN: usize> RecordDecryptionProvider<AAD_LEN> for AeadRecordDecrypter {
    fn decrypt(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_LEN],
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

struct GcmRecordEncyptionProvider {
    enc_key: aead::TlsRecordSealingKey,
}

impl<const AAD_LEN: usize> RecordEncryptionProvider<AAD_LEN> for GcmRecordEncyptionProvider {
    fn encrypt(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_LEN],
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

impl<const AAD_LEN: usize> ContiguousRecordEncryptionProvider<AAD_LEN>
    for GcmRecordEncyptionProvider
{
    fn encrypt_contiguous<'a>(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_LEN],
        plaintext: &[u8],
        extra_plaintext: &[u8],
        ciphertext: &'a mut [u8],
        encrypted_len: usize,
    ) -> Result<&'a [u8], Error> {
        // Contiguous plaintext is sealed out-of-place, straight from the borrowed
        // input and the inner content type byte is specified as `extra_in`.
        let record = record_region(ciphertext, encrypted_len)?;
        let (ciphertext, typ_and_tag) = record.split_at_mut(plaintext.len());
        self.enc_key
            .seal_out_of_place_scatter(
                aead::Nonce::assume_unique_for_key(nonce.to_array()?),
                aead::Aad::from(aad),
                plaintext,
                ciphertext,
                extra_plaintext,
                typ_and_tag,
            )
            .map_err(|_| Error::EncryptError)?;

        Ok(&*record)
    }
}

struct GcmRecordDecrypter {
    dec_key: aead::TlsRecordOpeningKey,
}

impl<const AAD_LEN: usize> RecordDecryptionProvider<AAD_LEN> for GcmRecordDecrypter {
    fn decrypt(
        &mut self,
        nonce: Nonce,
        aad: [u8; AAD_LEN],
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

struct AwsLcHkdf(hkdf::Algorithm, hmac::Algorithm);

impl Hkdf for AwsLcHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(&zeroes[..self.0.len()]),
        })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(secret),
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(AwsLcHkdfExpander {
            alg: self.0,
            prk: hkdf::Prk::new_less_safe(self.0, okm.as_ref()),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> crypto::hmac::Tag {
        crypto::hmac::Tag::new(hmac::sign(&hmac::Key::new(self.1, key.as_ref()), message).as_ref())
    }

    fn fips(&self) -> FipsStatus {
        super::fips()
    }
}

struct AwsLcHkdfExpander {
    alg: hkdf::Algorithm,
    prk: hkdf::Prk,
}

impl HkdfExpander for AwsLcHkdfExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        self.prk
            .expand(info, Len(output.len()))
            .and_then(|okm| okm.fill(output))
            .map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut buf = [0u8; OkmBlock::MAX_LEN];
        let output = &mut buf[..self.hash_len()];
        self.prk
            .expand(info, Len(output.len()))
            .and_then(|okm| okm.fill(output))
            .unwrap();
        OkmBlock::new(output)
    }

    fn hash_len(&self) -> usize {
        self.alg.len()
    }
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use std::vec;
    use std::vec::Vec;

    use rustls::crypto::cipher::{EncodableVersion, InboundOpaque, OutboundPlain, Record};
    use rustls::enums::{ContentType, ProtocolVersion};

    use super::*;

    /// Test that contiguous plaintext and fragmented plaintext are handled identically.
    #[test]
    fn out_of_place_sealing_matches_in_place() {
        let plain = b"the quick brown fox jumps over the lazy dog";
        let chunks = [&plain[..3], &plain[3..27], &plain[27..]];

        for suite in ALL_TLS13_CIPHER_SUITES {
            // Different `fill` values prove both paths write every output byte.
            let contiguous = seal(suite, OutboundPlain::from(plain), 0x00);
            let fragmented = seal(suite, OutboundPlain::new(&chunks), 0xff);
            assert_eq!(contiguous, fragmented, "{:?}", suite.common.suite);
        }
    }

    /// Sealed records must open through the corresponding decrypter.
    #[test]
    fn sealed_records_open() {
        for suite in ALL_TLS13_CIPHER_SUITES {
            for plain in [&b""[..], b"hello"] {
                let mut sealed = seal(suite, OutboundPlain::from(plain), 0x00);
                let record = Record::new(
                    ContentType::ApplicationData,
                    EncodableVersion::Legacy(ProtocolVersion::TLSv1_2),
                    InboundOpaque(&mut sealed),
                );
                let mut decrypter = suite
                    .aead_alg
                    .record_decrypter(test_key(suite.aead_alg.key_len()), Iv::from(TEST_IV));
                let opened = decrypter
                    .decrypt(record, TEST_SEQ)
                    .unwrap();
                assert_eq!(opened.typ, ContentType::ApplicationData);
                assert_eq!(opened.payload, plain, "{:?}", suite.common.suite);
            }
        }
    }

    fn seal(suite: &Tls13CipherSuite, payload: OutboundPlain<'_>, fill: u8) -> Vec<u8> {
        let mut encrypter = suite
            .aead_alg
            .record_encrypter(test_key(suite.aead_alg.key_len()), Iv::from(TEST_IV));
        let record = Record::new(
            ContentType::ApplicationData,
            EncodableVersion::Legacy(ProtocolVersion::TLSv1_3),
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

    const TEST_IV: [u8; 12] = [0x55; 12];
    const TEST_SEQ: u64 = 7;
}
