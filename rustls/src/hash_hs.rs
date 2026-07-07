use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;

use crate::crypto::{HashAlgorithm, hash};
use crate::enums::ProtocolVersion;
use crate::msgs::{Codec, HandshakeAlignedProof, HandshakeMessagePayload, Message, MessagePayload};

/// Early stage buffering of handshake payloads.
///
/// Before we know the hash algorithm to use to verify the handshake, we just buffer the messages.
/// During the handshake, we may restart the transcript due to a HelloRetryRequest, reverting
/// from the `HandshakeHash` to a `HandshakeHashBuffer` again.
#[derive(Clone)]
pub(crate) struct HandshakeHashBuffer {
    buffer: Vec<u8>,
    client_auth_enabled: bool,
}

impl HandshakeHashBuffer {
    pub(crate) fn new() -> Self {
        Self {
            buffer: Vec::new(),
            client_auth_enabled: false,
        }
    }

    /// We might be doing client auth, so need to keep a full
    /// log of the handshake.
    pub(crate) fn set_client_auth_enabled(&mut self) {
        self.client_auth_enabled = true;
    }

    /// Hash or buffer a byte slice.
    pub(crate) fn add(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Get the hash value if we were to hash `extra` too.
    pub(crate) fn hash_given(
        &self,
        provider: &'static dyn hash::Hash,
        extra: &[u8],
    ) -> hash::Output {
        let mut ctx = provider.start();
        ctx.update(&self.buffer);
        ctx.update(extra);
        ctx.finish()
    }

    /// We now know what hash function the verify_data will use.
    pub(crate) fn start_hash(
        self,
        provider: &'static dyn hash::Hash,
        negotiated_version: ProtocolVersion,
    ) -> HandshakeHash {
        let (first, second) = HandshakeHash::split_around_dtls_handshake_fragment_fields(
            negotiated_version,
            &self.buffer,
        );
        let mut ctx = provider.start();
        ctx.update(first);
        ctx.update(second);
        HandshakeHash {
            provider,
            ctx,
            client_auth: match self.client_auth_enabled {
                true => {
                    let mut buf = first.to_vec();
                    buf.extend_from_slice(second);
                    Some(buf)
                }
                false => None,
            },
        }
    }
}

/// This deals with keeping a running hash of the handshake
/// payloads.  This is computed by buffering initially.  Once
/// we know what hash function we need to use we switch to
/// incremental hashing.
///
/// For client auth, we also need to buffer all the messages.
/// This is disabled in cases where client auth is not possible.
pub(crate) struct HandshakeHash {
    provider: &'static dyn hash::Hash,
    ctx: Box<dyn hash::Context>,

    /// buffer for client-auth.
    client_auth: Option<Vec<u8>>,
}

impl HandshakeHash {
    /// We decided not to do client auth after all, so discard
    /// the transcript.
    pub(crate) fn abandon_client_auth(&mut self) {
        self.client_auth = None;
    }

    /// Hash/buffer an encoded handshake message.
    pub(crate) fn add(&mut self, version: ProtocolVersion, bytes: &[u8]) {
        let (first, second) = Self::split_around_dtls_handshake_fragment_fields(version, bytes);
        self.add_raw(first).add_raw(second);
    }

    /// Hash or buffer a byte slice.
    fn add_raw(&mut self, buf: &[u8]) -> &mut Self {
        self.ctx.update(buf);

        if let Some(buffer) = &mut self.client_auth {
            buffer.extend_from_slice(buf);
        }

        self
    }

    /// Get the hash value if we were to hash `extra` too.
    pub(crate) fn hash_given(&self, extra: &[u8]) -> hash::Output {
        let mut ctx = self.ctx.fork();
        ctx.update(extra);
        ctx.finish()
    }

    pub(crate) fn into_hrr_buffer(self, _proof: &HandshakeAlignedProof) -> HandshakeHashBuffer {
        let old_hash = self.ctx.finish();
        let old_handshake_hash_msg =
            HandshakeMessagePayload::build_handshake_hash(old_hash.as_ref());

        HandshakeHashBuffer {
            buffer: old_handshake_hash_msg.get_encoding(),
            client_auth_enabled: self.client_auth.is_some(),
        }
    }

    /// Take the current hash value, and encapsulate it in a
    /// 'handshake_hash' handshake message.  Start this hash
    /// again, with that message at the front.
    pub(crate) fn rollup_for_hrr(&mut self) {
        let ctx = &mut self.ctx;

        let old_ctx = mem::replace(ctx, self.provider.start());
        let old_hash = old_ctx.finish();
        let old_handshake_hash_msg =
            HandshakeMessagePayload::build_handshake_hash(old_hash.as_ref());

        self.add_raw(&old_handshake_hash_msg.get_encoding());
    }

    /// Get the current hash value.
    pub(crate) fn current_hash(&self) -> hash::Output {
        self.ctx.fork_finish()
    }

    /// Takes this object's buffer containing all handshake messages
    /// so far.  This method only works once; it resets the buffer
    /// to empty.
    pub(crate) fn take_handshake_buf(&mut self) -> Option<Vec<u8>> {
        self.client_auth.take()
    }

    /// The hashing algorithm
    pub(crate) fn algorithm(&self) -> HashAlgorithm {
        self.provider.algorithm()
    }

    /// In TLS 1.2 or 1.3, the entire handshake payload gets hashed. In DTLS 1.2, the entire
    /// handshake message including the DTLS-specific message_seq, fragment_offset, and
    /// fragment_length fields are hashed ([1]). But in DTLS 1.3, those fields are omitted ([2]).
    ///
    /// This function takes the encoded handshake message payload and splits it into two slices
    /// based on protocol version. For TLS 1.2, TLS 1.3 and DTLS 1.2, the entire encoded payload is
    /// yielded, split across the two slices. For DTLS 1.3, the encoded payload is split around
    /// bytes 5-12, which are occupied by the omitted fields.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.6
    /// [2]: https://datatracker.ietf.org/doc/html/rfc9147#section-5.2
    fn split_around_dtls_handshake_fragment_fields(
        version: ProtocolVersion,
        encoded_handshake_payload: &[u8],
    ) -> (&[u8], &[u8]) {
        if encoded_handshake_payload.len() < 4 {
            return (encoded_handshake_payload, &[]);
        }
        // msg_type (1 byte) + length (3 bytes)
        let first_slice = &encoded_handshake_payload[..1 + 3];
        let second_slice = if version == ProtocolVersion::DTLSv1_3 {
            // Skip msg_typ (1 byte) + length (3 bytes) + message_seq (2 bytes) +
            // fragment_offset (3 bytes) + fragment_length (3 bytes)
            &encoded_handshake_payload[1 + 3 + 2 + 3 + 3..]
        } else {
            // Remainder of input buffer
            &encoded_handshake_payload[1 + 3..]
        };

        (first_slice, second_slice)
    }
}

impl Clone for HandshakeHash {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider,
            ctx: self.ctx.fork(),
            client_auth: self.client_auth.clone(),
        }
    }
}

#[cfg(all(test, any(target_arch = "aarch64", target_arch = "x86_64")))]
mod tests {
    use super::*;
    use crate::crypto::cipher::Payload;
    use crate::crypto::test_provider::SHA256;
    use crate::enums::{HandshakeType, ProtocolVersion};
    use crate::msgs::{HandshakeMessagePayload, HandshakePayload};

    #[test]
    fn hashes_correctly() {
        let mut hhb = HandshakeHashBuffer::new();
        hhb.add(b"hello");
        assert_eq!(hhb.buffer.len(), 5);
        let mut hh = hhb.start_hash(SHA256, ProtocolVersion::TLSv1_2);
        assert!(hh.client_auth.is_none());
        hh.add_raw(b"world");
        let h = hh.current_hash();
        let h = h.as_ref();
        assert_eq!(h[0], 0x93);
        assert_eq!(h[1], 0x6a);
        assert_eq!(h[2], 0x18);
        assert_eq!(h[3], 0x5c);
    }

    #[test]
    fn buffers_correctly() {
        let mut hhb = HandshakeHashBuffer::new();
        hhb.set_client_auth_enabled();
        hhb.add(b"hello");
        assert_eq!(hhb.buffer.len(), 5);

        let mut hh = hhb.start_hash(SHA256, ProtocolVersion::TLSv1_2);
        assert_eq!(
            hh.client_auth
                .as_ref()
                .map(|buf| buf.len()),
            Some(5)
        );

        hh.add_raw(b"world");
        assert_eq!(
            hh.client_auth
                .as_ref()
                .map(|buf| buf.len()),
            Some(10)
        );

        let h = hh.current_hash();
        let h = h.as_ref();
        assert_eq!(h[0], 0x93);
        assert_eq!(h[1], 0x6a);
        assert_eq!(h[2], 0x18);
        assert_eq!(h[3], 0x5c);
        let buf = hh.take_handshake_buf();
        assert_eq!(Some(b"helloworld".to_vec()), buf);
    }

    #[test]
    fn abandon() {
        let mut hhb = HandshakeHashBuffer::new();
        hhb.set_client_auth_enabled();
        hhb.add(b"hello");
        assert_eq!(hhb.buffer.len(), 5);

        let mut hh = hhb.start_hash(SHA256, ProtocolVersion::TLSv1_2);
        assert_eq!(
            hh.client_auth
                .as_ref()
                .map(|buf| buf.len()),
            Some(5)
        );

        hh.abandon_client_auth();
        assert_eq!(hh.client_auth, None);
        hh.add_raw(b"world");
        assert_eq!(hh.client_auth, None);

        let h = hh.current_hash();
        let h = h.as_ref();
        assert_eq!(h[0], 0x93);
        assert_eq!(h[1], 0x6a);
        assert_eq!(h[2], 0x18);
        assert_eq!(h[3], 0x5c);
    }

    #[test]
    fn clones_correctly() {
        let mut hhb = HandshakeHashBuffer::new();
        hhb.set_client_auth_enabled();
        hhb.add(b"hello");
        assert_eq!(hhb.buffer.len(), 5);

        // Cloning the HHB should result in the same buffer and client auth state.
        let mut hhb_prime = hhb.clone();
        assert_eq!(hhb_prime.buffer, hhb.buffer);
        assert!(hhb_prime.client_auth_enabled);

        // Updating the HHB clone shouldn't affect the original.
        hhb_prime.add(b"world");
        assert_eq!(hhb_prime.buffer.len(), 10);
        assert_ne!(hhb.buffer, hhb_prime.buffer);

        let hh = hhb.start_hash(SHA256, ProtocolVersion::TLSv1_2);
        let hh_hash = hh.current_hash();
        let hh_hash = hh_hash.as_ref();

        // Cloning the HH should result in the same current hash.
        let mut hh_prime = hh.clone();
        let hh_prime_hash = hh_prime.current_hash();
        let hh_prime_hash = hh_prime_hash.as_ref();
        assert_eq!(hh_hash, hh_prime_hash);

        // Updating the HH clone shouldn't affect the original.
        hh_prime.add_raw(b"goodbye");
        assert_eq!(hh.current_hash().as_ref(), hh_hash);
        assert_ne!(hh_prime.current_hash().as_ref(), hh_hash);
    }

    #[test]
    fn dtls_versions() {
        let first_message = [1u8; 20];
        let second_message = [2u8; 20];

        let mut hhb = HandshakeHashBuffer::new();
        hhb.add(&first_message);

        let mut hh_tls_12 = hhb
            .clone()
            .start_hash(SHA256, ProtocolVersion::TLSv1_2);
        let mut hh_tls_13 = hhb
            .clone()
            .start_hash(SHA256, ProtocolVersion::TLSv1_3);
        let mut hh_dtls_12 = hhb
            .clone()
            .start_hash(SHA256, ProtocolVersion::DTLSv1_2);
        let mut hh_dtls_13 = hhb
            .clone()
            .start_hash(SHA256, ProtocolVersion::DTLSv1_3);

        for (hh, version) in [
            (&mut hh_tls_12, ProtocolVersion::TLSv1_2),
            (&mut hh_tls_13, ProtocolVersion::TLSv1_3),
            (&mut hh_dtls_12, ProtocolVersion::DTLSv1_2),
            (&mut hh_dtls_13, ProtocolVersion::DTLSv1_3),
        ] {
            hh.add(version, &second_message);
        }

        // Transcript hashes for TLS 1.2, TLS 1.3, DTLS 1.2 should all be the same
        assert_eq!(
            hh_tls_12.current_hash().as_ref(),
            hh_tls_13.current_hash().as_ref()
        );
        assert_eq!(
            hh_tls_12.current_hash().as_ref(),
            hh_dtls_12.current_hash().as_ref()
        );
        // Transcript hash for DTLS 1.3 should differ
        assert_ne!(
            hh_tls_12.current_hash().as_ref(),
            hh_dtls_13.current_hash().as_ref()
        );

        // Hashing as DTLS 1.3 should be equivalent to hashing bytes [0..4]+[12..] as any other
        // version
        let mut hhb = HandshakeHashBuffer::new();
        hhb.add(&first_message[..4]);
        hhb.add(&first_message[12..]);
        let mut hh = hhb
            .clone()
            .start_hash(SHA256, ProtocolVersion::TLSv1_2);
        hh.add_raw(&second_message[..4]);
        hh.add_raw(&second_message[12..]);
        assert_eq!(
            hh_dtls_13.current_hash().as_ref(),
            hh.current_hash().as_ref()
        );
    }
}
