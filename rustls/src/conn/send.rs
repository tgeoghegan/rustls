use alloc::boxed::Box;
use alloc::vec::Vec;

#[cfg(feature = "dtls")]
use crate::EpochAndSequence;
use crate::common_state::Protocol;
use crate::crypto::cipher::{
    EncodedMessage, EncryptionState, MessageEncrypter, OutboundOpaque, OutboundPlain,
    PreEncryptAction,
};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{AlertDescription, Error};
use crate::log::{debug, error};
use crate::msgs::{AlertLevel, Message, MessageFragmenter};
#[cfg(feature = "dtls")]
use crate::msgs::{Codec, MessagePayload};
use crate::tls13::key_schedule::KeyScheduleTrafficSend;
use crate::vecbuf::ChunkVecBuffer;

/// The data path from us to the peer.
pub(crate) struct SendPath {
    pub(crate) protocol: Protocol,
    pub(crate) encrypt_state: EncryptionState,
    pub(crate) may_send_application_data: bool,
    pub(crate) may_send_half_rtt_data: bool,
    has_sent_fatal_alert: bool,
    /// If we signaled end of stream.
    pub(crate) has_sent_close_notify: bool,
    message_fragmenter: MessageFragmenter,
    pub(crate) sendable_tls: ChunkVecBuffer,
    queued_key_update_message: Option<Vec<u8>>,
    pub(crate) refresh_traffic_keys_pending: bool,
    negotiated_version: Option<ProtocolVersion>,
    pub(crate) tls13_key_schedule: Option<Box<KeyScheduleTrafficSend>>,
    #[cfg(feature = "dtls")]
    handshake_sequence_number: u16,
}

impl SendPath {
    pub(crate) fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            encrypt_state: EncryptionState::new(),
            may_send_application_data: false,
            may_send_half_rtt_data: false,
            has_sent_fatal_alert: false,
            has_sent_close_notify: false,
            message_fragmenter: MessageFragmenter::default(),
            sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            queued_key_update_message: None,
            refresh_traffic_keys_pending: false,
            negotiated_version: None,
            tls13_key_schedule: None,
            #[cfg(feature = "dtls")]
            handshake_sequence_number: 0,
        }
    }

    #[expect(dead_code)]
    pub(crate) fn write_plaintext(
        &mut self,
        payload: OutboundPlain<'_>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if payload.is_empty() {
            return Ok(self.sendable_tls.take());
        }

        let fragments = self
            .message_fragmenter
            .fragment_payload(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                #[cfg(feature = "dtls")]
                None,
                payload.clone(),
            );

        for f in 0..fragments.len() {
            match self
                .encrypt_state
                .pre_encrypt_action(f as u64)
            {
                PreEncryptAction::Nothing => {}
                PreEncryptAction::RefreshOrClose => match self.negotiated_version {
                    Some(ProtocolVersion::TLSv1_3) => {
                        // driven by caller, as we don't have the `State` here
                        self.refresh_traffic_keys_pending = true;
                    }
                    _ => {
                        error!(
                            "traffic keys exhausted, closing connection to prevent security failure"
                        );
                        self.send_close_notify();
                        return Err(Error::EncryptError);
                    }
                },
                PreEncryptAction::Refuse => {
                    return Err(Error::EncryptError);
                }
            }
        }

        self.perhaps_write_key_update();

        let fragments = self
            .message_fragmenter
            .fragment_payload(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                #[cfg(feature = "dtls")]
                None,
                payload,
            );

        Ok(self.write_fragments(fragments))
    }

    pub(crate) fn send_early_plaintext(&mut self, data: &[u8]) -> usize {
        debug_assert!(self.encrypt_state.is_encrypting());

        // Limit on `sendable_tls` should apply to encrypted data but is enforced
        // for plaintext data instead which does not include cipher+record overhead.
        let len = self
            .sendable_tls
            .apply_limit(data.len());
        if len == 0 {
            // Don't send empty fragments.
            return 0;
        }

        self.send_appdata_encrypt(data[..len].into())
    }

    /// Like send_msg_encrypt, but operate on an appdata directly.
    fn send_appdata_encrypt(&mut self, payload: OutboundPlain<'_>) -> usize {
        let len = payload.len();
        let typ = ContentType::ApplicationData;

        match self.protocol {
            // For DTLS, we don't fragment application data, instead expecting clients to chunk up
            // application layer messages appropriately themselves.
            #[cfg(feature = "dtls")]
            Protocol::Udp => self.send_single_fragment(EncodedMessage {
                typ,
                version: ProtocolVersion::DTLSv1_2,
                epoch_and_sequence: self.dtls_epoch_and_sequence(),
                payload,
            }),
            Protocol::Tcp | Protocol::Quic(_) => {
                let iter = self
                    .message_fragmenter
                    .fragment_payload(typ, ProtocolVersion::TLSv1_2, None, payload);
                for m in iter {
                    self.send_single_fragment(m);
                }
            }
        }

        len
    }

    fn send_single_fragment(&mut self, m: EncodedMessage<OutboundPlain<'_>>) {
        if m.typ == ContentType::Alert {
            // Alerts are always sendable -- never quashed by a PreEncryptAction.
            let em = self.encrypt_state.encrypt_outgoing(m);
            self.queue_tls_message(em);
            return;
        }

        match self
            .encrypt_state
            .next_pre_encrypt_action()
        {
            PreEncryptAction::Nothing => {}

            // Close connection once we start to run out of
            // sequence space.
            PreEncryptAction::RefreshOrClose => {
                match self.negotiated_version {
                    Some(ProtocolVersion::TLSv1_3) => {
                        // driven by caller, as we don't have the `State` here
                        self.refresh_traffic_keys_pending = true;
                    }
                    _ => {
                        error!(
                            "traffic keys exhausted, closing connection to prevent security failure"
                        );
                        self.send_close_notify();
                        return;
                    }
                }
            }

            // Refuse to wrap counter at all costs.  This
            // is basically untestable unfortunately.
            PreEncryptAction::Refuse => {
                return;
            }
        };

        let em = self.encrypt_state.encrypt_outgoing(m);
        self.queue_tls_message(em);
    }

    /// Send plaintext application data, fragmenting and
    /// encrypting it as it goes out.
    ///
    /// If internal buffers are too small, this function will not accept
    /// all the data.
    pub(crate) fn buffer_plaintext(
        &mut self,
        payload: OutboundPlain<'_>,
        sendable_plaintext: &mut ChunkVecBuffer,
    ) -> usize {
        self.perhaps_write_key_update();
        if !self.may_send_application_data {
            // If we haven't completed handshaking, buffer
            // plaintext to send once we do.
            return sendable_plaintext.append_limited_copy(payload);
        }

        // Limit on `sendable_tls` should apply to encrypted data but is enforced
        // for plaintext data instead which does not include cipher+record overhead.
        let len = self
            .sendable_tls
            .apply_limit(payload.len());
        if len == 0 {
            // Don't send empty fragments.
            return 0;
        }

        debug_assert!(self.encrypt_state.is_encrypting());
        self.send_appdata_encrypt(payload.split_at(len).0)
    }

    pub(crate) fn send_buffered_plaintext(&mut self, plaintext: &mut ChunkVecBuffer) {
        while let Some(buf) = plaintext.pop() {
            self.send_appdata_encrypt(buf.as_slice().into());
        }
    }

    pub(crate) fn start_outgoing_traffic(&mut self) {
        self.may_send_application_data = true;
        debug_assert!(self.encrypt_state.is_encrypting());
    }

    // Put m into sendable_tls for writing.
    fn queue_tls_message(&mut self, m: EncodedMessage<OutboundOpaque>) {
        self.perhaps_write_key_update();
        self.sendable_tls.append(m.encode());
    }

    fn perhaps_write_key_update(&mut self) {
        if let Some(message) = self.queued_key_update_message.take() {
            self.sendable_tls.append(message);
        }
    }

    pub(crate) fn send_close_notify(&mut self) {
        if self.has_sent_close_notify {
            return;
        }
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.has_sent_close_notify = true;
        self.send_alert(AlertLevel::Warning, AlertDescription::CloseNotify);
    }

    pub(crate) fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription) {
        match level {
            AlertLevel::Fatal if self.has_sent_fatal_alert => return,
            AlertLevel::Fatal => self.has_sent_fatal_alert = true,
            _ => {}
        };
        self.send_msg(
            Message::build_alert(level, desc),
            self.encrypt_state.is_encrypting(),
        );
    }

    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool) {
        match (self.protocol, &m.payload) {
            // DTLS handshake messages can be fragmented into multiple records which contain
            // information necessary for reassembly.
            #[cfg(feature = "dtls")]
            (Protocol::Udp, MessagePayload::Handshake { parsed, encoded }) => {
                for m in self
                    .message_fragmenter
                    .fragment_dtls_handshake_message(
                        self.dtls_epoch_and_sequence()
                            .expect("epoch and sequence should be set for DTLS"),
                        parsed.0.handshake_type(),
                        self.handshake_sequence_number,
                        encoded.bytes(),
                    )
                {
                    self.send_fragment(
                        EncodedMessage {
                            typ: m.typ,
                            version: m.version,
                            epoch_and_sequence: m.epoch_and_sequence,
                            payload: m
                                .payload
                                .get_encoding()
                                .as_slice()
                                .into(),
                        },
                        must_encrypt,
                    );
                }
            }
            // Other DTLS messages are required to fit into a single record. Application data should
            // be chunked by the application before being handled off to rustls.
            #[cfg(feature = "dtls")]
            (Protocol::Udp, _) => self.send_fragment(
                m.encoded_message(self.dtls_epoch_and_sequence())
                    .borrow_outbound(),
                must_encrypt,
            ),
            // TLS messages can be fragmented into multiple TCP or QUIC packets
            _ => {
                let msg = m.encoded_message(
                    #[cfg(feature = "dtls")]
                    None,
                );
                for m in self
                    .message_fragmenter
                    .fragment_message(&msg)
                {
                    self.send_fragment(m, must_encrypt);
                }
            }
        }
    }

    fn send_fragment<'a>(
        &mut self,
        fragment: EncodedMessage<OutboundPlain<'a>>,
        must_encrypt: bool,
    ) {
        if must_encrypt {
            self.send_single_fragment(fragment);
        } else {
            self.queue_tls_message(fragment.to_unencrypted_opaque());
        }
    }

    fn write_fragments<'a>(
        &mut self,
        fragments: impl Iterator<Item = EncodedMessage<OutboundPlain<'a>>>,
    ) -> Vec<Vec<u8>> {
        for m in fragments {
            let em = self
                .encrypt_state
                .encrypt_outgoing(m)
                .encode();

            self.sendable_tls.append(em);
        }

        self.sendable_tls.take()
    }

    pub(crate) fn set_max_fragment_size(&mut self, new: Option<usize>) -> Result<(), Error> {
        self.message_fragmenter
            .set_max_fragment_size(new)
    }

    pub(crate) fn ensure_key_update_queued(&mut self) {
        if self.queued_key_update_message.is_some() {
            return;
        }

        let message = Message::build_key_update_notify().encoded_message(
            #[cfg(feature = "dtls")]
            self.dtls_epoch_and_sequence(),
        );
        self.queued_key_update_message = Some(
            self.encrypt_state
                .encrypt_outgoing(message.borrow_outbound())
                .encode(),
        );

        if let Some(mut ks) = self.tls13_key_schedule.take() {
            ks.update_encrypter_for_key_update(self);
            self.tls13_key_schedule = Some(ks);
        }
    }

    #[cfg(feature = "dtls")]
    fn dtls_epoch_and_sequence(&self) -> Option<EpochAndSequence> {
        match self.protocol {
            Protocol::Udp => Some(EpochAndSequence::from_sequence_number(
                self.encrypt_state.write_seq(),
            )),
            _ => None,
        }
    }

    /// Trigger a `refresh_traffic_keys` if required.
    pub(crate) fn maybe_refresh_traffic_keys(&mut self) {
        if self.refresh_traffic_keys_pending {
            let _ = self.refresh_traffic_keys();
        }
    }

    pub(crate) fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        let ks = self.tls13_key_schedule.take();

        let Some(mut ks) = ks else {
            return Err(Error::HandshakeNotComplete);
        };

        ks.request_key_update_and_update_encrypter(self);
        self.refresh_traffic_keys_pending = false;
        self.tls13_key_schedule = Some(ks);
        Ok(())
    }
}

impl SendOutput for SendPath {
    fn negotiated_version(&mut self, version: ProtocolVersion) {
        self.negotiated_version = Some(version);
    }

    fn ensure_key_update_queued(&mut self) {
        self.ensure_key_update_queued();
    }

    fn set_encrypter(&mut self, encrypter: Box<dyn MessageEncrypter>, max_messages: u64) {
        self.encrypt_state
            .set_message_encrypter(encrypter, max_messages);
    }

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>) {
        self.tls13_key_schedule = Some(schedule);
    }

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription) {
        self.send_alert(level, desc);
    }

    fn start_traffic(&mut self) {
        self.may_send_half_rtt_data = true;
        self.start_outgoing_traffic();
    }

    /// Send a raw TLS message, fragmenting it if needed.
    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool) {
        self.send_msg(m, must_encrypt);
    }
}

pub(crate) trait SendOutput {
    fn negotiated_version(&mut self, version: ProtocolVersion);

    fn ensure_key_update_queued(&mut self);

    fn set_encrypter(&mut self, cipher: Box<dyn MessageEncrypter>, max_messages: u64);

    fn update_key_schedule(&mut self, schedule: Box<KeyScheduleTrafficSend>);

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription);

    fn start_traffic(&mut self);

    fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool);
}

pub(super) const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;
