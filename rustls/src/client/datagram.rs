use core::ops::Deref;

use alloc::vec::Vec;

use pki_types::ServerName;

use crate::client::connection::ClientConnectionData;
use crate::client::{ClientSide, hs::ClientHelloInput};
use crate::common_state::Side;
use crate::conn::SideCommonOutput;
use crate::crypto::cipher::{InboundOpaque, OutboundPlain};
use crate::datagram::{DatagramHandler, Socket, SocketCommon};
use crate::msgs::ClientExtensionsInput;
use crate::sync::Arc;
use crate::{ClientConfig, CommonState, ConnectionOutputs, Error, Protocol, TlsInputBuffer};

pub struct ClientSocket {
    inner: SocketCommon<ClientSide>,
}

impl ClientSocket {
    pub fn connect(
        server_name: ServerName<'static>,
        config: ClientConfig,
        datagrams_to_send: &mut Vec<Vec<u8>>,
    ) -> Result<Self, Error> {
        let mut common_state = CommonState::new(Side::Client, config.fips(), Protocol::Udp);
        common_state
            .send
            .set_max_fragment_size(config.max_fragment_size)?;
        let mut side_data = ClientConnectionData::default();

        let mut output = SideCommonOutput {
            side: &mut side_data,
            quic: None,
            common: &mut common_state,
            tls: datagrams_to_send,
        };

        let extra_exts = ClientExtensionsInput::from_alpn(config.alpn_protocols.clone());
        let input = ClientHelloInput::new(
            server_name,
            &extra_exts,
            Protocol::Udp,
            &mut output,
            Arc::new(config),
        )?;
        let state = input.start_handshake(extra_exts, &mut output)?;

        Ok(Self {
            inner: SocketCommon {
                state: Ok(state),
                side: side_data,
                common: common_state,
            },
        })
    }
}

impl Socket for ClientSocket {
    type Side = ClientSide;

    fn write(
        &mut self,
        plaintext: OutboundPlain<'_>,
        datagrams_to_send: &mut Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        self.inner
            .write(plaintext, datagrams_to_send)
    }

    fn read_tls<'a, 'm>(
        &'a mut self,
        input: &'m mut dyn TlsInputBuffer,
        datagrams_to_send: &'a mut Vec<Vec<u8>>,
    ) -> DatagramHandler<'a, 'm, Self::Side> {
        self.inner
            .read_tls(input, datagrams_to_send)
    }

    fn refresh_traffic_keys(&mut self, datagrams_to_send: &mut Vec<Vec<u8>>) -> Result<(), Error> {
        self.inner
            .refresh_traffic_keys(datagrams_to_send)
    }

    fn records_acked_by_peer(&self) -> &[crate::AckRecordSequenceNumber] {
        self.inner.common.recv.acked_by_peer()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }
}

impl Deref for ClientSocket {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
