use core::ops::Deref;

use crate::common_state::Side;
use crate::conn::private::SideOutput;
use crate::conn::{MessageIter, SendPath};
use crate::crypto::cipher::{InboundOpaque, OutboundPlain};
use crate::datagram::{DatagramHandler, Socket, SocketCommon};
use crate::error::{ApiMisuse, Error};
use crate::msgs::{DtlsDeframerCore, ServerExtensionsInput};
use crate::server::ServerSide;
use crate::server::connection::ServerConnectionData;
use crate::server::hs::ExpectClientHello;
use crate::sync::Arc;
use crate::{
    ClientConfig, CommonState, ConnectionOutputs, IoState, Protocol, ServerConfig, SideData,
    TlsInputBuffer,
};

use alloc::boxed::Box;
use alloc::vec::Vec;

pub struct ServerSocket {
    inner: SocketCommon<ServerSide>,
}

impl ServerSocket {
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        let mut common = CommonState::new(Side::Server, config.fips(), Protocol::Udp);
        common
            .send
            .set_max_fragment_size(config.max_fragment_size)?;

        Ok(Self {
            inner: SocketCommon {
                state: Ok(Box::new(ExpectClientHello::new(
                    config,
                    ServerExtensionsInput::default(),
                    Vec::new(),
                    Protocol::Udp,
                ))
                .into()),
                side: ServerConnectionData::default(),
                common,
            },
        })
    }
}

impl Socket for ServerSocket {
    type Side = ServerSide;

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

impl Deref for ServerSocket {
    type Target = ConnectionOutputs;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
