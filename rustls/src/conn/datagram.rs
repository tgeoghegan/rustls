use core::ops::Deref;

use crate::client::ClientSide;
use crate::common_state::Output;
use crate::conn::private::SideOutput;
use crate::conn::{MessageIter, SendPath};
use crate::crypto::cipher::{InboundOpaque, OutboundPlain, Payload};
use crate::error::{ApiMisuse, Error};
use crate::msgs::{Delocator, DtlsDeframerCore};
use crate::server::ServerSide;
use crate::{
    AckRecordSequenceNumber, ClientConfig, CommonState, IoState, Protocol, SideData,
    TlsInputBuffer, TlsOutput,
};

use alloc::vec::Vec;

pub trait Socket {
    type Side: SideData;

    fn write(
        &mut self,
        plaintext: OutboundPlain<'_>,
        datagrams_to_send: &mut Vec<Vec<u8>>,
    ) -> Result<(), Error>;

    fn read_tls<'a, 'm>(
        &'a mut self,
        input: &'m mut dyn TlsInputBuffer,
        datagrams_to_send: &'a mut Vec<Vec<u8>>,
    ) -> DatagramHandler<'a, 'm, Self::Side>;

    fn refresh_traffic_keys(&mut self, datagrams_to_send: &mut Vec<Vec<u8>>) -> Result<(), Error>;

    fn records_acked_by_peer(&self) -> &[AckRecordSequenceNumber];

    fn is_handshaking(&self) -> bool;
}

pub struct DatagramHandler<'a, 'm, Side: SideData> {
    iter: MessageIter<'a, 'm, Side, SendPath, DtlsDeframerCore>,
    done: bool,
}

impl<'a, 'm, Side: SideData> DatagramHandler<'a, 'm, Side> {
    pub fn handle_all(mut self, received_plaintext: &mut Vec<Vec<u8>>) -> Result<(), Error> {
        while let Some(result) = self.next_datagram() {
            // TODO: this forces a heap allocation + copy of the payload. Do better!
            received_plaintext.push(result?.into_vec());
        }

        Ok(())
    }

    pub fn next_datagram(&mut self) -> Option<Result<Payload<'_>, Error>> {
        if self.done {
            return None;
        }

        let Some(result) = self.iter.next() else {
            self.done = true;
            return None;
        };

        let payload = match result {
            Ok(payload) => payload,
            Err(err) => {
                self.done = true;
                return Some(Err(err));
            }
        };

        Some(Ok(
            payload.reborrow(&Delocator::new(self.iter.input.slice_mut()))
        ))
    }
}

pub(crate) struct SocketCommon<Side: SideData> {
    pub(crate) state: Result<Side::State, Error>,
    pub(crate) side: Side::Data,
    pub(crate) common: CommonState<DtlsDeframerCore>,
}

impl<Side: SideData> SocketCommon<Side> {
    pub(crate) fn read_tls<'a, 'm>(
        &'a mut self,
        input: &'m mut dyn TlsInputBuffer,
        datagrams_to_send: &'a mut Vec<Vec<u8>>,
    ) -> DatagramHandler<'a, 'm, Side> {
        DatagramHandler {
            iter: MessageIter::new_datagram(input, datagrams_to_send, self, false),
            done: false,
        }
    }

    pub(crate) fn write(
        &mut self,
        plaintext: OutboundPlain<'_>,
        datagrams_to_send: &mut Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        if plaintext.is_empty() {
            return Ok(());
        } else if !self
            .common
            .send
            .may_send_application_data
        {
            return Err(ApiMisuse::WriteTlsBeforeHandshakeComplete.into());
        } else if self.common.send.has_sent_close_notify {
            return Err(ApiMisuse::WriteTlsAfterSendPathClosed.into());
        }

        self.common
            .send
            .send_appdata_encrypt(plaintext, datagrams_to_send);

        Ok(())
    }

    pub(crate) fn refresh_traffic_keys(
        &mut self,
        datagrams_to_send: &mut Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        self.common
            .send
            .refresh_traffic_keys(datagrams_to_send)
    }
}

impl<Side: SideData> Deref for SocketCommon<Side> {
    type Target = CommonState<DtlsDeframerCore>;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}
