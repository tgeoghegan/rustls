use crate::conn::{MessageIter, SendPath};
use crate::crypto::cipher::{InboundOpaque, OutboundPlain, Payload};
use crate::error::{ApiMisuse, Error};
use crate::msgs::DtlsDeframerCore;
use crate::{IoState, SideData};

use alloc::vec::Vec;
use core::fmt::{self, Debug};

pub trait Socket: Debug {
    type Side: SideData;

    fn write_tls(
        &mut self,
        plaintext: OutboundPlain<'_>,
        datagrams_to_send: &mut Vec<Payload<'_>>,
    ) -> Result<(), Error>;

    fn process_new_packets(
        &mut self,
        input: &mut [InboundOpaque<'_>],
        datagrams_to_send: &mut Vec<Payload<'_>>,
    ) -> DatagramHandler<Self::Side>;

    fn refresh_traffic_keys(
        &mut self,
        datagrams_to_send: &mut Vec<Payload<'_>>,
    ) -> Result<(), Error>;
}

pub struct DatagramHandler<'a, 'm, Side: SideData> {
    iter: MessageIter<'a, 'm, Side, SendPath, DtlsDeframerCore>,
}

impl<'a, 'm, Side: SideData> DatagramHandler<'a, 'm, Side> {
    pub fn handle_all(
        mut self,
        received_plaintext: &mut Vec<Payload<'_>>,
    ) -> Result<IoState, Error> {
        todo!()
    }

    pub fn next_datagram(&mut self) -> Option<Result<Payload<'_>, Error>> {
        todo!()
    }
}
