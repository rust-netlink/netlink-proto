// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, EncodeError, NetlinkDeserializable, NetlinkHeader,
    NetlinkMessagePayload,
};

const RTM_GETLINK: u16 = 18;
const IFINFOMSG_LEN: usize = 16;

/// Minimal raw ROUTE message used by the examples so that they do not depend
/// on `netlink-packet-route`.
#[derive(Debug)]
pub struct RawRouteMessage {
    message_type: u16,
    payload: Vec<u8>,
}

impl RawRouteMessage {
    /// A `RTM_GETLINK` request with an empty `ifinfomsg`.
    pub fn get_link() -> Self {
        Self {
            message_type: RTM_GETLINK,
            payload: vec![0; IFINFOMSG_LEN],
        }
    }
}

impl Emitable for RawRouteMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

impl NetlinkMessagePayload for RawRouteMessage {
    fn message_type(&self) -> u16 {
        self.message_type
    }
}

impl NetlinkDeserializable for RawRouteMessage {
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            message_type: header.message_type,
            payload: payload.to_vec(),
        })
    }
}
