// SPDX-License-Identifier: MIT

use futures_util::StreamExt;
use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_proto::{
    new_connection,
    sys::{SocketAddr, protocols::NETLINK_ROUTE},
};

mod common;

use common::RawRouteMessage;

#[tokio::main]
async fn main() -> Result<(), String> {
    // Create the netlink socket. Here, we won't use the channel that
    // receives unsolicited messages.
    let (conn, handle, _) = new_connection(NETLINK_ROUTE).map_err(|e| {
        format!("Failed to create a new netlink connection: {e}")
    })?;

    // Spawn the `Connection` in the background
    tokio::spawn(conn);

    // Create the netlink message that requests the links to be dumped
    let mut nl_hdr = NetlinkHeader::default();
    nl_hdr.flags = NLM_F_DUMP | NLM_F_REQUEST;
    let request = NetlinkMessage::new(
        nl_hdr,
        NetlinkPayload::InnerMessage(RawRouteMessage::get_link()),
    );

    // Send the request
    let mut response = handle
        .request(request, SocketAddr::new(0, 0))
        .map_err(|e| format!("Failed to send request: {e}"))?;

    // Print all the messages received in response
    while let Some(packet) = response.next().await {
        println!("<<< {packet:?}");
    }

    Ok(())
}
