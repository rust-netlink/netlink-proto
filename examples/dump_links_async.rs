// SPDX-License-Identifier: MIT

use futures_util::StreamExt;
use libc::NETLINK_ROUTE as NETLINK_ROUTE_RAW;
use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_proto::{new_connection, sys::SocketAddr};

mod common;

const NETLINK_ROUTE: isize = NETLINK_ROUTE_RAW as isize;

use common::RawRouteMessage;

#[tokio::main]
async fn main() -> Result<(), String> {
    // Create the netlink socket. Here, we won't use the channel that
    // receives unsolicited messages.
    let (conn, handle, _) = new_connection(NETLINK_ROUTE).map_err(|e| {
        format!("Failed to create a new netlink connection: {}", e)
    })?;

    // Spawn the `Connection` so that it starts polling the netlink
    // socket in the background.
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
        .map_err(|e| format!("Failed to send request: {}", e))?;

    // Print all the messages received in response. The stream yields `Err`
    // if the connection dies before the dump completes.
    while let Some(packet) = response.next().await {
        match packet {
            Ok(packet) => println!("<<< {:?}", packet),
            Err(e) => eprintln!("connection error: {e}"),
        }
    }

    Ok(())
}
