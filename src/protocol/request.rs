// SPDX-License-Identifier: MIT

use netlink_packet_core::NetlinkMessage;

use crate::sys::SocketAddr;

/// Describe whether a response from the destination is expected for each
/// message of a [`Request`].
#[derive(Debug)]
pub(crate) enum ExpectResponse {
    /// A response is expected when the message has at least one of the
    /// `NLM_F_REQUEST`, `NLM_F_ACK` or `NLM_F_ECHO` flags set.
    FromFlags,
    /// Explicitly describe, for each message of the request, whether a
    /// response is expected. This slice must have exactly one entry per
    /// message of the request.
    Explicit(Box<[bool]>),
}

#[derive(Debug)]
pub(crate) struct Request<T, M> {
    pub metadata: M,
    pub messages: Box<[NetlinkMessage<T>]>,
    pub destination: SocketAddr,
    pub expect_response: ExpectResponse,
}
