// SPDX-License-Identifier: MIT

use std::sync::Arc;

use crate::sys::SocketAddr;

/// A message that has already been encoded, together with the metadata needed
/// to match its response once it has been sent.
#[derive(Debug)]
pub(crate) struct OutgoingMessage {
    /// The encoded netlink message.
    pub buffer: Vec<u8>,
    /// The sequence number assigned to this message.
    pub sequence_number: u32,
    /// Whether an acknowledgment was requested for this message.
    pub expecting_ack: bool,
    /// Whether a response is expected for this message.
    pub expects_response: bool,
}

#[derive(Debug)]
pub(crate) struct Request<M> {
    pub metadata: M,
    pub messages: Box<[OutgoingMessage]>,
    pub destination: SocketAddr,
    /// Identifies this request so that a terminal error is delivered once per
    /// request, even when it contains several messages.
    pub token: Arc<()>,
}
