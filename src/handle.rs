// SPDX-License-Identifier: MIT

use futures_channel::mpsc::{unbounded, UnboundedSender};
use futures_util::Stream;
use netlink_packet_core::NetlinkMessage;
use std::fmt::Debug;

use crate::{
    errors::NetlinkProtoError, sys::SocketAddr, ExpectResponse, Request,
};

/// Describe whether the response of a message sent through
/// [`ConnectionHandle::request_batch_with_expectation`] should be delivered
/// through the returned stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyExpectation {
    /// Wait for the response of the message.
    Expected,
    /// Do not wait for a response. Any reply from the destination, including
    /// error messages, is forwarded to the unsolicited messages stream
    /// instead of the stream returned by the request.
    NotExpected,
}

/// A handle to pass requests to a [`Connection`](struct.Connection.html).
#[derive(Clone, Debug)]
pub struct ConnectionHandle<T>
where
    T: Debug,
{
    requests_tx: UnboundedSender<Request<T>>,
}

impl<T> ConnectionHandle<T>
where
    T: Debug,
{
    pub(crate) fn new(requests_tx: UnboundedSender<Request<T>>) -> Self {
        ConnectionHandle { requests_tx }
    }

    /// Send a new request and get the response as a stream of messages. Note
    /// that some messages are not part of the response stream:
    ///
    /// - **acknowledgments**: when an acknowledgment is received, the stream is
    ///   closed
    /// - **end of dump messages**: similarly, upon receiving an "end of dump"
    ///   message, the stream is closed
    ///
    /// A response is expected for the request when the `NLM_F_REQUEST`,
    /// `NLM_F_ACK` or `NLM_F_ECHO` flag is set, like other netlink users such
    /// as `iproute2`. If the destination never sends a reply, the returned
    /// stream never closes. Use
    /// [`ConnectionHandle::request_batch_with_expectation`] to explicitly
    /// describe whether a response is expected for each message.
    pub fn request(
        &self,
        message: NetlinkMessage<T>,
        destination: SocketAddr,
    ) -> Result<impl Stream<Item = NetlinkMessage<T>>, NetlinkProtoError> {
        self.request_batch([message], destination)
    }

    /// Send a multiple messages as a _single_ request and get the response as
    /// a stream of messages.
    ///
    /// A response is expected for every message having the `NLM_F_REQUEST`,
    /// `NLM_F_ACK` or `NLM_F_ECHO` flag set, and the stream is only closed
    /// when every such message received a response. Some requests are however
    /// never answered by the kernel even though `NLM_F_REQUEST` is set (for
    /// instance the NfNetlink `BATCH_BEGIN` and `BATCH_END` messages on
    /// kernels older than 6.10): use
    /// [`ConnectionHandle::request_batch_with_expectation`] for these.
    ///
    /// This method can be used to send NfNetlink messages in batches.
    pub fn request_batch(
        &self,
        messages: impl IntoIterator<Item = NetlinkMessage<T>>,
        destination: SocketAddr,
    ) -> Result<impl Stream<Item = NetlinkMessage<T>>, NetlinkProtoError> {
        let (tx, rx) = unbounded::<NetlinkMessage<T>>();
        let request = Request {
            metadata: tx,
            messages: messages.into_iter().collect(),
            destination,
            expect_response: ExpectResponse::FromFlags,
        };
        Self::send_request(&self.requests_tx, request)?;
        Ok(rx)
    }

    /// Send multiple messages as a _single_ request and get the response as a
    /// stream of messages, explicitly describing whether a response is
    /// expected for each message instead of deriving it from the message
    /// flags.
    ///
    /// The returned stream is closed once every message marked as
    /// [`ReplyExpectation::Expected`] has been fully processed.
    ///
    /// Messages marked as [`ReplyExpectation::NotExpected`] are not tracked
    /// as pending requests: any reply from the destination for these messages,
    /// including error messages, is forwarded to the unsolicited messages
    /// stream instead.
    ///
    /// This is useful to send requests that may never be answered by the
    /// destination, such as the NfNetlink `BATCH_BEGIN` and `BATCH_END`
    /// messages on kernels older than 6.10, while still expecting responses
    /// for the other messages of the batch.
    pub fn request_batch_with_expectation(
        &self,
        messages: impl IntoIterator<Item = (NetlinkMessage<T>, ReplyExpectation)>,
        destination: SocketAddr,
    ) -> Result<impl Stream<Item = NetlinkMessage<T>>, NetlinkProtoError> {
        let (tx, rx) = unbounded::<NetlinkMessage<T>>();
        let mut netlink_messages = Vec::new();
        let mut expect_response = Vec::new();
        for (message, expectation) in messages {
            netlink_messages.push(message);
            expect_response
                .push(matches!(expectation, ReplyExpectation::Expected));
        }
        let request = Request {
            metadata: tx,
            messages: netlink_messages.into_boxed_slice(),
            destination,
            expect_response: ExpectResponse::Explicit(
                expect_response.into_boxed_slice(),
            ),
        };
        Self::send_request(&self.requests_tx, request)?;
        Ok(rx)
    }

    /// Send a message without expecting any response from the destination.
    ///
    /// Unlike [`ConnectionHandle::request`], the message is not tracked as a
    /// pending request. This is safe to use for messages that are not
    /// guaranteed to be answered even though `NLM_F_REQUEST` is set, for
    /// instance when `NLM_F_ACK` is not set. Any reply from the destination,
    /// including error messages, is forwarded to the unsolicited messages
    /// stream.
    pub fn notify(
        &self,
        message: NetlinkMessage<T>,
        destination: SocketAddr,
    ) -> Result<(), NetlinkProtoError> {
        let (tx, _rx) = unbounded::<NetlinkMessage<T>>();
        let request = Request {
            metadata: tx,
            messages: Box::new([message]),
            destination,
            expect_response: ExpectResponse::Explicit(Box::new([false])),
        };
        Self::send_request(&self.requests_tx, request)
    }

    fn send_request(
        requests_tx: &UnboundedSender<Request<T>>,
        request: Request<T>,
    ) -> Result<(), NetlinkProtoError> {
        trace!("handle: forwarding new request to connection");
        // The channel is unbounded, so the only reason for sending to fail
        // is that the `Connection` was shut down and the receiver was
        // dropped.
        UnboundedSender::unbounded_send(requests_tx, request)
            .map_err(|_| NetlinkProtoError::ConnectionClosed)
    }
}
