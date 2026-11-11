// SPDX-License-Identifier: MIT

use std::{
    fmt::Debug,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use futures_channel::mpsc::{UnboundedSender, unbounded};
use futures_util::Stream;
use netlink_packet_core::{
    EncodeError, NLM_F_ACK, NLM_F_ECHO, NLM_F_REQUEST, NetlinkMessage,
    NetlinkMessagePayload,
};

use crate::{
    NetlinkMessageCodec, Request, ResponseStream,
    errors::NetlinkProtoError,
    protocol::OutgoingMessage,
    shutdown::{Closed, Shared},
    sys::SocketAddr,
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

/// A handle used to send requests over a fallible netlink connection.
#[derive(Clone, Debug)]
pub struct ConnectionHandle<T>
where
    T: Debug + NetlinkMessagePayload,
{
    requests_tx: UnboundedSender<Request<T>>,
    shared: Arc<Shared>,
    sequence: Arc<AtomicU32>,
    encode: fn(NetlinkMessage<T>, &mut Vec<u8>) -> Result<(), EncodeError>,
}

fn encode_with<T, C>(
    message: NetlinkMessage<T>,
    buffer: &mut Vec<u8>,
) -> Result<(), EncodeError>
where
    T: Debug + NetlinkMessagePayload,
    C: NetlinkMessageCodec,
{
    C::encode(message, buffer)
}

impl<T> ConnectionHandle<T>
where
    T: Debug + NetlinkMessagePayload,
{
    pub(crate) fn new<C>(
        requests_tx: UnboundedSender<Request<T>>,
        shared: Arc<Shared>,
        sequence: Arc<AtomicU32>,
    ) -> Self
    where
        C: NetlinkMessageCodec,
    {
        ConnectionHandle {
            requests_tx,
            shared,
            sequence,
            encode: encode_with::<T, C>,
        }
    }

    /// A future that completes once the connection has terminated.
    ///
    /// It resolves to the error that caused the connection to stop, or `None`
    /// if the connection shut down cleanly (or was dropped without
    /// completing).
    pub fn closed(
        &self,
    ) -> impl Future<Output = Option<Arc<NetlinkProtoError>>> + use<T> {
        Closed::new(self.shared.clone())
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
    ///
    /// Each stream item is a `Result`: response messages are `Ok`, and if the
    /// connection dies before the response is complete, the terminal error is
    /// delivered as the final `Err` item.
    pub fn request(
        &self,
        message: NetlinkMessage<T>,
        destination: SocketAddr,
    ) -> Result<
        impl Stream<Item = Result<NetlinkMessage<T>, NetlinkProtoError>> + use<T>,
        NetlinkProtoError,
    > {
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
    pub fn request_batch<I>(
        &self,
        messages: I,
        destination: SocketAddr,
    ) -> Result<
        impl Stream<Item = Result<NetlinkMessage<T>, NetlinkProtoError>> + use<T, I>,
        NetlinkProtoError,
    >
    where
        I: IntoIterator<Item = NetlinkMessage<T>>,
    {
        let messages = messages.into_iter().map(|message| {
            let expects_response = message.header.flags
                & (NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO)
                != 0;
            (message, expects_response)
        });
        let (request, response) = self.encode_request(messages, destination)?;
        self.send_request(request)?;
        Ok(response)
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
    pub fn request_batch_with_expectation<I>(
        &self,
        messages: I,
        destination: SocketAddr,
    ) -> Result<
        impl Stream<Item = Result<NetlinkMessage<T>, NetlinkProtoError>> + use<T, I>,
        NetlinkProtoError,
    >
    where
        I: IntoIterator<Item = (NetlinkMessage<T>, ReplyExpectation)>,
    {
        let messages = messages.into_iter().map(|(message, expectation)| {
            (message, matches!(expectation, ReplyExpectation::Expected))
        });
        let (request, response) = self.encode_request(messages, destination)?;
        self.send_request(request)?;
        Ok(response)
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
        let (request, _response) =
            self.encode_request([(message, false)], destination)?;
        self.send_request(request)
    }

    /// Assign a sequence number to every message, encode them, and build the
    /// request that will be handed to the connection.
    ///
    /// Encoding happens here so that an invalid message is reported to the
    /// caller instead of tearing down the connection.
    fn encode_request<I>(
        &self,
        messages: I,
        destination: SocketAddr,
    ) -> Result<(Request<T>, ResponseStream<T>), NetlinkProtoError>
    where
        I: IntoIterator<Item = (NetlinkMessage<T>, bool)>,
    {
        if let Some(error) = self.shared.terminal_error() {
            return Err(error);
        }
        let (metadata, response) =
            unbounded::<Result<NetlinkMessage<T>, NetlinkProtoError>>();
        let mut outgoing = Vec::new();
        for (mut message, expects_response) in messages {
            let sequence_number = self.sequence.fetch_add(1, Ordering::Relaxed);
            message.header.sequence_number = sequence_number;
            let expecting_ack = message.header.flags & NLM_F_ACK == NLM_F_ACK;
            let mut buffer = Vec::new();
            (self.encode)(message, &mut buffer)?;
            outgoing.push(OutgoingMessage {
                buffer,
                sequence_number,
                expecting_ack,
                expects_response,
            });
        }
        let request = Request {
            metadata,
            messages: outgoing.into_boxed_slice(),
            destination,
            token: Arc::new(()),
        };
        Ok((request, response))
    }

    fn send_request(
        &self,
        request: Request<T>,
    ) -> Result<(), NetlinkProtoError> {
        trace!("handle: forwarding new request to connection");
        // If the connection already recorded why it stopped, report that
        // cause instead of a generic `ConnectionClosed`.
        if let Some(error) = self.shared.terminal_error() {
            return Err(error);
        }
        // The channel is unbounded, so the only reason for sending to fail
        // is that the `Connection` was shut down and the receiver was
        // dropped.
        UnboundedSender::unbounded_send(&self.requests_tx, request).map_err(
            |_| {
                self.shared
                    .terminal_error()
                    .unwrap_or(NetlinkProtoError::ConnectionClosed)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt::Debug, io, sync::Arc};

    use futures_channel::mpsc::unbounded;
    use netlink_packet_core::{
        DecodeError, Emitable, EncodeError, NLM_F_ACK, NLM_F_REQUEST,
        NetlinkDeserializable, NetlinkHeader, NetlinkMessage,
        NetlinkMessagePayload, NetlinkPayload,
    };

    use super::ConnectionHandle;
    use crate::{
        NetlinkMessageCodec, Request, new_sequence, shutdown::Shared,
        sys::SocketAddr,
    };

    #[derive(Debug)]
    struct Fake;

    impl Emitable for Fake {
        fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
            out.extend_from_slice(b"abc");
            Ok(())
        }
    }

    impl NetlinkMessagePayload for Fake {
        fn message_type(&self) -> u16 {
            1
        }
    }

    impl NetlinkDeserializable for Fake {
        fn deserialize(
            _header: &NetlinkHeader,
            _payload: &[u8],
        ) -> Result<Self, DecodeError> {
            Ok(Fake)
        }
    }

    struct NoopCodec;

    impl NetlinkMessageCodec for NoopCodec {
        fn decode<T>(
            _src: &mut [u8],
        ) -> io::Result<Option<(NetlinkMessage<T>, usize)>>
        where
            T: NetlinkDeserializable + Debug,
        {
            Ok(None)
        }

        fn encode<T>(
            _message: NetlinkMessage<T>,
            _buffer: &mut Vec<u8>,
        ) -> Result<(), EncodeError>
        where
            T: NetlinkMessagePayload + Debug,
        {
            Ok(())
        }
    }

    #[test]
    fn first_request_uses_non_zero_sequence_number() {
        let (tx, mut rx) = unbounded::<Request<Fake>>();
        let handle = ConnectionHandle::<Fake>::new::<NoopCodec>(
            tx,
            Arc::new(Shared::new()),
            new_sequence(),
        );

        let mut message = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(Fake),
        );
        message.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let _ = handle.request(message, SocketAddr::new(0, 0)).unwrap();
        let request = rx.try_recv().unwrap();
        assert_eq!(request.messages[0].sequence_number, 1);
    }

    #[test]
    fn closed_future_does_not_borrow_the_handle() {
        let (tx, _rx) = unbounded::<Request<Fake>>();
        let handle = ConnectionHandle::<Fake>::new::<NoopCodec>(
            tx,
            Arc::new(Shared::new()),
            new_sequence(),
        );

        let closed = handle.closed();
        drop(handle);
        drop(closed);
    }
}
