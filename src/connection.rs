// SPDX-License-Identifier: MIT

use std::{
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures_util::{Future, Sink, Stream};
use log::warn;
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkMessagePayload,
    NetlinkPayload,
};

use crate::{
    NetlinkProtoError, Protocol, Request, Response,
    codecs::{NetlinkCodec, NetlinkMessageCodec},
    framed::NetlinkFramed,
    shutdown::Shared,
    sys::{AsyncSocket, SocketAddr},
};

#[cfg(feature = "tokio_socket")]
use netlink_sys::TokioSocket as DefaultSocket;
#[cfg(not(feature = "tokio_socket"))]
type DefaultSocket = ();

/// Fallible connection to a netlink socket, running in the background.
///
/// [`ConnectionHandle`](struct.ConnectionHandle.html) are used to pass new
/// requests to the `Connection`, that in turn, sends them through the netlink
/// socket.
///
/// Any socket read or write error is fatal: the connection stops, its
/// [`Future`](std::future::Future) resolves to `Err`, in-flight request streams
/// receive that error as their final item, and
/// [`ConnectionHandle::closed`](crate::ConnectionHandle::closed) resolves with
/// it. Once it has stopped, new requests made through the
/// [`ConnectionHandle`](crate::ConnectionHandle) fail with the same error when
/// it is known, or with [`NetlinkProtoError::ConnectionClosed`] otherwise.
///
/// Encode errors are not fatal: they are reported synchronously by the
/// [`ConnectionHandle`](crate::ConnectionHandle) method that submits the
/// request.
pub struct Connection<T, S = DefaultSocket, C = NetlinkCodec>
where
    T: Debug + NetlinkMessagePayload + NetlinkDeserializable,
{
    socket: NetlinkFramed<T, S, C>,
    protocol: Protocol<
        T,
        UnboundedSender<Result<NetlinkMessage<T>, NetlinkProtoError>>,
    >,
    /// Channel used by the user to pass requests to the connection.
    requests_rx: Option<UnboundedReceiver<Request<T>>>,
    /// Channel used to transmit to the ConnectionHandle the unsolicited
    /// messages received from the socket (multicast messages for instance).
    unsolicited_messages_tx:
        Option<UnboundedSender<(NetlinkMessage<T>, SocketAddr)>>,
    shared: Arc<Shared>,
    socket_closed: bool,
    forward_noop: bool,
    forward_done: bool,
    forward_ack: bool,
}

impl<T, S, C> Connection<T, S, C>
where
    T: Debug + NetlinkMessagePayload + NetlinkDeserializable + Unpin,
    S: AsyncSocket,
    C: NetlinkMessageCodec,
{
    pub(crate) fn new(
        requests_rx: UnboundedReceiver<Request<T>>,
        unsolicited_messages_tx: UnboundedSender<(
            NetlinkMessage<T>,
            SocketAddr,
        )>,
        shared: Arc<Shared>,
        protocol: isize,
    ) -> Result<Self, NetlinkProtoError> {
        let socket = S::new(protocol)?;
        Ok(Connection {
            socket: NetlinkFramed::new(socket),
            protocol: Protocol::new(),
            requests_rx: Some(requests_rx),
            unsolicited_messages_tx: Some(unsolicited_messages_tx),
            shared,
            socket_closed: false,
            forward_noop: false,
            forward_done: false,
            forward_ack: false,
        })
    }

    /// Whether [`NetlinkPayload::Noop`] should be forwarded to the handler.
    pub fn set_forward_noop(&mut self, value: bool) {
        self.forward_noop = value;
    }

    /// Whether [`NetlinkPayload::Done`] should be forwarded to the handler.
    pub fn set_forward_done(&mut self, value: bool) {
        self.forward_done = value;
    }

    /// Whether acknowledgments should be forwarded to the handler.
    pub fn set_forward_ack(&mut self, value: bool) {
        self.forward_ack = value;
    }

    pub fn socket_mut(&mut self) -> &mut S {
        self.socket.get_mut()
    }

    pub fn poll_send_messages(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<(), NetlinkProtoError>> {
        trace!("poll_send_messages called");
        if !self.protocol.outgoing_messages.is_empty() {
            trace!(
                "found outgoing message to send checking if socket is ready"
            );
            match Pin::new(&mut self.socket).poll_ready(cx) {
                Poll::Ready(Err(e)) => {
                    // Sink errors are usually not recoverable. The socket
                    // probably shut down.
                    warn!("netlink socket shut down: {e:?}");
                    self.socket_closed = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    trace!("poll is not ready, returning");
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {}
            }

            let (messages, addr) =
                self.protocol.outgoing_messages.pop_front().unwrap();
            for message in messages.into_vec() {
                trace!("queueing encoded outgoing message");
                self.socket.start_send_encoded(&message.buffer, addr);
            }
        }

        trace!("poll_send_messages done");
        self.poll_flush(cx)
    }

    pub fn poll_flush(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<(), NetlinkProtoError>> {
        trace!("poll_flush called");
        match Pin::new(&mut self.socket).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                warn!("error flushing netlink socket: {e:?}");
                self.socket_closed = true;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Poll the socket for incoming messages.
    ///
    /// Returns the terminal error if the socket stream failed.
    pub fn poll_read_messages(
        &mut self,
        cx: &mut Context,
    ) -> Option<NetlinkProtoError> {
        trace!("poll_read_messages called");
        loop {
            trace!("polling socket");
            match Pin::new(&mut self.socket).poll_next(cx) {
                Poll::Ready(Some(Ok((message, addr)))) => {
                    trace!("read datagram from socket");
                    self.protocol.handle_message(message, addr);
                }
                Poll::Ready(Some(Err(e))) => {
                    warn!("netlink socket stream failed: {e:?}");
                    self.socket_closed = true;
                    return Some(e);
                }
                Poll::Ready(None) => {
                    warn!("netlink socket stream shut down");
                    self.socket_closed = true;
                    return None;
                }
                Poll::Pending => {
                    trace!("no datagram read from socket");
                    return None;
                }
            }
        }
    }

    pub fn poll_requests(&mut self, cx: &mut Context) {
        trace!("poll_requests called");
        if let Some(mut stream) = self.requests_rx.as_mut() {
            loop {
                match Pin::new(&mut stream).poll_next(cx) {
                    Poll::Ready(Some(request)) => {
                        self.protocol.request(request)
                    }
                    Poll::Ready(None) => break,
                    Poll::Pending => return,
                }
            }
            let _ = self.requests_rx.take();
            trace!("no new requests to handle poll_requests done");
        }
    }

    pub fn forward_unsolicited_messages(&mut self) {
        if self.unsolicited_messages_tx.is_none() {
            while let Some((message, source)) =
                self.protocol.incoming_requests.pop_front()
            {
                warn!(
                    "ignoring unsolicited message {:?} from {:?}",
                    message, source
                );
            }
            return;
        }

        trace!("forward_unsolicited_messages called");
        let mut ready = false;

        let Connection {
            protocol,
            unsolicited_messages_tx,
            ..
        } = self;

        while let Some((message, source)) =
            protocol.incoming_requests.pop_front()
        {
            if unsolicited_messages_tx
                .as_mut()
                .unwrap()
                .unbounded_send((message, source))
                .is_err()
            {
                // The channel is unbounded so the only error that can
                // occur is that the channel is closed because the
                // receiver was dropped
                warn!(
                    "failed to forward message to connection handle: channel closed"
                );
                ready = true;
                break;
            }
        }

        if ready
            || self
                .unsolicited_messages_tx
                .as_ref()
                .is_none_or(|x| x.is_closed())
        {
            // The channel is closed so we can drop the sender.
            let _ = self.unsolicited_messages_tx.take();
            // purge `protocol.incoming_requests`
            self.forward_unsolicited_messages();
        }

        trace!("forward_unsolicited_messages done");
    }

    pub fn forward_responses(&mut self) {
        trace!("forward_responses called");
        let protocol = &mut self.protocol;

        while let Some(response) = protocol.incoming_responses.pop_front() {
            let Response {
                message,
                done,
                metadata: tx,
            } = response;
            if done {
                use NetlinkPayload::*;
                match &message.payload {
                    Noop => {
                        if !self.forward_noop {
                            trace!("Not forwarding Noop message to the handle");
                            continue;
                        }
                    }
                    // Since `self.protocol` set the `done` flag here,
                    // we know it has already dropped the request and
                    // its associated metadata, ie the UnboundedSender
                    // used to forward messages back to the
                    // ConnectionHandle. By just continuing we're
                    // dropping the last instance of that sender,
                    // hence closing the channel and signaling the
                    // handle that no more messages are expected.
                    Done(_) => {
                        if !self.forward_done {
                            trace!("Not forwarding Done message to the handle");
                            continue;
                        }
                    }
                    Overrun(_) => {
                        // Forward to the handle: the application must
                        // resync its state after message loss.
                    }
                    // We need to forward error messages and messages
                    // that are part of the netlink subprotocol,
                    // because only the user knows how they want to
                    // handle them.
                    Error(err_msg) => {
                        if err_msg.code.is_none() && !self.forward_ack {
                            trace!("Not forwarding Ack message to the handle");
                            continue;
                        }
                    }
                    InnerMessage(_) => {}
                    _ => {}
                }
            }

            trace!("forwarding response to the handle");
            if tx.unbounded_send(Ok(message)).is_err() {
                // With an unboundedsender, an error can
                // only happen if the receiver is closed.
                warn!("failed to forward response back to the handle");
            }
        }
        trace!("forward_responses done");
    }

    /// Record a terminal error and deliver it to every in-flight request.
    fn record_terminal(&mut self, error: &NetlinkProtoError) {
        self.protocol.fail_pending(|metadata| {
            let _ = metadata.unbounded_send(Err(error.duplicate()));
        });
        self.shared.set_closed(Some(error.duplicate()));
    }

    pub fn should_shut_down(&self) -> bool {
        self.socket_closed
            || (self.unsolicited_messages_tx.is_none()
                && self.requests_rx.is_none())
    }
}

impl<T, S, C> Connection<T, S, C>
where
    T: Debug + NetlinkMessagePayload + NetlinkDeserializable + Unpin,
    S: AsyncSocket,
    C: NetlinkMessageCodec,
{
    pub(crate) fn from_socket(
        requests_rx: UnboundedReceiver<Request<T>>,
        unsolicited_messages_tx: UnboundedSender<(
            NetlinkMessage<T>,
            SocketAddr,
        )>,
        shared: Arc<Shared>,
        socket: S,
    ) -> Self {
        Connection {
            socket: NetlinkFramed::new(socket),
            protocol: Protocol::new(),
            requests_rx: Some(requests_rx),
            unsolicited_messages_tx: Some(unsolicited_messages_tx),
            shared,
            socket_closed: false,
            forward_noop: false,
            forward_done: false,
            forward_ack: false,
        }
    }
}

impl<T, S, C> Future for Connection<T, S, C>
where
    T: Debug + NetlinkMessagePayload + NetlinkDeserializable + Unpin,
    S: AsyncSocket,
    C: NetlinkMessageCodec,
{
    type Output = Result<(), NetlinkProtoError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        trace!("polling Connection");
        let pinned = self.get_mut();

        trace!("reading incoming messages");
        let read_error = pinned.poll_read_messages(cx);

        trace!("forwarding unsolicited messages to the connection handle");
        pinned.forward_unsolicited_messages();

        trace!(
            "forwarding responses to previous requests to the connection handle"
        );
        pinned.forward_responses();

        trace!("handling requests");
        pinned.poll_requests(cx);

        // Forward whatever was read before the failure, then stop. Requests
        // are polled first so that already-submitted ones are registered and
        // receive the terminal error below.
        if let Some(error) = read_error {
            pinned.record_terminal(&error);
            return Poll::Ready(Err(error));
        }

        trace!("sending messages");
        match pinned.poll_send_messages(cx) {
            Poll::Ready(Err(error)) => {
                pinned.record_terminal(&error);
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(())) | Poll::Pending => {}
        }

        trace!("done polling Connection");

        if pinned.should_shut_down() {
            pinned.shared.set_closed(None);
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl<T, S, C> Drop for Connection<T, S, C>
where
    T: Debug + NetlinkMessagePayload + NetlinkDeserializable,
{
    fn drop(&mut self) {
        // If the future is dropped before completing (for instance because
        // the task was aborted), make sure `ConnectionHandle::closed` does not
        // hang forever.
        self.shared.set_closed(None);
    }
}

#[cfg(all(test, feature = "tokio_socket"))]
mod tests {
    use std::{
        fmt::Debug,
        io,
        task::{Context, Poll},
    };

    use futures_util::StreamExt;
    use netlink_packet_core::{
        DecodeError, Emitable, EncodeError, EncodeErrorKind, NLM_F_ACK,
        NLM_F_REQUEST, NetlinkDeserializable, NetlinkHeader, NetlinkMessage,
        NetlinkMessagePayload, NetlinkPayload,
    };
    use netlink_sys::Socket;
    use tokio::time;

    use crate::{
        NetlinkMessageCodec, NetlinkProtoError, from_socket_with_codec,
        new_connection,
        sys::{AsyncSocket, SocketAddr, TokioSocket, protocols::NETLINK_ROUTE},
    };

    #[derive(Debug)]
    struct Fake;

    impl Emitable for Fake {
        fn emit_value(&self, _out: &mut Vec<u8>) -> Result<(), EncodeError> {
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

    fn request() -> NetlinkMessage<Fake> {
        let mut message = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(Fake),
        );
        message.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        message
    }

    /// A codec that fails to encode any message.
    struct FailingCodec;

    impl NetlinkMessageCodec for FailingCodec {
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
            Err(EncodeError::new(EncodeErrorKind::Bug, "encode failure"))
        }
    }

    /// Which operation of [`FailingSocket`] fails.
    #[derive(Clone, Copy)]
    enum Failure {
        Send,
        Receive,
    }

    /// A socket that fails on send or receive.
    struct FailingSocket {
        inner: TokioSocket,
        failure: Failure,
    }

    impl FailingSocket {
        fn new(protocol: isize, failure: Failure) -> Self {
            Self {
                inner: TokioSocket::new(protocol).unwrap(),
                failure,
            }
        }
    }

    impl AsyncSocket for FailingSocket {
        fn socket_ref(&self) -> &Socket {
            self.inner.socket_ref()
        }

        fn socket_mut(&mut self) -> &mut Socket {
            self.inner.socket_mut()
        }

        fn new(protocol: isize) -> io::Result<Self> {
            Ok(Self {
                inner: TokioSocket::new(protocol)?,
                failure: Failure::Send,
            })
        }

        fn poll_send(
            &self,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.inner.poll_send(cx, buf)
        }

        fn poll_send_to(
            &self,
            _cx: &mut Context<'_>,
            _buf: &[u8],
            _addr: &SocketAddr,
        ) -> Poll<io::Result<usize>> {
            match self.failure {
                Failure::Send => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "socket send failure",
                ))),
                Failure::Receive => Poll::Pending,
            }
        }

        fn poll_recv<B>(
            &self,
            _cx: &mut Context<'_>,
            _buf: &mut B,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_recv_from<B>(
            &self,
            _cx: &mut Context<'_>,
            _buf: &mut B,
        ) -> Poll<io::Result<SocketAddr>> {
            match self.failure {
                Failure::Receive => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "socket receive failure",
                ))),
                Failure::Send => Poll::Pending,
            }
        }

        fn poll_recv_from_full(
            &self,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<(Vec<u8>, SocketAddr)>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn connection_is_closed() {
        let (conn, _, _) = new_connection::<Fake>(NETLINK_ROUTE).unwrap();
        let join_handle = tokio::spawn(conn);
        time::sleep(time::Duration::from_millis(200)).await;
        assert!(join_handle.is_finished());
    }

    #[tokio::test]
    async fn encode_error_is_returned_by_request() {
        let (conn, handle, _messages) =
            from_socket_with_codec::<Fake, TokioSocket, FailingCodec>(
                TokioSocket::new(NETLINK_ROUTE).unwrap(),
            );
        let _join = tokio::spawn(conn);

        let error = handle
            .request(request(), SocketAddr::new(0, 0))
            .err()
            .unwrap();
        assert!(matches!(error, NetlinkProtoError::Encode(_)));

        // An invalid message must not tear down the connection.
        assert!(
            time::timeout(time::Duration::from_millis(100), handle.closed())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn socket_error_is_reported_through_closed() {
        let (conn, handle, _messages) =
            from_socket_with_codec::<Fake, FailingSocket, crate::NetlinkCodec>(
                FailingSocket::new(NETLINK_ROUTE, Failure::Send),
            );
        let _join = tokio::spawn(conn);

        let mut stream =
            handle.request(request(), SocketAddr::new(0, 0)).unwrap();
        let item = stream.next().await;
        assert!(
            matches!(item, Some(Err(NetlinkProtoError::SocketIo(_)))),
            "unexpected stream item: {item:?}"
        );
        assert!(stream.next().await.is_none());

        let error = handle.closed().await;
        assert!(
            matches!(error.as_deref(), Some(NetlinkProtoError::SocketIo(_))),
            "unexpected terminal error: {error:?}"
        );

        // A later request reports the actual cause instead of a generic
        // `ConnectionClosed`.
        let error = handle
            .request(request(), SocketAddr::new(0, 0))
            .err()
            .unwrap();
        assert!(
            matches!(error, NetlinkProtoError::SocketIo(_)),
            "unexpected request error: {error:?}"
        );
    }

    #[tokio::test]
    async fn read_error_is_reported_to_multicast_and_closed() {
        let (conn, handle, mut messages) =
            from_socket_with_codec::<Fake, FailingSocket, crate::NetlinkCodec>(
                FailingSocket::new(NETLINK_ROUTE, Failure::Receive),
            );
        let _join = tokio::spawn(conn);

        assert!(messages.next().await.is_none());

        let error = handle.closed().await;
        assert!(
            matches!(error.as_deref(), Some(NetlinkProtoError::SocketIo(_))),
            "unexpected terminal error: {error:?}"
        );
    }
}
