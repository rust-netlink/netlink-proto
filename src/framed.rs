// SPDX-License-Identifier: MIT

use std::{
    fmt::Debug,
    io,
    marker::PhantomData,
    mem::size_of,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::{Sink, Stream, ready};
use log::{error, trace, warn};
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkHeader, NetlinkMessage,
    NetlinkMessagePayload, NetlinkPayload,
};

use crate::sys::{AsyncSocket, SocketAddr};
use crate::{NetlinkMessageCodec, NetlinkProtoError};

/// Buffer overrun condition
const ENOBUFS: i32 = 105;

/// Data lost.
const NLMSG_OVERRUN: u16 = 4;

/// A framed netlink socket using the fallible encoding API.
pub struct NetlinkFramed<T, S, C> {
    socket: S,
    // see https://doc.rust-lang.org/nomicon/phantom-data.html
    // "invariant" seems like the safe choice; using `fn(T) -> T`
    // should make it invariant but still Send+Sync.
    msg_type: PhantomData<fn(T) -> T>, // invariant
    codec: PhantomData<fn(C) -> C>,    // invariant
    reader: Vec<u8>,
    reader_offset: usize,
    writer: Vec<u8>,
    in_addr: SocketAddr,
    out_addr: SocketAddr,
    flushed: bool,
}

impl<T, S, C> Stream for NetlinkFramed<T, S, C>
where
    T: NetlinkDeserializable + Debug,
    S: AsyncSocket,
    C: NetlinkMessageCodec,
{
    type Item = Result<(NetlinkMessage<T>, SocketAddr), NetlinkProtoError>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            socket,
            in_addr,
            reader,
            reader_offset,
            ..
        } = Pin::get_mut(self);

        loop {
            match C::decode::<T>(&mut reader[*reader_offset..]) {
                Ok(Some((item, consumed))) => {
                    *reader_offset += consumed;
                    return Poll::Ready(Some(Ok((item, *in_addr))));
                }
                Ok(None) => {}
                Err(e) => {
                    return Poll::Ready(Some(Err(NetlinkProtoError::from(e))));
                }
            }

            reader.clear();
            *reader_offset = 0;
            reader.reserve(INITIAL_READER_CAPACITY);

            *in_addr = match ready!(socket.poll_recv_from(cx, reader)) {
                Ok(addr) => addr,
                // When receiving messages in multicast mode (i.e. we subscribed
                // to notifications), the kernel will not wait
                // for us to read datagrams before sending more.
                // The receive buffer has a finite size, so once it is full (no
                // more message can fit in), new messages will be dropped and
                // recv calls will return `ENOBUFS`.
                // This needs to be handled for applications to resynchronize
                // with the contents of the kernel if necessary.
                // We don't need to do anything special:
                // - contents of the reader is still valid because we won't have
                //   partial messages in there anyways (large enough buffer)
                // - contents of the socket's internal buffer is still valid
                //   because the kernel won't put partial data in it
                Err(e) if e.raw_os_error() == Some(ENOBUFS) => {
                    warn!("netlink socket buffer full");
                    let mut hdr = NetlinkHeader::default();
                    hdr.length = size_of::<NetlinkHeader>() as u32;
                    hdr.message_type = NLMSG_OVERRUN;
                    let msg = NetlinkMessage::new(
                        hdr,
                        NetlinkPayload::Overrun(Vec::new()),
                    );
                    return Poll::Ready(Some(Ok((msg, SocketAddr::new(0, 0)))));
                }
                Err(e) => {
                    error!("failed to read from netlink socket: {:?}", e);
                    return Poll::Ready(Some(Err(NetlinkProtoError::from(e))));
                }
            };
        }
    }
}

impl<T, S, C> Sink<(NetlinkMessage<T>, SocketAddr)> for NetlinkFramed<T, S, C>
where
    T: NetlinkMessagePayload + Debug,
    S: AsyncSocket,
    C: NetlinkMessageCodec,
{
    type Error = NetlinkProtoError;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: (NetlinkMessage<T>, SocketAddr),
    ) -> Result<(), Self::Error> {
        trace!("sending frame");
        let (frame, out_addr) = item;
        let pin = self.get_mut();
        let start = pin.writer.len();
        if let Err(error) = C::encode(frame, &mut pin.writer) {
            pin.writer.truncate(start);
            return Err(NetlinkProtoError::from(error));
        }
        pin.out_addr = out_addr;
        pin.flushed = false;
        trace!("frame encoded; length={}", pin.writer.len());
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        trace!("flushing frames; length={}", self.writer.len());
        let Self {
            ref mut socket,
            ref mut out_addr,
            ref mut writer,
            ..
        } = *self;

        let n = match ready!(socket.poll_send_to(
            cx,
            writer.as_slice(),
            out_addr
        )) {
            Ok(n) => n,
            Err(e) => {
                return Poll::Ready(Err(NetlinkProtoError::SocketIo(e)));
            }
        };
        trace!("written {}", n);

        let wrote_all = n == self.writer.len();
        self.writer.clear();
        self.flushed = true;

        let result = if wrote_all {
            Ok(())
        } else {
            Err(NetlinkProtoError::SocketIo(io::Error::other(
                "failed to write entire datagram to socket",
            )))
        };

        Poll::Ready(result)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

// The theoretical max netlink packet size is 32KB for a netlink
// message since Linux 4.9 (16KB before). See:
// https://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git/commit/?id=d35c99ff77ecb2eb239731b799386f3b3637a31e
const INITIAL_READER_CAPACITY: usize = 64 * 1024;
const INITIAL_WRITER_CAPACITY: usize = 8 * 1024;

impl<T, S, C> NetlinkFramed<T, S, C> {
    /// Queue an already-encoded netlink message for sending.
    ///
    /// This is used by [`Connection`](crate::Connection) so that messages are
    /// only encoded once, when the request is submitted through the handle.
    pub(crate) fn start_send_encoded(
        &mut self,
        buffer: &[u8],
        addr: SocketAddr,
    ) {
        self.writer.extend_from_slice(buffer);
        self.out_addr = addr;
        self.flushed = false;
    }

    /// Create a new `NetlinkFramed` backed by the given socket and codec.
    pub fn new(socket: S) -> Self {
        Self {
            socket,
            msg_type: PhantomData,
            codec: PhantomData,
            out_addr: SocketAddr::new(0, 0),
            in_addr: SocketAddr::new(0, 0),
            reader: Vec::with_capacity(INITIAL_READER_CAPACITY),
            reader_offset: 0,
            writer: Vec::with_capacity(INITIAL_WRITER_CAPACITY),
            flushed: true,
        }
    }

    /// Return a reference to the underlying socket.
    ///
    /// # Note
    ///
    /// Care should be taken to not tamper with the underlying stream of data
    /// coming in as it may corrupt the stream of frames otherwise being worked
    /// with.
    pub fn get_ref(&self) -> &S {
        &self.socket
    }

    /// Return a mutable reference to the underlying socket.
    ///
    /// # Note
    ///
    /// Care should be taken to not tamper with the underlying stream of data
    /// coming in as it may corrupt the stream of frames otherwise being worked
    /// with.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }

    /// Consume this framed socket and return the underlying socket.
    pub fn into_inner(self) -> S {
        self.socket
    }
}
