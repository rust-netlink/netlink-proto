// SPDX-License-Identifier: MIT

use std::{
    collections::{HashMap, VecDeque, hash_map},
    fmt::Debug,
    sync::Arc,
};

use log::trace;
use netlink_packet_core::{NLM_F_MULTIPART, NetlinkMessage, NetlinkPayload};

use super::{OutgoingMessage, Request};
use crate::sys::SocketAddr;

#[derive(Debug, Eq, PartialEq, Hash)]
struct RequestId {
    sequence_number: u32,
    port: u32,
}

impl RequestId {
    fn new(sequence_number: u32, port: u32) -> Self {
        Self {
            sequence_number,
            port,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Response<T, M> {
    pub done: bool,
    pub message: NetlinkMessage<T>,
    pub metadata: M,
}

#[derive(Debug)]
struct PendingRequest<M> {
    expecting_ack: bool,
    metadata: M,
    token: Arc<()>,
}

#[derive(Debug, Default)]
pub(crate) struct Protocol<T, M> {
    /// Requests for which we're awaiting a response. Metadata are
    /// associated with each request.
    pending_requests: HashMap<RequestId, PendingRequest<M>>,

    /// Responses to pending requests
    pub incoming_responses: VecDeque<Response<T, M>>,

    /// Requests from remote peers
    pub incoming_requests: VecDeque<(NetlinkMessage<T>, SocketAddr)>,

    /// The messages to be sent out
    pub outgoing_messages: VecDeque<(Box<[OutgoingMessage]>, SocketAddr)>,
}

impl<T, M> Protocol<T, M>
where
    T: Debug,
    M: Debug + Clone,
{
    pub fn new() -> Self {
        Self {
            pending_requests: HashMap::new(),
            incoming_responses: VecDeque::new(),
            incoming_requests: VecDeque::new(),
            outgoing_messages: VecDeque::new(),
        }
    }

    pub fn handle_message(
        &mut self,
        message: NetlinkMessage<T>,
        source: SocketAddr,
    ) {
        let request_id = RequestId::new(
            message.header.sequence_number,
            source.port_number(),
        );
        trace!("handling messages (request id = {:?})", request_id);
        if let hash_map::Entry::Occupied(entry) =
            self.pending_requests.entry(request_id)
        {
            Self::handle_response(&mut self.incoming_responses, entry, message);
        } else {
            self.incoming_requests.push_back((message, source));
        }
    }

    fn handle_response(
        incoming_responses: &mut VecDeque<Response<T, M>>,
        entry: hash_map::OccupiedEntry<RequestId, PendingRequest<M>>,
        message: NetlinkMessage<T>,
    ) {
        let entry_key;
        let mut request_id = entry.key();
        trace!("handling response to request {:?}", request_id);

        // A request is processed if we receive an Ack, Error,
        // Done, Overrun, or InnerMessage without the
        // multipart flag and we were not expecting an Ack
        let done = match message.payload {
            NetlinkPayload::InnerMessage(_)
                if message.header.flags & NLM_F_MULTIPART
                    == NLM_F_MULTIPART =>
            {
                false
            }
            NetlinkPayload::InnerMessage(_) => !entry.get().expecting_ack,
            _ => true,
        };

        let metadata = if done {
            trace!("request {:?} fully processed", request_id);
            let (k, v) = entry.remove_entry();
            entry_key = k;
            request_id = &entry_key;
            v.metadata
        } else {
            trace!("more responses to request {:?} may come", request_id);
            entry.get().metadata.clone()
        };

        let response = Response::<T, M> {
            done,
            message,
            metadata,
        };
        incoming_responses.push_back(response);
        trace!("done handling response to request {:?}", request_id);
    }

    pub fn request(&mut self, request: Request<M>) {
        let Request {
            metadata,
            messages,
            destination,
            token,
        } = request;

        for message in messages.iter() {
            if message.expects_response {
                let request_id = RequestId::new(
                    message.sequence_number,
                    destination.port_number(),
                );
                self.pending_requests.insert(
                    request_id,
                    PendingRequest {
                        expecting_ack: message.expecting_ack,
                        metadata: metadata.clone(),
                        token: token.clone(),
                    },
                );
            }
        }
        self.outgoing_messages.push_back((messages, destination));
    }

    /// Drop every pending request, handing its metadata to `fail`.
    ///
    /// Used when the connection terminates: each in-flight request can then be
    /// told why it will never receive a response. Metadata is handed over once
    /// per request, even if it spans several messages.
    pub fn fail_pending(&mut self, mut fail: impl FnMut(M)) {
        let mut failed = Vec::new();
        for (_, pending) in self.pending_requests.drain() {
            if failed
                .iter()
                .any(|token| Arc::ptr_eq(token, &pending.token))
            {
                continue;
            }
            failed.push(pending.token);
            fail(pending.metadata);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};

    #[derive(Debug)]
    struct TestMessage;

    fn new_protocol() -> Protocol<TestMessage, ()> {
        Protocol::new()
    }

    fn message(sequence_number: u32) -> NetlinkMessage<TestMessage> {
        let mut message = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(TestMessage),
        );
        message.header.sequence_number = sequence_number;
        message
    }

    fn outgoing(
        sequence_number: u32,
        expects_response: bool,
    ) -> OutgoingMessage {
        OutgoingMessage {
            buffer: Vec::new(),
            sequence_number,
            expecting_ack: false,
            expects_response,
        }
    }

    fn request(messages: Box<[OutgoingMessage]>) -> Request<()> {
        Request {
            metadata: (),
            messages,
            destination: SocketAddr::new(0, 0),
            token: Arc::new(()),
        }
    }

    #[test]
    fn expected_response_registers_pending_request() {
        let mut protocol = new_protocol();
        protocol.request(request(Box::new([outgoing(1, true)])));
        assert_eq!(protocol.pending_requests.len(), 1);
        assert!(
            protocol
                .pending_requests
                .contains_key(&RequestId::new(1, 0))
        );
        assert_eq!(protocol.outgoing_messages.len(), 1);
    }

    #[test]
    fn unexpected_message_is_not_tracked() {
        let mut protocol = new_protocol();
        protocol.request(request(Box::new([outgoing(1, false)])));
        assert!(protocol.pending_requests.is_empty());
        assert_eq!(protocol.outgoing_messages.len(), 1);
    }

    #[test]
    fn response_without_pending_request_is_unsolicited() {
        let mut protocol = new_protocol();
        protocol.request(request(Box::new([outgoing(1, false)])));

        protocol.handle_message(message(1), SocketAddr::new(0, 0));
        assert!(protocol.incoming_responses.is_empty());
        assert_eq!(protocol.incoming_requests.len(), 1);
    }

    #[test]
    fn expected_response_closes_pending_request() {
        let mut protocol = new_protocol();
        protocol.request(request(Box::new([outgoing(1, true)])));
        assert_eq!(protocol.pending_requests.len(), 1);

        protocol.handle_message(message(1), SocketAddr::new(0, 0));

        assert!(protocol.pending_requests.is_empty());
        assert!(protocol.incoming_requests.is_empty());
        assert_eq!(protocol.incoming_responses.len(), 1);
        assert!(protocol.incoming_responses[0].done);
    }

    #[test]
    fn fail_pending_notifies_once_per_request() {
        use futures_channel::mpsc::unbounded;

        use crate::NetlinkProtoError;

        let (tx, mut rx) = unbounded::<
            Result<NetlinkMessage<TestMessage>, NetlinkProtoError>,
        >();
        let mut protocol: Protocol<TestMessage, _> = Protocol::new();
        protocol.request(Request {
            metadata: tx.clone(),
            messages: Box::new([outgoing(1, true), outgoing(2, true)]),
            destination: SocketAddr::new(0, 0),
            token: Arc::new(()),
        });
        drop(tx);

        protocol.fail_pending(|metadata| {
            metadata
                .unbounded_send(Err(NetlinkProtoError::ConnectionClosed))
                .unwrap();
        });

        assert!(matches!(
            rx.try_recv(),
            Ok(Err(NetlinkProtoError::ConnectionClosed))
        ));
        assert!(rx.try_recv().is_err());
        assert!(protocol.pending_requests.is_empty());
    }
}
