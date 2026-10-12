// SPDX-License-Identifier: MIT

use std::{
    collections::{hash_map, HashMap, VecDeque},
    fmt::Debug,
};

use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
    NLM_F_ACK, NLM_F_ECHO, NLM_F_MULTIPART, NLM_F_REQUEST,
};

use super::{ExpectResponse, Request};
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
}

#[derive(Debug, Default)]
pub(crate) struct Protocol<T, M> {
    /// Counter that is incremented for each message sent
    sequence_id: u32,

    /// Requests for which we're awaiting a response. Metadata are
    /// associated with each request.
    pending_requests: HashMap<RequestId, PendingRequest<M>>,

    /// Responses to pending requests
    pub incoming_responses: VecDeque<Response<T, M>>,

    /// Requests from remote peers
    pub incoming_requests: VecDeque<(NetlinkMessage<T>, SocketAddr)>,

    /// The messages to be sent out
    pub outgoing_messages: VecDeque<(Box<[NetlinkMessage<T>]>, SocketAddr)>,
}

impl<T, M> Protocol<T, M>
where
    T: Debug + NetlinkSerializable + NetlinkDeserializable,
    M: Debug + Clone,
{
    pub fn new() -> Self {
        Self {
            sequence_id: 0,
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

    pub fn request(&mut self, request: Request<T, M>) {
        let Request {
            metadata,
            mut messages,
            destination,
            expect_response,
        } = request;

        for (index, message) in messages.iter_mut().enumerate() {
            self.set_sequence_id(message);
            let request_id =
                RequestId::new(self.sequence_id, destination.port_number());
            let flags = message.header.flags;

            // If we expect a response, we store the request id so that we
            // can map the response to this specific request.
            let expects_response = match &expect_response {
                // We expect a response when the message has one of:
                //  - the NLM_F_REQUEST flag
                //  - the NLM_F_ACK flag
                //  - the NLM_F_ECHO flag
                ExpectResponse::FromFlags => {
                    flags & (NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO) != 0
                }
                ExpectResponse::Explicit(expected) => {
                    expected.get(index).copied().unwrap_or(false)
                }
            };
            if expects_response {
                let expecting_ack = flags & NLM_F_ACK == NLM_F_ACK;
                self.pending_requests.insert(
                    request_id,
                    PendingRequest {
                        expecting_ack,
                        metadata: metadata.clone(),
                    },
                );
            }
        }
        self.outgoing_messages.push_back((messages, destination));
    }

    fn set_sequence_id(&mut self, message: &mut NetlinkMessage<T>) {
        self.sequence_id += 1;
        message.header.sequence_number = self.sequence_id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_audit::AuditMessage;

    fn new_protocol() -> Protocol<AuditMessage, ()> {
        Protocol::new()
    }

    fn message(flags: u16) -> NetlinkMessage<AuditMessage> {
        let mut message = NetlinkMessage::from(AuditMessage::GetStatus(None));
        message.header.flags = flags;
        message
    }

    fn request(
        messages: Box<[NetlinkMessage<AuditMessage>]>,
        expect_response: ExpectResponse,
    ) -> Request<AuditMessage, ()> {
        Request {
            metadata: (),
            messages,
            destination: SocketAddr::new(0, 0),
            expect_response,
        }
    }

    #[test]
    fn flags_define_expected_response() {
        for flags in [NLM_F_REQUEST, NLM_F_ACK, NLM_F_ECHO] {
            let mut protocol = new_protocol();
            protocol.request(request(
                Box::new([message(flags)]),
                ExpectResponse::FromFlags,
            ));
            assert_eq!(protocol.pending_requests.len(), 1, "flags: {flags:#x}");
        }

        let mut protocol = new_protocol();
        protocol.request(request(
            Box::new([message(0)]),
            ExpectResponse::FromFlags,
        ));
        assert!(protocol.pending_requests.is_empty());
    }

    #[test]
    fn explicit_expectation_overrides_flags() {
        let mut protocol = new_protocol();
        protocol.request(request(
            Box::new([message(NLM_F_REQUEST), message(NLM_F_REQUEST)]),
            ExpectResponse::Explicit(Box::new([true, false])),
        ));
        assert_eq!(protocol.pending_requests.len(), 1);
        assert!(protocol
            .pending_requests
            .contains_key(&RequestId::new(1, 0)));
        assert!(!protocol
            .pending_requests
            .contains_key(&RequestId::new(2, 0)));
    }

    #[test]
    fn unexpected_response_is_unsolicited() {
        let mut protocol = new_protocol();
        protocol.request(request(
            Box::new([message(NLM_F_REQUEST | NLM_F_ACK)]),
            ExpectResponse::Explicit(Box::new([false])),
        ));
        assert!(protocol.pending_requests.is_empty());

        protocol.handle_message(message(0), SocketAddr::new(0, 0));
        assert!(protocol.incoming_responses.is_empty());
        assert_eq!(protocol.incoming_requests.len(), 1);
    }

    #[test]
    fn expected_response_closes_pending_request() {
        let mut protocol = new_protocol();
        protocol.request(request(
            Box::new([message(NLM_F_REQUEST)]),
            ExpectResponse::Explicit(Box::new([true])),
        ));
        assert_eq!(protocol.pending_requests.len(), 1);

        let mut response = message(0);
        response.header.sequence_number = 1;
        protocol.handle_message(response, SocketAddr::new(0, 0));

        assert!(protocol.pending_requests.is_empty());
        assert!(protocol.incoming_requests.is_empty());
        assert_eq!(protocol.incoming_responses.len(), 1);
        assert!(protocol.incoming_responses[0].done);
    }
}
