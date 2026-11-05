// SPDX-License-Identifier: MIT

use std::fmt::Debug;

use netlink_packet_core::{
    DecodeError, EncodeError, NetlinkBuffer, NetlinkDeserializable,
    NetlinkMessage, NetlinkSerializable,
};

/// Protocol to serialize and deserialize messages to and from datagrams
///
/// This is separate from `tokio_util::codec::{Decoder, Encoder}` as the
/// implementations rely on the buffer containing full datagrams; they won't
/// work well with simple bytestreams.
///
/// Officially there should be exactly one implementation of this, but the audit
/// subsystem ignores way too many rules of the protocol, so they need a
/// separate implementation.
///
/// Although one could make a tighter binding between `NetlinkMessageCodec` and
/// the message types (NetlinkDeserializable+NetlinkSerializable) it can handle,
/// this would put quite some overhead on subsystems that followed the spec - so
/// we simply default to the proper implementation (in `Connection`) and the
/// `audit` code needs to overwrite it.
pub trait NetlinkMessageCodec {
    /// Decode message of given type from datagram payload
    ///
    /// There might be more than one message; this needs to be called until it
    /// either returns `Ok(None)` or an error.
    fn decode<T>(
        src: &mut Vec<u8>,
    ) -> Result<Option<NetlinkMessage<T>>, DecodeError>
    where
        T: NetlinkDeserializable + Debug;

    /// Encode message to (datagram) buffer
    fn encode<T>(
        msg: NetlinkMessage<T>,
        buf: &mut Vec<u8>,
    ) -> Result<(), EncodeError>
    where
        T: NetlinkSerializable + Debug;
}

/// Standard implementation of `NetlinkMessageCodec`
pub struct NetlinkCodec {
    // we don't need an instance of this, just the type
    _private: (),
}

impl NetlinkMessageCodec for NetlinkCodec {
    fn decode<T>(
        src: &mut Vec<u8>,
    ) -> Result<Option<NetlinkMessage<T>>, DecodeError>
    where
        T: NetlinkDeserializable + Debug,
    {
        trace!("NetlinkCodec: decoding next message");

        // If there's nothing to read, return Ok(None)
        if src.is_empty() {
            trace!("buffer is empty");
            return Ok(None);
        }

        let len = NetlinkBuffer::new_checked(src.as_slice())?.length() as usize;
        let packet = NetlinkMessage::<T>::deserialize(&src[..len])?;
        src.drain(..len);
        trace!("<<< {:?}", packet);
        Ok(Some(packet))
    }

    fn encode<T>(
        msg: NetlinkMessage<T>,
        buf: &mut Vec<u8>,
    ) -> Result<(), EncodeError>
    where
        T: NetlinkSerializable + Debug,
    {
        msg.serialize_into(buf)?;
        trace!(">>> {:?}", msg);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use netlink_packet_core::{
        DefaultNla, Emitable, EncodeError, NLA_MAX_VALUE_LEN, NetlinkBuffer,
        NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload,
        NetlinkSerializable,
    };
    use netlink_packet_route::{
        RouteNetlinkMessage,
        route::{RouteAttribute, RouteMessage},
    };

    use super::{NetlinkCodec, NetlinkMessageCodec};

    #[derive(Debug, PartialEq, Eq)]
    struct Fake;

    impl Emitable for Fake {
        fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
            out.extend_from_slice(b"abc");
            Ok(())
        }
    }

    impl NetlinkSerializable for Fake {
        fn message_type(&self) -> u16 {
            42
        }
    }

    impl NetlinkDeserializable for Fake {
        type Error = Infallible;

        fn deserialize(
            _header: &NetlinkHeader,
            payload: &[u8],
        ) -> Result<Self, Self::Error> {
            assert_eq!(payload, b"abc");
            Ok(Fake)
        }
    }

    #[test]
    fn encode_sets_header_and_decode_round_trips() {
        let message: NetlinkMessage<Fake> = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(Fake),
        );

        let mut buffer = Vec::new();
        NetlinkCodec::encode(message, &mut buffer).unwrap();
        assert_eq!(buffer.len(), 19);
        let header = NetlinkBuffer::new_checked(buffer.as_slice()).unwrap();
        assert_eq!(header.length(), 19);
        assert_eq!(header.message_type(), 42);

        let mut source = buffer.clone();
        let decoded =
            NetlinkCodec::decode::<Fake>(&mut source).unwrap().unwrap();
        assert_eq!(decoded.payload, NetlinkPayload::InnerMessage(Fake));
    }

    #[test]
    fn encode_error_preserves_buffer() {
        #[derive(Debug)]
        struct Bad;

        impl Emitable for Bad {
            fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
                out.push(1);
                Err(EncodeError::new("bad message"))
            }
        }

        impl NetlinkSerializable for Bad {
            fn message_type(&self) -> u16 {
                1
            }
        }

        let message = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(Bad),
        );
        let mut buffer = vec![0xaa];
        NetlinkCodec::encode(message, &mut buffer).unwrap_err();
        assert_eq!(buffer, vec![0xaa]);
    }

    #[test]
    fn encode_route_attribute_error_preserves_buffer() {
        let mut route = RouteMessage::default();
        route.attributes.push(RouteAttribute::Other(DefaultNla::new(
            1,
            vec![0; NLA_MAX_VALUE_LEN + 1],
        )));
        let message = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)),
        );

        let mut buffer = vec![0xaa];
        let error = NetlinkCodec::encode(message, &mut buffer).unwrap_err();
        assert!(error.is_too_large(), "unexpected error: {error}");
        assert_eq!(buffer, vec![0xaa]);
    }
}
