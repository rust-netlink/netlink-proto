// SPDX-License-Identifier: MIT

use std::{fmt::Debug, io};

use log::{error, trace};
use netlink_packet_core::{
    Emitable, EncodeError, NetlinkBuffer, NetlinkDeserializable,
    NetlinkMessage, NetlinkMessagePayload,
};

/// Netlink message alignment, in bytes.
const NLMSG_ALIGNTO: usize = 4;

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
/// the message types (NetlinkDeserializable+NetlinkMessagePayload) it can
/// handle, this would put quite some overhead on subsystems that followed the
/// spec - so we simply default to the proper implementation (in `Connection`)
/// and the `audit` code needs to overwrite it.
pub trait NetlinkMessageCodec {
    /// Decode message of given type from datagram payload
    ///
    /// There might be more than one message; this needs to be called until it
    /// either returns `Ok(None)` or an error.
    ///
    /// On success, the returned tuple contains the message and the number of
    /// bytes consumed from the start of `src` (including any malformed
    /// messages that were skipped). The caller is expected to advance its
    /// buffer by that amount. `Ok(None)` means the rest of the datagram should
    /// be discarded.
    fn decode<T>(
        src: &mut [u8],
    ) -> io::Result<Option<(NetlinkMessage<T>, usize)>>
    where
        T: NetlinkDeserializable + Debug;

    /// Encode message to (datagram) buffer
    fn encode<T>(
        msg: NetlinkMessage<T>,
        buf: &mut Vec<u8>,
    ) -> Result<(), EncodeError>
    where
        T: NetlinkMessagePayload + Debug;
}

/// Standard implementation of `NetlinkMessageCodec`
pub struct NetlinkCodec {
    // we don't need an instance of this, just the type
    _private: (),
}

impl NetlinkMessageCodec for NetlinkCodec {
    fn decode<T>(
        src: &mut [u8],
    ) -> io::Result<Option<(NetlinkMessage<T>, usize)>>
    where
        T: NetlinkDeserializable + Debug,
    {
        trace!("NetlinkCodec: decoding next message");

        let mut offset = 0;
        loop {
            let remaining = &src[offset..];

            // If there's nothing to read, return Ok(None)
            if remaining.is_empty() {
                trace!("buffer is empty");
                return Ok(None);
            }

            // Validate once, parse from the validated buffer, and report how
            // many bytes the caller should discard. This avoids validating
            // the same bytes again in NetlinkMessage::deserialize().
            let (consumed, parsed) = {
                let buf = match NetlinkBuffer::new(remaining) {
                    Ok(buf) => buf,
                    Err(e) => {
                        // We either received a truncated packet, or the
                        // packet is malformed (invalid length field). In
                        // both cases, we can't decode the datagram, and we
                        // cannot find the start of the next one (if
                        // any). The only solution is to discard the rest of
                        // the datagram and potentially lose some messages.
                        error!(
                            "failed to decode datagram, discarding buffer: {:?}: {:#x?}.",
                            e, remaining
                        );
                        return Ok(None);
                    }
                };
                let len = buf.length() as usize;
                // Packed datagrams pad every message to `NLMSG_ALIGNTO`, so
                // the next header starts at the aligned length. The last
                // message may have no trailing padding.
                let aligned = len.saturating_add(NLMSG_ALIGNTO - 1)
                    & !(NLMSG_ALIGNTO - 1);
                (
                    aligned.min(remaining.len()),
                    NetlinkMessage::<T>::parse_buffer(&buf),
                )
            };

            match parsed {
                Ok(packet) => {
                    trace!("<<< {:?}", packet);
                    return Ok(Some((packet, offset + consumed)));
                }
                Err(e) => {
                    error!(
                        "failed to decode packet {:#x?}: {}",
                        &remaining[..consumed],
                        e
                    );
                    offset += consumed;
                    // continue looping, there may be more datagrams in the
                    // buffer
                }
            }
        }
    }

    fn encode<T>(
        msg: NetlinkMessage<T>,
        buf: &mut Vec<u8>,
    ) -> Result<(), EncodeError>
    where
        T: NetlinkMessagePayload + Debug,
    {
        msg.emit(buf)?;
        trace!(">>> {:?}", msg);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use netlink_packet_core::{
        DecodeError, DefaultNla, Emitable, EncodeError, EncodeErrorKind,
        NLA_MAX_VALUE_LEN, NetlinkBuffer, NetlinkDeserializable, NetlinkHeader,
        NetlinkMessage, NetlinkMessagePayload, NetlinkPayload, Nla,
    };

    use super::{NLMSG_ALIGNTO, NetlinkCodec, NetlinkMessageCodec};

    #[derive(Debug, PartialEq, Eq)]
    struct Fake;

    impl Emitable for Fake {
        fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
            out.extend_from_slice(b"abc");
            Ok(())
        }
    }

    impl NetlinkMessagePayload for Fake {
        fn message_type(&self) -> u16 {
            42
        }
    }

    impl NetlinkDeserializable for Fake {
        fn deserialize(
            _header: &NetlinkHeader,
            payload: &[u8],
        ) -> Result<Self, DecodeError> {
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
        let header = NetlinkBuffer::new(buffer.as_slice()).unwrap();
        assert_eq!(header.length(), 19);
        assert_eq!(header.message_type(), 42);

        let mut source = buffer.clone();
        let (decoded, consumed) =
            NetlinkCodec::decode::<Fake>(&mut source).unwrap().unwrap();
        assert_eq!(decoded.payload, NetlinkPayload::InnerMessage(Fake));
        assert_eq!(consumed, buffer.len());
    }

    #[test]
    fn decode_skips_message_alignment_padding() {
        let message: NetlinkMessage<Fake> = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(Fake),
        );

        let mut first = Vec::new();
        NetlinkCodec::encode(message, &mut first).unwrap();
        assert_ne!(first.len() % NLMSG_ALIGNTO, 0);

        let second: NetlinkMessage<Fake> = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(Fake),
        );
        let mut datagram = first.clone();
        let padding =
            (NLMSG_ALIGNTO - first.len() % NLMSG_ALIGNTO) % NLMSG_ALIGNTO;
        datagram.resize(datagram.len() + padding, 0);
        NetlinkCodec::encode(second, &mut datagram).unwrap();

        let mut source = datagram.clone();
        let (decoded, consumed) =
            NetlinkCodec::decode::<Fake>(&mut source).unwrap().unwrap();
        assert_eq!(decoded.payload, NetlinkPayload::InnerMessage(Fake));
        let (decoded, consumed_tail) =
            NetlinkCodec::decode::<Fake>(&mut source[consumed..])
                .unwrap()
                .unwrap();
        assert_eq!(decoded.payload, NetlinkPayload::InnerMessage(Fake));
        assert_eq!(consumed + consumed_tail, source.len());
    }

    #[test]
    fn decode_rejects_invalid_length_without_panicking() {
        let mut bytes = vec![0u8; 16];
        bytes[0] = 0x04;
        let mut source = bytes;
        let decoded = NetlinkCodec::decode::<Fake>(&mut source).unwrap();
        assert!(decoded.is_none());
    }

    #[test]
    fn decode_rejects_truncated_header_without_panicking() {
        let mut source = vec![0x28, 0x00];
        let decoded = NetlinkCodec::decode::<Fake>(&mut source).unwrap();
        assert!(decoded.is_none());
    }

    #[test]
    fn encode_error_preserves_buffer() {
        #[derive(Debug)]
        struct Bad;

        impl Emitable for Bad {
            fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
                out.push(1);
                Err(EncodeError::new(EncodeErrorKind::Bug, "bad message"))
            }
        }

        impl NetlinkMessagePayload for Bad {
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

    #[derive(Debug)]
    struct OversizedNla(DefaultNla);

    impl Emitable for OversizedNla {
        fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
            self.0.emit(out)
        }
    }

    impl NetlinkMessagePayload for OversizedNla {
        fn message_type(&self) -> u16 {
            1
        }
    }

    #[test]
    fn encode_attribute_error_preserves_buffer() {
        let message = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(OversizedNla(DefaultNla::new(
                1,
                vec![0; NLA_MAX_VALUE_LEN + 1],
            ))),
        );

        let mut buffer = vec![0xaa];
        let error = NetlinkCodec::encode(message, &mut buffer).unwrap_err();
        assert!(error.is_too_large(), "unexpected error: {error}");
        assert_eq!(buffer, vec![0xaa]);
    }
}
