// SPDX-License-Identifier: MIT

use std::{fmt, io};

use netlink_packet_core::ErrorMessage;

#[derive(Debug)]
pub enum NetlinkProtoError {
    /// The netlink connection is closed
    ConnectionClosed,

    /// Received an error message encoded in a netlink packet as a response
    NetlinkError(ErrorMessage),

    /// Error while reading from or writing to the netlink socket
    SocketIo(io::Error),
}

impl fmt::Display for NetlinkProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionClosed => {
                write!(f, "the netlink connection is closed")
            }
            Self::NetlinkError(msg) => {
                write!(f, "received an error message as a response: {msg:?}")
            }
            Self::SocketIo(err) => write!(
                f,
                "error while reading from or writing to the netlink socket: \
                 {err}"
            ),
        }
    }
}

impl std::error::Error for NetlinkProtoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SocketIo(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for NetlinkProtoError {
    fn from(err: io::Error) -> Self {
        Self::SocketIo(err)
    }
}

impl From<ErrorMessage> for NetlinkProtoError {
    fn from(err_msg: ErrorMessage) -> Self {
        Self::NetlinkError(err_msg)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use netlink_packet_core::ErrorMessage;

    use super::NetlinkProtoError;

    #[test]
    fn display_connection_closed() {
        assert_eq!(
            NetlinkProtoError::ConnectionClosed.to_string(),
            "the netlink connection is closed"
        );
    }

    #[test]
    fn display_and_source_netlink_error() {
        let err = NetlinkProtoError::from(ErrorMessage::default());
        assert_eq!(
            err.to_string(),
            "received an error message as a response: ErrorMessage { code: \
             None, header: [] }"
        );
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn display_and_source_socket_io() {
        let err = NetlinkProtoError::from(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "test",
        ));
        assert_eq!(
            err.to_string(),
            "error while reading from or writing to the netlink socket: test"
        );
        let source = std::error::Error::source(&err)
            .expect("socket error should expose its source");
        assert_eq!(source.to_string(), "test");
    }
}
