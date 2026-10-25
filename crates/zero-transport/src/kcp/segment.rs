//! The mKCP segment format.
//!
//! Xray replaced its KCP transport in 24.9.30 with this small protocol: a
//! reliable, ordered byte stream carried in UDP datagrams. A datagram may hold
//! several segments back to back, so [`parse`] reads until the buffer ends or a
//! segment does not parse; the rest of that datagram is dropped, the way Xray
//! drops it.
//!
//! Every segment starts with the same four bytes, followed by a body whose
//! shape depends on the command:
//!
//! ```text
//! conv:u16  cmd:u8  option:u8  body
//!
//! data      (cmd 1): timestamp:u32 number:u32 sending_next:u32 len:u16 payload
//! ack       (cmd 0): window:u32 receiving_next:u32 timestamp:u32 count:u8 numbers:[u32; count]
//! ping      (cmd 3): sending_next:u32 receiving_next:u32 peer_rto:u32
//! terminate (cmd 2): sending_next:u32 receiving_next:u32 peer_rto:u32
//! ```
//!
//! All integers are big-endian. `option` is a bit field; [`OPTION_CLOSE`] is
//! the only bit this protocol defines and it says "the sender has closed its
//! side and is only finishing what it already queued".

use bytes::Bytes;

/// Bytes every data segment spends on framing.
pub const DATA_OVERHEAD: usize = 18;

/// Most sequence numbers one acknowledgement segment may carry. Xray caps the
/// value its MTU would allow at 128 (`transport/internet/kcp/segment.go`, an
/// `ackNumberLimit` constant) and so does this reader.
const ACK_NUMBER_LIMIT: usize = 128;

pub const CMD_ACK: u8 = 0;
pub const CMD_DATA: u8 = 1;
pub const CMD_TERMINATE: u8 = 2;
pub const CMD_PING: u8 = 3;

pub const OPTION_CLOSE: u8 = 1;

#[derive(Debug, Clone)]
pub struct DataSegment {
    pub conv: u16,
    pub option: u8,
    pub timestamp: u32,
    pub number: u32,
    pub sending_next: u32,
    pub payload: Bytes,
}

#[derive(Debug, Clone, Default)]
pub struct AckSegment {
    pub conv: u16,
    pub option: u8,
    pub receiving_window: u32,
    pub receiving_next: u32,
    pub timestamp: u32,
    pub numbers: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct CommandSegment {
    pub conv: u16,
    pub command: u8,
    pub option: u8,
    pub sending_next: u32,
    pub receiving_next: u32,
    pub peer_rto: u32,
}

#[derive(Debug, Clone)]
pub enum Segment {
    Ack(AckSegment),
    Data(DataSegment),
    Command(CommandSegment),
}

impl Segment {
    pub fn conv(&self) -> u16 {
        match self {
            Segment::Ack(s) => s.conv,
            Segment::Data(s) => s.conv,
            Segment::Command(s) => s.conv,
        }
    }

    pub fn option(&self) -> u8 {
        match self {
            Segment::Ack(s) => s.option,
            Segment::Data(s) => s.option,
            Segment::Command(s) => s.option,
        }
    }

    /// Serialize into `out`, which is cleared first. The caller owns the
    /// buffer so a driver can reuse one allocation for every segment it sends.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.clear();
        match self {
            Segment::Data(s) => {
                out.extend_from_slice(&s.conv.to_be_bytes());
                out.push(CMD_DATA);
                out.push(s.option);
                out.extend_from_slice(&s.timestamp.to_be_bytes());
                out.extend_from_slice(&s.number.to_be_bytes());
                out.extend_from_slice(&s.sending_next.to_be_bytes());
                out.extend_from_slice(&(s.payload.len() as u16).to_be_bytes());
                out.extend_from_slice(&s.payload);
            }
            Segment::Ack(s) => {
                out.extend_from_slice(&s.conv.to_be_bytes());
                out.push(CMD_ACK);
                out.push(s.option);
                out.extend_from_slice(&s.receiving_window.to_be_bytes());
                out.extend_from_slice(&s.receiving_next.to_be_bytes());
                out.extend_from_slice(&s.timestamp.to_be_bytes());
                out.push(s.numbers.len() as u8);
                for number in &s.numbers {
                    out.extend_from_slice(&number.to_be_bytes());
                }
            }
            Segment::Command(s) => {
                out.extend_from_slice(&s.conv.to_be_bytes());
                out.push(s.command);
                out.push(s.option);
                out.extend_from_slice(&s.sending_next.to_be_bytes());
                out.extend_from_slice(&s.receiving_next.to_be_bytes());
                out.extend_from_slice(&s.peer_rto.to_be_bytes());
            }
        }
    }

    /// Encoded size, used by the acknowledgement writer to decide when a
    /// segment is full before it has been serialized.
    pub fn encoded_len(&self) -> usize {
        match self {
            Segment::Data(s) => DATA_OVERHEAD + s.payload.len(),
            Segment::Ack(s) => 17 + s.numbers.len() * 4,
            Segment::Command(_) => 16,
        }
    }
}

/// Read every segment a datagram carries. A segment that does not parse ends
/// the parse: Xray treats the remainder as unusable rather than guessing.
pub fn parse(mut buf: &[u8]) -> Vec<Segment> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        match parse_one(buf) {
            Some((segment, rest)) => {
                out.push(segment);
                buf = rest;
            }
            None => break,
        }
    }
    out
}

fn parse_one(buf: &[u8]) -> Option<(Segment, &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let conv = u16::from_be_bytes([buf[0], buf[1]]);
    let command = buf[2];
    let option = buf[3];
    let body = &buf[4..];
    match command {
        CMD_DATA => {
            // Four fixed fields plus the length, then the payload. Xray asks
            // for 15 bytes before it reads 14 of them; the extra byte means a
            // segment whose payload field would be truncated still fails here.
            if body.len() < 15 {
                return None;
            }
            let timestamp = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let number = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            let sending_next = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
            let len = u16::from_be_bytes([body[12], body[13]]) as usize;
            let start: usize = 14;
            let end = start.checked_add(len)?;
            if body.len() < end {
                return None;
            }
            Some((
                Segment::Data(DataSegment {
                    conv,
                    option,
                    timestamp,
                    number,
                    sending_next,
                    payload: Bytes::copy_from_slice(&body[start..end]),
                }),
                &body[end..],
            ))
        }
        CMD_ACK => {
            if body.len() < 13 {
                return None;
            }
            let receiving_window = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let receiving_next = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            let timestamp = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
            let count = body[12] as usize;
            let start: usize = 13;
            let end = start.checked_add(count.checked_mul(4)?)?;
            if body.len() < end {
                return None;
            }
            let mut numbers = Vec::with_capacity(count.min(ACK_NUMBER_LIMIT));
            let (groups, _) = body[start..end].as_chunks::<4>();
            for chunk in groups {
                numbers.push(u32::from_be_bytes(*chunk));
            }
            Some((
                Segment::Ack(AckSegment {
                    conv,
                    option,
                    receiving_window,
                    receiving_next,
                    timestamp,
                    numbers,
                }),
                &body[end..],
            ))
        }
        command => {
            if body.len() < 12 {
                return None;
            }
            let sending_next = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let receiving_next = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            let peer_rto = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
            Some((
                Segment::Command(CommandSegment {
                    conv,
                    command,
                    option,
                    sending_next,
                    receiving_next,
                    peer_rto,
                }),
                &body[12..],
            ))
        }
    }
}

/// How many sequence numbers fit in one acknowledgement segment at this MTU.
pub fn ack_limit(mtu: u32) -> u32 {
    ((mtu.saturating_sub(17)) / 4).clamp(1, ACK_NUMBER_LIMIT as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_round_trips() {
        let segment = Segment::Data(DataSegment {
            conv: 0xBEEF,
            option: OPTION_CLOSE,
            timestamp: 7,
            number: 9,
            sending_next: 3,
            payload: Bytes::from_static(b"hello"),
        });
        let mut buf = Vec::new();
        segment.encode(&mut buf);
        assert_eq!(buf.len(), DATA_OVERHEAD + 5);
        let parsed = parse(&buf);
        assert_eq!(parsed.len(), 1);
        let Segment::Data(data) = &parsed[0] else {
            panic!("wrong variant");
        };
        assert_eq!(data.conv, 0xBEEF);
        assert_eq!(data.option, OPTION_CLOSE);
        assert_eq!(data.timestamp, 7);
        assert_eq!(data.number, 9);
        assert_eq!(data.sending_next, 3);
        assert_eq!(&data.payload[..], b"hello");
    }

    #[test]
    fn acknowledgements_round_trip_and_pack_back_to_back() {
        let ack = Segment::Ack(AckSegment {
            conv: 42,
            option: 0,
            receiving_window: 100,
            receiving_next: 12,
            timestamp: 55,
            numbers: vec![1, 2, 3, 0xFFFF_FFFF],
        });
        let data = Segment::Data(DataSegment {
            conv: 42,
            option: 0,
            timestamp: 1,
            number: 4,
            sending_next: 1,
            payload: Bytes::from_static(b"x"),
        });
        let mut buf = Vec::new();
        ack.encode(&mut buf);
        let ack_len = buf.len();
        let ack_len_expected = ack.encoded_len();
        let mut second = Vec::new();
        data.encode(&mut second);
        buf.extend_from_slice(&second);

        let parsed = parse(&buf);
        assert_eq!(parsed.len(), 2);
        let Segment::Ack(back) = &parsed[0] else {
            panic!("wrong variant");
        };
        assert_eq!(back.numbers, vec![1, 2, 3, 0xFFFF_FFFF]);
        assert_eq!(ack_len, ack_len_expected);
        assert!(matches!(parsed[1], Segment::Data(_)));
    }

    #[test]
    fn a_truncated_segment_ends_the_parse() {
        let mut buf = Vec::new();
        Segment::Command(CommandSegment {
            conv: 1,
            command: CMD_PING,
            option: 0,
            sending_next: 1,
            receiving_next: 2,
            peer_rto: 100,
        })
        .encode(&mut buf);
        buf.truncate(buf.len() - 1);
        assert!(parse(&buf).is_empty());
    }

    #[test]
    fn a_bad_length_field_ends_the_parse() {
        let mut buf = vec![0u8; 4];
        buf.extend_from_slice(&7u32.to_be_bytes());
        buf.extend_from_slice(&7u32.to_be_bytes());
        buf.extend_from_slice(&7u32.to_be_bytes());
        buf.extend_from_slice(&500u16.to_be_bytes());
        assert!(parse(&buf).is_empty());
    }

    #[test]
    fn the_ack_limit_matches_the_mtu_and_the_cap() {
        assert_eq!(ack_limit(1350), 128);
        assert_eq!(ack_limit(576), 128);
        assert_eq!(ack_limit(100), 20);
    }

    #[test]
    fn the_wire_vectors_match_xray_byte_for_byte() {
        // Captured from the Go reference's own segment structs, so a
        // reordering of a field fails here rather than at a peer.
        let data = Segment::Data(DataSegment {
            conv: 1,
            option: 0,
            timestamp: 3,
            number: 4,
            sending_next: 5,
            payload: Bytes::from_static(b"abcd"),
        });
        let mut wire = Vec::new();
        data.encode(&mut wire);
        assert_eq!(
            hex(&wire),
            "00010100000000030000000400000005000461626364"
        );

        let ack = Segment::Ack(AckSegment {
            conv: 1,
            option: 0,
            receiving_window: 2,
            receiving_next: 3,
            timestamp: 10,
            numbers: vec![1, 3, 5, 7, 9],
        });
        ack.encode(&mut wire);
        assert_eq!(
            hex(&wire),
            "0001000000000002000000030000000a050000000100000003000000050000000700000009"
        );

        let command = Segment::Command(CommandSegment {
            conv: 1,
            command: CMD_PING,
            option: OPTION_CLOSE,
            sending_next: 11,
            receiving_next: 13,
            peer_rto: 15,
        });
        command.encode(&mut wire);
        assert_eq!(hex(&wire), "000103010000000b0000000d0000000f");

        // And the same bytes parse back into the values that produced them.
        assert!(matches!(parse(&wire).as_slice(), [Segment::Command(parsed)]
            if parsed.command == CMD_PING && parsed.option == OPTION_CLOSE
                && parsed.sending_next == 11 && parsed.receiving_next == 13));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
