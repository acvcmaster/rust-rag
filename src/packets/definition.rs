use crate::packets::server::{
    ac_refuse_login::ac_refuse_login_to_bytes, sc_notify_ban::sc_notify_ban_to_bytes,
};

use super::{
    server::sc_notify_ban::NotifyBanReason,
    util::{from_bytes, get_string},
};

#[derive(Debug, Clone, Copy)]
pub enum Packet<'a> {
    CaLogin {
        packet_type: i16,
        version: u32,
        id: &'a str,
        passwd: &'a str,
        client_type: u8,
    },
    AcRefuseLogin {
        error_code: u8,
        block_date: Option<&'a str>,
    },
    ScNotifyBan {
        error_code: NotifyBanReason, // 1: Server Closed, 2: Already logged-in, 8: Already online
    },
}

impl Packet<'_> {
    /// Returns a `constant`, when the packet is server-side.
    /// Otherwise returns the valued contained in `packet_type`.
    pub fn get_type(&self) -> i16 {
        match self {
            Packet::CaLogin { packet_type, .. } => *packet_type,
            Packet::AcRefuseLogin { .. } => 0x6a,
            Packet::ScNotifyBan { .. } => 0x81,
        }
    }
}

#[derive(Debug)]
pub struct PacketError {
    pub message: String,
}

pub fn get_packet(bytes: &[u8]) -> Packet {
    let length = bytes.len();
    let packet_type = *from_bytes::<i16>(bytes);

    match packet_type {
        0x64 => {
            if length >= 55 {
                Packet::CaLogin {
                    packet_type,
                    version: *from_bytes::<u32>(&bytes[2..6]),
                    id: get_string(&bytes[6..30], false),
                    passwd: get_string(&bytes[30..54], false),
                    client_type: bytes[54],
                }
            } else {
                panic_invalid_length(packet_type)
            }
        }
        _ => panic_unknown_packet(packet_type),
    }
}

pub fn to_bytes(packet: Packet, buffer: &mut [u8]) -> Result<usize, PacketError> {
    let packet_type = packet.get_type();

    match packet {
        Packet::AcRefuseLogin {
            error_code,
            block_date,
        } => ac_refuse_login_to_bytes(buffer, packet_type, error_code, block_date),
        Packet::ScNotifyBan { error_code } => {
            sc_notify_ban_to_bytes(buffer, packet_type, error_code)
        }
        _ => Err(PacketError {
            message: format!("INVALID_PACKET_CAST (must be server-side packet)"),
        }),
    }
}

// Errors
pub fn panic_invalid_length(packet_type: i16) -> ! {
    panic!("PACKET_0x{:X}_INVALID_LENGTH", packet_type)
}

pub fn panic_unknown_packet(packet_type: i16) -> ! {
    panic!("UNKNOWN_PACKET_0x{:X}", packet_type)
}

pub fn panic_expected_packet(packet_name: &str) -> ! {
    panic!("EXPECTED_PACKET_{}", packet_name)
}
