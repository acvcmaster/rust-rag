use std::net::Ipv4Addr;

use crate::packets::{client::{ca_login_packet::get_ca_login_packet, ch_enter_packet::get_ch_enter}, server::{
        ac_accept_login::ac_accept_login_to_bytes, ac_refuse_login::ac_refuse_login_to_bytes,
        sc_notify_ban::sc_notify_ban_to_bytes,
    }};

use super::{
    server::{ac_refuse_login::RefuseLoginReason, sc_notify_ban::NotifyBanReason},
    util::from_bytes,
};

#[derive(Debug, Clone, Copy)]
pub enum Sex {
    Male,
    Female,
}

#[derive(Debug, Clone, Copy)]
pub enum ServerStatus {
    Normal,
    Maintenance,
    Over18,
    Paying,
    P2P,
}

#[derive(Debug, Clone, Copy)]
pub struct Server<'a> {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub name: &'a str,
    pub user_count: u16,
    pub state: ServerStatus,
    pub is_new: bool,
}

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
        error_code: RefuseLoginReason,
        block_date: Option<&'a str>,
    },
    ScNotifyBan {
        error_code: NotifyBanReason, // 1: Server Closed, 2: Already logged-in, 8: Already online
    },
    AcAcceptLogin {
        auth_code: i32,
        account_id: u32,
        user_level: u32,
        sex: Sex,
        server_list: &'a [Server<'a>],
    },
    ChEnter {
        packet_type: i16,
        account_id: u32,
        auth_code: i32,
        user_level: u32,
        client_type: i16,
        sex: &'a str,
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
            Packet::AcAcceptLogin { .. } => 0xac4,
            Packet::ChEnter { packet_type, .. } => *packet_type,
        }
    }

    /// Returns the packet length for variable-length packets.
    /// Otherwise returns `0`.
    pub fn get_length(&self) -> usize {
        match self {
            Packet::AcAcceptLogin { server_list, .. } => 0x40 + 0xA0 * (*server_list).len(),
            _ => 0,
        }
    }
}

#[derive(Debug)]
pub struct PacketError {
    pub message: String,
}

pub fn get_packet(bytes: &[u8]) -> Result<Packet, PacketError> {
    let packet_type = from_bytes::<i16>(bytes);

    match packet_type {
        0x64 => get_ca_login_packet(bytes),
        0x65 => get_ch_enter(bytes),
        _ => Err(PacketError {
            message: format!("UNKNOWN_PACKET_0x{:X}", packet_type),
        }),
    }
}

pub fn get_bytes(packet: Packet, buffer: &mut [u8]) -> Result<usize, PacketError> {
    let packet_type = packet.get_type();
    let packet_len = packet.get_length();

    match packet {
        Packet::AcRefuseLogin {
            error_code,
            block_date,
        } => ac_refuse_login_to_bytes(buffer, packet_type, error_code, block_date),
        Packet::ScNotifyBan { error_code } => {
            sc_notify_ban_to_bytes(buffer, packet_type, error_code)
        }
        Packet::AcAcceptLogin {
            auth_code,
            account_id,
            user_level,
            sex,
            server_list,
        } => ac_accept_login_to_bytes(
            buffer,
            packet_type,
            packet_len,
            auth_code,
            account_id,
            user_level,
            sex,
            server_list,
        ),
        _ => Err(PacketError {
            message: format!("INVALID_PACKET_CAST (must be server-side packet)"),
        }),
    }
}
