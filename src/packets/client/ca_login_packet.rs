use crate::packets::{
    definition::{Packet, PacketError},
    util::{from_bytes, get_string},
};

pub fn get_ca_login_packet(bytes: &[u8]) -> Result<Packet, PacketError> {
    let length = bytes.len();

    if length >= 55 {
        Ok(Packet::CaLogin {
            packet_type: 0x64,
            version: from_bytes::<u32>(&bytes[2..6]),
            id: get_string(&bytes[6..30], false),
            passwd: get_string(&bytes[30..54], false),
            client_type: bytes[54],
        })
    } else {
        Err(PacketError {
            message: format!("PACKET_0x{:X}_INVALID_LENGTH", 0x64),
        })
    }
}
