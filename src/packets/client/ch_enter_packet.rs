use crate::packets::{
    definition::{Packet, PacketError},
    util::{from_bytes, get_string},
};

pub fn get_ch_enter(bytes: &[u8]) -> Result<Packet, PacketError> {
    let length = bytes.len();

    if length >= 0x11 {
        Ok(Packet::ChEnter {
            packet_type: 0x65,
            account_id: from_bytes::<u32>(&bytes[2..6]),
            auth_code: from_bytes::<i32>(&bytes[6..10]),
            user_level: from_bytes::<u32>(&bytes[10..14]),
            client_type: from_bytes::<i16>(&bytes[14..16]),
            sex: get_string(&bytes[16..], false),
        })
    } else {
        Err(PacketError {
            message: format!("PACKET_0x{:X}_INVALID_LENGTH", 0x65),
        })
    }
}
