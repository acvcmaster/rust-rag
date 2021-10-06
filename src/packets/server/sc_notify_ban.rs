use byteorder::{ByteOrder, LittleEndian};

use crate::packets::definition::PacketError;

#[derive(Debug, Clone, Copy)]
pub enum NotifyBanReason {
    ServerClosed,         // 1
    AlreadyLoggedIn,      // 2
    LoginStillRecognized, // 8
}

pub fn sc_notify_ban_to_bytes(
    buffer: &mut [u8],
    packet_type: i16,
    error_code: NotifyBanReason,
) -> Result<usize, PacketError> {
    let length = 3;

    if buffer.len() >= length {
        LittleEndian::write_i16(&mut buffer[0..], packet_type);

        buffer[2] = match error_code {
            NotifyBanReason::ServerClosed => 1,
            NotifyBanReason::AlreadyLoggedIn => 2,
            NotifyBanReason::LoginStillRecognized => 8,
        };

        Ok(length)
    } else {
        Err(PacketError {
            message: format!("BUFFER_TOO_SMALL (must be at least {} bytes long)", length),
        })
    }
}
