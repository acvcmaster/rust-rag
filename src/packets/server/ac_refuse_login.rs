use byteorder::{ByteOrder, LittleEndian};

use crate::packets::{definition::{PacketError}, util::write_str};

pub fn ac_refuse_login_to_bytes(
    buffer: &mut [u8],
    packet_type: i16,
    error_code: u8,
    block_date: Option<&str>,
) -> Result<usize, PacketError> {
    let length = 23;

    if buffer.len() >= length {
        LittleEndian::write_i16(&mut buffer[0..], packet_type);
        buffer[2] = error_code;

        if let Some(value) = block_date {
            if let Err(error) = write_str(&mut buffer[3..], value) {
                return Err(error);
            }
        }

        Ok(length)
    } else {
        Err(PacketError {
            message: format!("BUFFER_TOO_SMALL (must be at least {} bytes long)", length),
        })
    }
}
