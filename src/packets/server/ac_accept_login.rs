use byteorder::{ByteOrder, LittleEndian};

use crate::packets::{
    definition::{PacketError, Server, ServerStatus, Sex},
    util::{write_ip, write_str},
};

pub fn ac_accept_login_to_bytes(
    buffer: &mut [u8],
    packet_type: i16,
    length: usize,
    auth_code: i32,
    account_id: u32,
    user_level: u32,
    sex: Sex,
    server_list: &[Server],
) -> Result<usize, PacketError> {
    if buffer.len() >= length {
        LittleEndian::write_i16(buffer, packet_type);
        LittleEndian::write_u16(&mut buffer[0x2..], length as u16);
        LittleEndian::write_i32(&mut buffer[0x4..], auth_code);
        LittleEndian::write_u32(&mut buffer[0x8..], account_id);
        LittleEndian::write_u32(&mut buffer[0xc..], user_level);

        if let Err(error) = match sex {
            Sex::Male => write_str(&mut buffer[0x2e..], "M"),
            Sex::Female => write_str(&mut buffer[0x2e..], "F"),
        } {
            return Err(error);
        }

        for i in 0..server_list.len() {
            let index = 0x40 + 0xA0 * i;
            let server = server_list[i];

            if let Err(error) = write_ip(&mut buffer[index..], server.ip) {
                return Err(error);
            }

            LittleEndian::write_u16(&mut buffer[index + 0x4..], server.port);

            if let Err(error) = write_str(&mut buffer[index + 0x6..], server.name) {
                return Err(error);
            }

            LittleEndian::write_u16(&mut buffer[index + 0x1a..], server.user_count);
            LittleEndian::write_u16(
                &mut buffer[index + 0x1c..],
                match server.state {
                    ServerStatus::Normal => 0,
                    ServerStatus::Maintenance => 1,
                    ServerStatus::Over18 => 2,
                    ServerStatus::Paying => 3,
                    ServerStatus::P2P => 4,
                },
            );
            LittleEndian::write_u16(
                &mut buffer[index + 0x1e..],
                match server.is_new {
                    true => 1,
                    false => 0,
                },
            );
        }

        Ok(length)
    } else {
        Err(PacketError {
            message: format!("BUFFER_TOO_SMALL (must be at least {} bytes long)", length),
        })
    }
}
