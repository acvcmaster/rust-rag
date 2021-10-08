use byteorder::{ByteOrder, LittleEndian};

use crate::packets::{definition::PacketError, util::write_str};

#[derive(Debug, Clone, Copy)]
pub enum RefuseLoginReason {
    UnregisteredId,       // 0
    IncorrectIdPassword,  // 1
    IdExpired,            // 2
    AccountBlocked,       // 4
    ExeNotLatestVersion,  // 5
    LoginProhibitedUntil, // 6
    ServerOverpopulation, // 7
    CantConnectSakray,    // 8
}

pub fn ac_refuse_login_to_bytes(
    buffer: &mut [u8],
    packet_type: i16,
    error_code: RefuseLoginReason,
    block_date: Option<&str>,
) -> Result<usize, PacketError> {
    let length = 23;

    if buffer.len() >= length {
        LittleEndian::write_i16(&mut buffer[0..], packet_type);

        buffer[2] = match error_code {
            RefuseLoginReason::UnregisteredId => 0,
            RefuseLoginReason::IncorrectIdPassword => 1,
            RefuseLoginReason::IdExpired => 2,
            RefuseLoginReason::AccountBlocked => 4,
            RefuseLoginReason::ExeNotLatestVersion => 5,
            RefuseLoginReason::LoginProhibitedUntil => 6,
            RefuseLoginReason::ServerOverpopulation => 7,
            RefuseLoginReason::CantConnectSakray => 8,
        };

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
