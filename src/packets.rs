use std::{mem::size_of, str::from_utf8};

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
        block_date: &'a str,
    },
}

impl Packet<'_> {
    /// Returns a `constant`, when the packet is server-side.
    /// Otherwise returns the valued contained in `packet_type`.
    pub fn get_type(&self) -> i16 {
        match self {
            Packet::CaLogin { packet_type, .. } => *packet_type,
            Packet::AcRefuseLogin { .. } => 0x6a,
        }
    }
}

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

pub fn from_bytes<'a, T>(bytes: &'a [u8]) -> &'a T {
    unsafe {
        let packet_bytes = &bytes[0..size_of::<T>()];
        let pointer: *const u8 = packet_bytes.as_ptr();

        match pointer.cast::<T>().as_ref() {
            Some(reference) => reference,
            None => panic!("INVALID_PACKET_CAST"),
        }
    }
}

pub fn to_bytes<'a>(packet: Packet, buffer: &mut [u8]) -> Result<usize, PacketError> {
    let packet_type = packet.get_type();

    match packet {
        Packet::AcRefuseLogin {
            error_code,
            block_date,
        } => {
            let length = 23;

            if buffer.len() >= length {
                let packet_type_bytes = packet_type.to_le_bytes();
                let block_data_bytes = block_date.as_bytes();

                buffer[0] = packet_type_bytes[0];
                buffer[1] = packet_type_bytes[1];
                buffer[2] = error_code;

                // [u8; 20]
                for i in 0..block_data_bytes.len() {
                    if i >= 20 {
                        break;
                    }

                    buffer[3 + i] = block_data_bytes[i];
                }

                Ok(length)
            } else {
                Err(PacketError {
                    message: format!("BUFFER_TOO_SMALL (must be at least {} bytes long)", length),
                })
            }
        }
        _ => Err(PacketError {
            message: format!("INVALID_PACKET_CAST (must be server-side packet)"),
        }),
    }
}

pub fn get_max_index_slice(bytes: &[u8]) -> usize {
    let length = bytes.len();
    let mut result = 0;

    for i in 0..length {
        if bytes[i] == 0x0 {
            break;
        }

        result = result + 1;
    }

    result
}

pub fn get_string(bytes: &[u8], trim: bool) -> &str {
    let sanitized_slice = &bytes[..get_max_index_slice(bytes)];

    match from_utf8(sanitized_slice) {
        Ok(result) => trim_string(result, trim),
        Err(error) => {
            let valid_index = error.valid_up_to();
            return match from_utf8(&sanitized_slice[..valid_index]) {
                Ok(result) => trim_string(result, trim),
                Err(_) => "",
            };
        }
    }
}

pub fn trim_string(value: &str, trim: bool) -> &str {
    if trim {
        value.trim()
    } else {
        value
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
