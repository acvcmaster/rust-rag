use std::{mem::size_of, net::Ipv4Addr, str::from_utf8};

use super::definition::PacketError;

pub fn from_bytes<T>(bytes: &[u8]) -> T
where
    T: Default + Copy,
{
    unsafe {
        let packet_bytes = &bytes[0..size_of::<T>()];
        let pointer: *const u8 = packet_bytes.as_ptr();

        match pointer.cast::<T>().as_ref() {
            Some(reference) => *reference,
            None => T::default(),
        }
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

pub fn write_str(buffer: &mut [u8], data: &str) -> Result<usize, PacketError> {
    let buffer_len = buffer.len();
    let data_buffer = data.as_bytes();
    let data_len = data_buffer.len();

    if data_len <= buffer_len {
        for i in 0..data_len {
            buffer[i] = data_buffer[i];
        }
        Ok(data_len)
    } else {
        Err(PacketError {
            message: format!(
                "WRITE_STR_BUFFER_TOO_SMALL (must be at least {} bytes long)",
                data_len
            ),
        })
    }
}

pub fn write_mem(target: &mut [u8], source: &[u8]) -> Result<usize, PacketError> {
    let target_len = target.len();
    let source_len = source.len();

    if target_len >= source_len {
        for i in 0..source_len {
            target[i] = source[i];
        }
        Ok(source_len)
    } else {
        Err(PacketError {
            message: format!(
                "WRITE_MEM_BUFFER_TOO_SMALL (must be at least {} bytes long)",
                source_len
            ),
        })
    }
}

pub fn write_ip(buffer: &mut [u8], ip: Ipv4Addr) -> Result<usize, PacketError> {
    let mut octets = ip.octets();
    octets.reverse(); // fixing byte order

    write_mem(buffer, &octets)
}
