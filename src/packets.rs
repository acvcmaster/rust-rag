use std::{mem::size_of, str::from_utf8};

#[repr(packed(1))]
#[derive(Debug, Clone, Copy)]
pub struct PacketCaLogin {
    pub packet_type: i16,
    pub version: u32,
    pub id: [u8; 24],
    pub passwd: [u8; 24],
    pub client_type: u8,
}

pub fn extract_packet_type(bytes: &[u8]) {

}

pub fn packet_from_bytes<T>(bytes: &[u8]) -> T
where
    T: Copy,
{
    unsafe {
        let packet_bytes = &bytes[0..size_of::<T>()];
        let pointer: *const u8 = packet_bytes.as_ptr();

        match pointer.cast::<T>().as_ref() {
            Some(reference) => *reference,
            None => panic!("INVALID_PACKET_CAST"),
        }
    }
}

pub fn get_string(bytes: &[u8], trim: bool) -> &str {
    match from_utf8(bytes) {
        Ok(result) => {
            if trim {
                result.trim()
            } else {
                result
            }
        }
        Err(_) => "",
    }
}
