use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
};

use crate::packets::{get_packet, to_bytes, Packet, PacketError};

#[derive(Debug, Clone)]
pub struct LoginServer {
    logged_accounts: Vec<String>,
}

impl LoginServer {
    pub fn new() -> Self {
        Self {
            logged_accounts: vec![],
        }
    }

    pub fn receive_data(
        login_server: Arc<Mutex<Self>>,
        stream: &mut TcpStream,
        address: &SocketAddr,
    ) {
        let mut empty = 0;

        loop {
            if empty >= 5 {
                println!(
                    "Connection dropped. The client {} appears to have disconected from the server.",
                    address
                );
                break;
            }

            let server_copy = Arc::clone(&login_server);
            let mut buffer: [u8; 512] = [0; 512];

            match stream.read(&mut buffer) {
                Ok(length) => {
                    Self::handle_packets(server_copy, stream, &address, &buffer, length, &mut empty)
                }
                Err(_) => println!("UNHANDLED_RECEIVE_ERROR"),
            }
        }
    }

    pub fn handle_packets(
        login_server: Arc<Mutex<Self>>,
        stream: &mut TcpStream,
        address: &SocketAddr,
        buffer: &[u8],
        length: usize,
        empty: &mut i32,
    ) {
        if length > 2 {
            match get_packet(buffer) {
                crate::packets::Packet::CaLogin {
                    packet_type,
                    version,
                    id,
                    passwd,
                    client_type,
                } => Self::handle_login(
                    login_server,
                    stream,
                    address,
                    version,
                    id,
                    passwd,
                    client_type,
                ),
                _ => debug!("Debug error: INVALID_CLIENT_PACKET"),
            }
        } else {
            debug!("Debug error: EMPTY_CLIENT_DATA");
            *empty = *empty + 1;
        }
    }

    pub fn handle_login(
        login_server: Arc<Mutex<Self>>,
        stream: &mut TcpStream,
        address: &SocketAddr,
        version: u32,
        id: &str,
        passwd: &str,
        client_type: u8,
    ) {
        println!("Received login from account '{}' at {}.", id, address);

        let a = Self::send_packet(
            stream,
            Packet::AcRefuseLogin {
                error_code: 3,
                block_date: ""
            },
        );
    }

    pub fn send_packet(stream: &mut TcpStream, packet: Packet) -> Result<(), PacketError> {
        let mut buffer = [0; 512];

        match to_bytes(packet, &mut buffer) {
            Ok(size) => match stream.write(&buffer[..size]) {
                Ok(_) => Ok(()),
                Err(_) => Err(PacketError {
                    message: format!("STREAM_WRITE_ERROR"),
                }),
            },
            Err(error) => Err(error),
        }
    }
}
