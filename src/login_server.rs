use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
};

use crate::packets::{
    definition::{get_packet, to_bytes, Packet, PacketError},
    server::sc_notify_ban::NotifyBanReason,
};

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
                Packet::CaLogin {
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
        // Self::send_packet(stream, Packet::AcRefuseLogin { error_code: 6, block_date: Some("2021-12-31 15:35:51") });

        // let a = [
        //     0x04, 0xAC, 0x4F, 0x2, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
        //     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        //     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 8, 39, 1, 10, 0xFA,
        //     0x1A, 0x44, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x53,
        //     0x65, 0x72, 0x76, 0x65, 0x72, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        // ];

        // let b = [
        //     0x04, 0xAC, 0x4F, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
        //     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        //     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4D, 8, 39, 1, 10, 0xFA,
        //     0x1A, 0x44, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x53,
        //     0x65, 0x72, 0x76, 0x65, 0x72, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        // ];

        // Self::print_packet(&b);

        // match stream.write(&b) {
        //     Ok(_) => println!("DATA SENT!!"),
        //     Err(_) => println!("ERROR!"),
        // }
    }

    pub fn send_packet(stream: &mut TcpStream, packet: Packet) -> Result<(), PacketError> {
        let mut buffer = [0; 512];

        match to_bytes(packet, &mut buffer) {
            Ok(size) => match stream.write(&buffer[..size]) {
                Ok(_) => {
                    Self::print_packet(&buffer[..size]);
                    Ok(())
                }
                Err(_) => Err(PacketError {
                    message: format!("STREAM_WRITE_ERROR"),
                }),
            },
            Err(error) => Err(error),
        }
    }

    pub fn print_packet(buffer: &[u8]) {
        print!("Packet: ");

        for data in buffer {
            let mut result = format!("{:X}", data);

            result = if result.len() == 1 {
                format!("0{}", result)
            } else {
                result
            };

            print!("{} ", result);
        }

        println!();
    }
}
