use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    sync::{Arc, Mutex},
};

use crate::packets::definition::{
    get_bytes, get_packet, Packet, PacketError, Server, ServerStatus, Sex,
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
                Ok(packet) => match packet {
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
                    Packet::ChEnter {
                        packet_type,
                        auth_code,
                        account_id,
                        user_level,
                        client_type,
                        sex,
                    } => {
                        let buf = [0x6c, 0x00, 0x1];
                        stream.write(&buf).unwrap();
                        println!("Sending ack..");
                    }
                    _ => println!("Debug error: INVALID_CLIENT_PACKET"),
                },
                Err(error) => println!("Debug error: {}", error.message),
            }
        } else {
            println!("Debug error: EMPTY_CLIENT_DATA");
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

        let packet = Packet::AcAcceptLogin {
            auth_code: 0,
            account_id: 1234,
            user_level: 1,
            sex: Sex::Male,
            server_list: &[Server {
                ip: Ipv4Addr::new(127, 0, 0, 1),
                port: 6900,
                name: "Urd",
                user_count: 0,
                state: ServerStatus::Normal,
                is_new: true,
            }],
        };

        if Self::send_packet(stream, packet).is_err() {
            return;
        }
    }

    pub fn send_packet(stream: &mut TcpStream, packet: Packet) -> Result<(), PacketError> {
        let mut buffer = [0; 2048];

        match get_bytes(packet, &mut buffer) {
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
