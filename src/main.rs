use std::{
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex},
    thread::spawn,
};

use login_server::LoginServer;

// use crate::packets::{get_packet, panic_expected_packet, Packet};

pub mod login_server;
pub mod packets;

#[macro_use] extern crate log;

fn main() {
    let addr = "0.0.0.0:6900".parse::<SocketAddr>().unwrap();
    let listener = TcpListener::bind(addr).unwrap();
    let login_server = Arc::new(Mutex::new(LoginServer::new()));

    loop {
        match listener.accept() {
            Ok((mut stream, address)) => {
                println!("Received connection from remote host: {}", address);
                let server_copy = Arc::clone(&login_server);

                spawn(move || {
                    LoginServer::receive_data(server_copy, &mut stream, &address);
                });
            }
            Err(_) => println!("Could not estabilish connection. Socket error."),
        }
    }
}
