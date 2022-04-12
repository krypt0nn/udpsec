use super::{rand_u8, xor_encode};
use super::{Packet, Socket};
use super::DATAGRAM_MAX_LENGTH;

use super::rand_core::OsRng;
use super::x25519_dalek::{PublicKey, ReusableSecret};

use std::net::SocketAddr;

fn get_socket() -> Socket {
    let rand_port = 50000 + rand_u8() as u16 * 10;

    match Socket::new(SocketAddr::new("127.0.0.1".parse().unwrap(), rand_port)) {
        Ok(socket) => socket,
        Err(_) => get_socket()
    }
}

fn get_sockets_pair() -> (Socket, Socket) {
    (get_socket(), get_socket())
}

fn get_rand_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);

    for _ in 0..size {
        data.push(rand_u8());
    }

    data
}

#[test]
fn test_packets() {
    let secret = ReusableSecret::new(OsRng);
    let public = PublicKey::from(&secret);

    let packet = Packet::KeyExchangeInit(public);
    let decoded = Packet::from_bytes(packet.to_bytes().as_slice()).expect("Couldn't decode KeyExchangeInit packet");

    assert_eq!(packet, decoded);
    
    let packet = Packet::KeyExchangeDone(public);
    let decoded = Packet::from_bytes(packet.to_bytes().as_slice()).expect("Couldn't decode KeyExchangeDone packet");

    assert_eq!(packet, decoded);

    let data = get_rand_data(u16::MAX as usize - 64);
    
    let packet = Packet::Datagram(data);
    let decoded = Packet::from_bytes(packet.to_bytes().as_slice()).expect("Couldn't decode Datagram packet");

    assert_eq!(packet, decoded);
}

#[test]
fn test_datagrams() {
    let (socket_a, socket_b) = get_sockets_pair();

    let data = get_rand_data(u16::MAX as usize - 64);

    socket_a.write(socket_b.addr(), Packet::Datagram(data.clone())).expect("Couldn't send datagram to socket_b");

    let received = socket_b.read().expect("Couldn't receive datagram from socket_a");

    assert_eq!(received.0, socket_a.addr());
    assert_eq!(received.1, Packet::Datagram(data.clone()));
}

#[test]
fn test_key_exchange() {
    let (mut socket_a, mut socket_b) = get_sockets_pair();

    socket_a.generate_secret(socket_b.addr()).expect("Couldn't send key exchange request to socket_b");

    socket_b.recv();
    socket_a.recv();

    let shared_a = socket_a.shared_secret(socket_b.addr()).expect("Couldn't generate shared secret with socket_b");
    let shared_b = socket_b.shared_secret(socket_a.addr()).expect("Couldn't generate shared secret with socket_a");

    assert_eq!(shared_a, shared_b);
}

#[test]
fn test_xor_encoding() {
    let mut key = [0u8; 32];

    for i in 0..32 {
        key[i] = rand_u8();
    }

    let data = get_rand_data(u16::MAX as usize);

    assert_eq!(xor_encode(xor_encode(data.clone(), &key), &key), data);
    assert_ne!(xor_encode(data.clone(), &key), data);
}
