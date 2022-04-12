use std::collections::HashMap;
use std::net::{UdpSocket, SocketAddr};
use std::io::{ErrorKind, Error};

use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, ReusableSecret};

pub use rand_core;
pub use x25519_dalek;

mod tests;

pub const CHECKSUM_LENGTH: usize = 4;

/// Maximal amount of bytes you can send with `Socket.send()` method
/// 
/// - 1 byte is reserved by the packet type
/// - `CHECKSUM_LENGTH` bytes are reserved by the `get_checksum()`
pub const DATAGRAM_MAX_LENGTH: usize = 65506 - CHECKSUM_LENGTH;

fn rand_u32() -> u32 {
    OsRng::default().next_u32()
}

fn rand_u8() -> u8 {
    (rand_u32() % 256) as u8
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Packet {
    KeyExchangeInit(PublicKey),
    KeyExchangeDone(PublicKey),
    Datagram(Vec<u8>)
}

impl Packet {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            // 0-85
            Packet::KeyExchangeInit(public_key) => {
                let mut packet = Vec::with_capacity(33);

                packet.push(rand_u8() % 86);
                packet.append(&mut public_key.as_bytes().to_vec());

                // Random noise
                for _ in 0..rand_u8() {
                    let mut rand = rand_u32();

                    while rand > 0 {
                        packet.push((rand % 256) as u8);

                        rand /= 256;
                    }
                }

                packet
            },

            // 86-170
            Packet::KeyExchangeDone(public_key) => {
                let mut packet = Vec::with_capacity(33);

                packet.push(rand_u8() % 85 + 86);
                packet.append(&mut public_key.as_bytes().to_vec());

                // Random noise
                for _ in 0..rand_u8() {
                    let mut rand = rand_u32();

                    while rand > 0 {
                        packet.push((rand % 256) as u8);

                        rand /= 256;
                    }
                }

                packet
            },

            // 171-255
            // datagram size: 65536
            Packet::Datagram(data) => {
                [vec![rand_u8() % 85 + 171], data.clone()].concat()
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Packet, Error> {
        if bytes.len() > 0 {
            if bytes[0] < 86 {
                let mut public_key = [0u8; 32];

                public_key.copy_from_slice(&bytes[1..33]);

                match PublicKey::try_from(public_key) {
                    Ok(public_key) => Ok(Packet::KeyExchangeInit(public_key)),
                    Err(_) => Err(Error::new(ErrorKind::InvalidData, "Public key decoding error"))
                }
            }

            else if bytes[0] < 171 {
                let mut public_key = [0u8; 32];

                public_key.copy_from_slice(&bytes[1..33]);

                match PublicKey::try_from(public_key) {
                    Ok(public_key) => Ok(Packet::KeyExchangeDone(public_key)),
                    Err(_) => Err(Error::new(ErrorKind::InvalidData, "Public key decoding error"))
                }
            }

            else {
                Ok(Packet::Datagram(bytes[1..].to_vec()))
            }
        }

        else {
            Err(Error::new(ErrorKind::InvalidInput, "Slice is empty"))
        }
    }
}

/// This function performs xor encoding / decoding of the input data
/// 
/// Used in both `Socket.encoder` and `Socket.decoder` by default
pub fn xor_encode(mut data: Vec<u8>, key: &[u8; 32]) -> Vec<u8> {
    for i in 0..data.len() {
        data[i] = data[i] ^ key[i % 32];
    }

    data
}

/// This function returns input value without any transformations
/// 
/// Can be used in both `Socket.encoder` and `Socket.decoder` to avoid datagrams encodings
pub fn plain_text(data: Vec<u8>, _: &[u8; 32]) -> Vec<u8> {
    data
}

/// This functions calculates checksum of the input data
fn get_checksum(data: &[u8]) -> [u8; CHECKSUM_LENGTH] {
    let mut checksum = [0; CHECKSUM_LENGTH];

    for i in 0..data.len() {
        let mut sum = u16::from(checksum[i % CHECKSUM_LENGTH]) + u16::from(data[i]);

        if sum > 255 {
            sum %= 256;
        }

        checksum[i % CHECKSUM_LENGTH] = sum as u8;
    }

    checksum
}

pub struct Socket {
    addr: SocketAddr,
    socket: UdpSocket,
    secrets: HashMap<SocketAddr, [u8; 32]>,
    floating_connections: HashMap<SocketAddr, ReusableSecret>,

    /// Datagrams encoder
    pub encoder: Box<dyn Fn(Vec<u8>, &[u8; 32]) -> Vec<u8>>,

    /// Datagrams decoder
    pub decoder: Box<dyn Fn(Vec<u8>, &[u8; 32]) -> Vec<u8>>
}

impl Socket {
    pub fn new(addr: SocketAddr) -> Result<Socket, Error> {
        match UdpSocket::bind(addr) {
            Ok(socket) => Ok(Socket {
                addr,
                socket,
                secrets: HashMap::new(),
                floating_connections: HashMap::new(),
                encoder: Box::new(xor_encode),
                decoder: Box::new(xor_encode)
            }),
            Err(err) => Err(err)
        }
    }

    pub fn from_socket(socket: UdpSocket) -> Result<Socket, Error> {
        match socket.local_addr() {
            Ok(addr) => Ok(Socket {
                socket,
                addr,
                secrets: HashMap::new(),
                floating_connections: HashMap::new(),
                encoder: Box::new(xor_encode),
                decoder: Box::new(xor_encode)
            }),
            Err(err) => Err(err)
        }
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Sets function that will encode datagrams before its transferring
    pub fn set_encoder<T: Fn(Vec<u8>, &[u8; 32]) -> Vec<u8> + 'static>(&mut self, encoder: T) {
        self.encoder = Box::new(encoder);
    }

    /// Sets function that will decode received datagrams
    pub fn set_decoder<T: Fn(Vec<u8>, &[u8; 32]) -> Vec<u8> + 'static>(&mut self, decoder: T) {
        self.decoder = Box::new(decoder);
    }

    fn write(&self, addr: SocketAddr, packet: Packet) -> Result<usize, Error> {
        self.socket.send_to(packet.to_bytes().as_slice(), addr)
    }

    fn read(&self) -> Result<(SocketAddr, Packet), Error> {
        let mut buf = [0; 65536];

        match self.socket.recv_from(&mut buf) {
            Ok((size, from)) => {
                match Packet::from_bytes(&buf[..size]) {
                    Ok(packet) => Ok((from, packet)),
                    Err(err) => Err(err)
                }
            },
            Err(err) => Err(err)
        }
    }

    /// Generate shared secret with specified remote address
    /// 
    /// ```
    /// use udpsec::Socket;
    /// 
    /// let local_addr = "127.0.0.1:50000".parse().unwrap();
    /// let remote_addr = "127.0.0.1:50001".parse().unwrap();
    /// 
    /// let mut socket_a = Socket::new(local_addr).unwrap();
    /// let mut socket_b = Socket::new(remote_addr).unwrap();
    /// 
    /// socket_a.generate_secret(remote_addr);
    /// 
    /// socket_b.recv(); // Remote client updates its state in a loop
    /// 
    /// while let None = socket_a.shared_secret(remote_addr) {
    ///     socket_a.recv();
    /// }
    /// 
    /// println!("Shared secret (local): {:?}", socket_a.shared_secret(remote_addr).unwrap());
    /// println!("Shared secret (remote): {:?}", socket_b.shared_secret(local_addr).unwrap());
    /// ```
    pub fn generate_secret(&mut self, addr: SocketAddr) -> Result<usize, Error> {
        self.floating_connections.insert(addr, ReusableSecret::new(OsRng));

        self.write(addr, Packet::KeyExchangeInit(PublicKey::from(self.floating_connections.get(&addr).unwrap())))
    }

    /// Get shared secret with a specified remote address
    /// 
    /// See `Socket.generate_secret()` for more details
    pub fn shared_secret(&self, addr: SocketAddr) -> Option<&[u8; 32]> {
        self.secrets.get(&addr)
    }

    /// Send data to remote address
    /// 
    /// Returns `false` if data couldn't be sent, or shared secret wasn't generated
    /// 
    /// ```
    /// use udpsec::Socket;
    /// 
    /// let local_addr = "127.0.0.1:50002".parse().unwrap();
    /// let remote_addr = "127.0.0.1:50003".parse().unwrap();
    /// 
    /// let mut socket_a = Socket::new(local_addr).unwrap();
    /// let mut socket_b = Socket::new(remote_addr).unwrap();
    /// 
    /// socket_a.generate_secret(remote_addr); // Send KeyExchangeInit to remote client
    /// 
    /// socket_b.recv(); // Process KeyExchangeInit packet from local client
    /// socket_a.recv(); // Receive KeyExchangeDone packet from remote client
    /// 
    /// socket_a.send(remote_addr, "Hello, World!".as_bytes().to_vec());
    /// 
    /// let received = socket_b.recv().unwrap();
    /// 
    /// println!("[{}] {}", received.0, String::from_utf8(received.1).unwrap());
    /// ```
    pub fn send(&self, addr: SocketAddr, mut data: Vec<u8>) -> Result<usize, Error> {
        match self.secrets.get(&addr) {
            Some(secret) => {
                data = [get_checksum(data.as_slice()).to_vec(), data].concat();
                data = (self.encoder)(data, secret);
                
                self.write(addr, Packet::Datagram(data))
            },
            None => Err(Error::new(ErrorKind::NotConnected, "Current socket doesn't have a shared secret with specified remote address"))
        }
    }

    /// Receive data from remote socket
    /// 
    /// See `Socket.send()` for more details
    pub fn recv(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        match self.read() {
            Ok((from, packet)) => {
                match packet {
                    Packet::KeyExchangeInit(public_key) => {
                        let secret = ReusableSecret::new(OsRng);

                        self.secrets.insert(from, *secret.diffie_hellman(&public_key).as_bytes());

                        self.write(from, Packet::KeyExchangeDone(PublicKey::from(&secret)));

                        None
                    }

                    Packet::KeyExchangeDone(public_key) => {
                        if let Some(secret) = self.floating_connections.get(&from) {
                            self.secrets.insert(from, *secret.diffie_hellman(&public_key).as_bytes());
                            
                            self.floating_connections.remove(&from);
                        }

                        None
                    }

                    Packet::Datagram(mut data) => {
                        match self.secrets.get(&from) {
                            Some(secret) => {
                                data = (self.decoder)(data, secret);

                                if get_checksum(&data[4..]) == &data[0..4] {
                                    Some((from, data[4..].to_vec()))
                                }

                                else {
                                    None
                                }
                            },
                            None => None
                        }
                    }
                }
            },
            Err(_) => None
        }
    }
}
