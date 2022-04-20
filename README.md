<h1 align="center">🦀 udpsec</h1>

Secure UDP implementation in Rust

## Example

### Client

```rs
use udpsec::Socket;

use std::io::Write;
use std::net::SocketAddr;

fn input(prefix: &str) -> String {
    let mut input = String::new();

    print!("{}", prefix);
    
    std::io::stdout().flush();
    std::io::stdin().read_line(&mut input);

    input.trim().to_string()
}

fn main() {
    let local_addr = input("Local addr: ").parse::<SocketAddr>().unwrap();
    let remote_addr = input("Remote addr: ").parse::<SocketAddr>().unwrap();
    
    let mut socket = Socket::new(local_addr).unwrap();

    // Send shared secret generation request
    let mut awaiter = socket.generate_secret(remote_addr).unwrap();

    // Wait until it'll not be generated
    while let None = socket.shared_secret(remote_addr) {
        socket.recv();
    }

    // wait because sometimes result can return None
    println!("Ping: {} ms", awaiter.wait(None).unwrap().as_millis());

    // Input and send text
    loop {
        socket.send(remote_addr, input("> ").as_bytes().to_vec());
    }
}
```

### Server

```rs
use udpsec::Socket;

use std::io::Write;
use std::net::SocketAddr;

fn input(prefix: &str) -> String {
    let mut input = String::new();

    print!("{}", prefix);
    
    std::io::stdout().flush();
    std::io::stdin().read_line(&mut input);

    input.trim().to_string()
}

fn main() {
    let local_addr = input("Local addr: ").parse::<SocketAddr>().unwrap();
    
    let mut socket = Socket::new(local_addr).unwrap();

    loop {
        if let Some((from, data)) = socket.recv() {
            println!("[{}] {}", from, String::from_utf8(data).unwrap());
        }
    }
}
```

### Custom data encoder/decoder

```rs
let mut socket = Socket::new(local_addr).unwrap();

socket.set_encoder(|data, key| {
    // somehow encode data

    data
});

socket.set_decoder(|data, key| {
    // somehow decode data

    data
});
```

Author: [Nikita Podvirnyy](https://vk.com/technomindlp)

Licensed under [GNU GPL 3.0](LICENSE)
