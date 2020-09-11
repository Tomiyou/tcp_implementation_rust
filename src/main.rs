use std::io;
use std::collections::HashMap;
use std::net::Ipv4Addr;

mod tcp;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    let tunnel = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Error opening tun_tap tunnel");
    let mut buf = [0u8; 1504];

    loop {
        let bytes_read = tunnel.recv(&mut buf[..])?;
        // let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        // println!("Eth {:x?}", &buf[0..4]);
        
        if eth_proto != 0x800 {
            // skip non IPv4 packets
            continue;
        }

        // parse IPv4 packet header
        let ip_header = match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..bytes_read]) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Unable to read IPv4 packet, skipping! {:?}", e);
                continue;
            }
        };
    
        // skip non TCP packets
        if ip_header.protocol() != 0x6 {
            continue;
        }

        // ip header size
        let iph_size = ip_header.slice().len();

        // parse TCP packet header
        let tcp_header = match etherparse::TcpHeaderSlice::from_slice(
            &buf[4 + iph_size..bytes_read],
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Unable to read TCP packet, skipping! {:?}", e);
                continue;
            }
        };

        // beginning of TCP payload within buf
        let datai = 4 + iph_size + tcp_header.slice().len();
        
        // find the appropriate connection from the hashmap
        let connection = connections.entry(Quad {
            src: (ip_header.source_addr(), tcp_header.source_port()),
            dst: (ip_header.destination_addr(), tcp_header.destination_port()),
        }).or_default();
        connection.accept(&tunnel, ip_header, tcp_header, &buf[datai..bytes_read])?;
    }
}
