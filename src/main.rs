use std::io;

fn main() -> io::Result<()> {
    let tunnel = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("");
    let mut buf = [0u8; 1504];

    loop {
        let bytes_read = tunnel.recv(&mut buf[..])?;
        let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_proto != 0x800 {
            // skip non IPv4 packets
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..bytes_read]) {
            Ok(p) => {
                println!(
                    "received {} -> {} : {}bytes of protocol {}",
                    p.source_addr(),
                    p.destination_addr(),
                    p.total_len(),
                    p.protocol()
                );
            },
            Err(e) => {
                eprintln!("Unable to read IPv4 packet, skipping! {:?}", e);
            }
        }
    }
}
