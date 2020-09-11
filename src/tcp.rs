pub struct Connection {}

impl Default for Connection {
    fn default() -> Self {
        Connection {}
    }
}

impl Connection {
    pub fn accept<'a>(
        &mut self,
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) {
        println!(
            "{}    {}:{} -> {}:{}      {} bytes",
            ip_header.protocol(),
            ip_header.source_addr(),
            tcp_header.source_port(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            data.len()
        );
    }
}
