use std::io;

pub struct Connection {}

impl Default for Connection {
    fn default() -> Self {
        Connection {}
    }
}

impl Connection {
    fn write(
        &mut self,
        ip_header: etherparse::Ipv4Header,
        tcp_header: etherparse::TcpHeader,
        net_ifc: &tun_tap::Iface,
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1504];
        buf[2] = 0x8;

        let bytes_written = {
            let mut buf = &mut buf[4..];
            ip_header
                .write(&mut buf)
                .expect("Unable to write IP packet to interface");
            tcp_header
                .write(&mut buf)
                .expect("Unable to write TCP packet to interface");
            1504 - buf.len()
        };

        net_ifc.send(&buf[..bytes_written])
    }

    pub fn accept<'a>(
        &mut self,
        net_ifc: &tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<usize> {
        if !tcp_header.syn() {
            // only accept SYN packets at this point
            return Ok(0)
        }

        let source = [
            ip_header.source()[0],
            ip_header.source()[1],
            ip_header.source()[2],
            ip_header.source()[3],
        ];
        let destination = [
            ip_header.destination()[0],
            ip_header.destination()[1],
            ip_header.destination()[2],
            ip_header.destination()[3],
        ];

        // create TCP packet
        let mut syn_ack = etherparse::TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            0,
            500,
        );
        syn_ack.syn = true;
        syn_ack.ack = true;

        // create IP packet
        let ipp = etherparse::Ipv4Header::new(
            syn_ack.header_len(),
            64,
            etherparse::IpTrafficClass::Tcp,
            destination,
            source,
        );

        self.write(ipp, syn_ack, net_ifc)
    }
}
