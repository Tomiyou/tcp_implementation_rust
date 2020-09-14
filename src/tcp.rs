use std::io;

pub struct Connection {
    state: State,
    send: SendTCB,
    recv: RecvTCB,
    ipp: etherparse::Ipv4Header,
    tcpp: etherparse::TcpHeader,
}

enum State {
    Closed,
    Listen,
    SynRcvd,
    SynSent,
    Estab,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::Listen => false,
            State::SynRcvd => false,
            State::SynSent => false,
            _ => true,
        }
    }
}

struct SendTCB {
    una: u32,
    nxt: u32,
    wnd: u16,
    up: bool,
    iss: u32,
}

struct RecvTCB {
    nxt: u32,
    wnd: u16,
    up: bool,
    irs: u32,
}

impl Connection {
    fn write(&mut self, net_ifc: &tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        // create buffer for writing
        const buf_len: usize = 1504;
        let mut buf = [0u8; buf_len];
        buf[2] = 0x8;

        // calculate size we can fit into buffer
        let size = std::cmp::min(
            buf_len,
            self.ipp.header_len() + self.tcpp.header_len() as usize + payload.len(),
        );

        // handle TCP flags and numbers
        self.tcpp.sequence_number = self.send.nxt;
        self.tcpp.acknowledgment_number = self.recv.nxt;
        self.tcpp.checksum = self
            .tcpp
            .calc_checksum_ipv4(&self.ipp, payload)
            .expect("Unable to calculate tcpp checksum");
        self.ipp
            .set_payload_len(size)
            .expect("Unable to set payload length");

        // start of slice moves with each write
        use std::io::Write;
        let mut _buf = &mut buf[4..];
        // write IP packet
        self.ipp
            .write(&mut _buf)
            .expect("Unable to write IP packet to interface");
        // write TCP packet
        self.tcpp
            .write(&mut _buf)
            .expect("Unable to write TCP packet to interface");
        // write payload
        let payload_bytes = _buf.write(payload)?;

        // increment send's next sequence number
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcpp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcpp.syn = false;
        }
        if self.tcpp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcpp.fin = false;
        }

        // this works as long as start of slice moves with each write
        let bytes_written = buf_len - _buf.len();
        net_ifc.send(&buf[..bytes_written])
    }

    pub fn accept<'a>(
        net_ifc: &tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
    ) -> io::Result<Option<Self>> {
        if !tcp_header.syn() {
            // only accept SYN packets at this point
            return Ok(None);
        }

        let iss = 0;
        let wnd = 500;
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
        // create a connection with state
        let mut conn = Connection {
            state: State::SynRcvd,
            send: SendTCB {
                iss,
                wnd,
                una: iss,
                nxt: iss,
                up: false,
            },
            recv: RecvTCB {
                irs: tcp_header.sequence_number(),
                nxt: tcp_header.sequence_number().wrapping_add(1),
                wnd: tcp_header.window_size(),
                up: false,
            },
            ipp: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                destination,
                source,
            ),
            tcpp: etherparse::TcpHeader::new(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                iss,
                wnd,
            ),
        };

        // create TCP packet
        conn.tcpp.syn = true;
        conn.tcpp.ack = true;

        conn.write(net_ifc, &[])?;
        Ok(Some(conn))
    }

    pub fn on_packet<'a>(
        &mut self,
        net_ifc: &tun_tap::Iface,
        ip_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // first determine if the packet we received is valid
        let ackn = tcp_header.acknowledgment_number();
        let seqn = tcp_header.sequence_number();
        let wnd_end = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let nxt_1 = self.recv.nxt.wrapping_sub(1);
        let mut seg_len = data.len() as u32;
        if tcp_header.syn() {
            seg_len += 1;
        }
        if tcp_header.fin() {
            seg_len += 1;
        }

        // A segment is judged to occupy a portion of valid receive sequence space if
        // Segment Receive  Test
        // Length  Window
        // ------- -------  -------------------------------------------
        //    0       0     SEG.SEQ = RCV.NXT
        //    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //   >0       0     not acceptable
        //   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //               or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        if seg_len == 0 {
            // 0 length segment, syn and ack are also 0 length segments, but have different rules
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_x_between(nxt_1, seqn, wnd_end) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_x_between(nxt_1, seqn, wnd_end)
                && !is_x_between(nxt_1, seqn.wrapping_add(seg_len - 1), wnd_end)
            {
                return Ok(());
            }
        }
        self.recv.nxt = seqn.wrapping_add(seg_len);

        //  A new acknowledgment (called an "acceptable ack"), is one for which
        //  the inequality below holds:
        //  SND.UNA < SEG.ACK =< SND.NXT
        if !is_x_between(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            //  If the connection is in any non-synchronized state (LISTEN,
            //  SYN-SENT, SYN-RECEIVED), and the incoming segment acknowledges
            //  something not yet sent (the segment carries an unacceptable ACK),
            //  a reset is sent.
            if !self.state.is_synchronized() {
                // send reset
                self.send_reset(net_ifc, tcp_header, data)?;
            }
            return Ok(());
        }
        self.send.una = ackn;

        // now respond to the packet with appropriate state rules
        match self.state {
            State::Closed => {
                unimplemented!("Closed state but connection already set??");
            }
            State::Listen => {}
            State::SynRcvd => {
                if !tcp_header.ack() {
                    // expected ACK as response to SYN,ACK... something weird happened
                    return Ok(());
                }

                self.state = State::Estab;

                self.tcpp.fin = true;
                self.write(net_ifc, &[])?;
                self.state = State::FinWait1;
            }
            State::SynSent => {}
            State::Estab => {
                unimplemented!();
            }
            State::FinWait1 => {
                if !tcp_header.fin() || !data.is_empty() {
                    unimplemented!();
                }

                self.tcpp.fin = false;
                self.write(net_ifc, &[])?;
                self.state = State::Closing;
            }
            State::FinWait2 => {}
            State::CloseWait => {}
            State::Closing => {

            }
        };

        Ok(())
    }

    fn send_reset(
        &mut self,
        net_ifc: &tun_tap::Iface,
        tcp_header: etherparse::TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<()> {
        self.tcpp.rst = true;

        self.write(net_ifc, &[])?;
        Ok(())
    }
}

fn is_x_between(start: u32, x: u32, end: u32) -> bool {
    // CHECKING IF: start < x < end, must handle >= or <= by subtracting/incrementing
    if start == x {
        return false;
    } else if start < x {
        // end has to be greater than x, or lower than start (if it wrapped)
        // otherwise it is in an illegal state
        if start <= end && end <= x {
            return false;
        }
    } else {
        // both x and end have wrapped, so end can only be between x and start
        // otherwise it is in an illegal state
        if x < end && end < start {
        } else {
            return false;
        }
    }
    return true;
}
