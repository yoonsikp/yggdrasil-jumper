use std::io::{ErrorKind, IoSlice, Write};
use tracing::{debug, warn};
use circular_buffer::CircularBuffer;

use crate::IoResult;

const FRAG_BUF_SIZE: usize = 1<<18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Varint {
    Ok { value: u64, varint_len: usize },
    Truncated,
    Invalid,
}

fn decode_varint(buf: &[u8]) -> Varint {
    const VARINT_MAX_LEN: usize = 10;

    let mut value: u64 = 0;

    for i in 0..VARINT_MAX_LEN {
        let Some(&byte) = buf.get(i) else {
            debug!("Varint truncated");
            return Varint::Truncated;
        };

        let bits = (byte & 0x7f) as u64;

        // Prevent overflow / invalid encodings
        if i == 9 && bits > 1 {
            debug!("Not a valid u64 varint (overflow)");
            return Varint::Invalid;
        }

        value |= bits << (i * 7);

        if byte & 0x80 == 0 {
            return Varint::Ok {
                value,
                varint_len: i + 1,
            };
        }
    }

    debug!("Not a varint (too long)");
    Varint::Invalid
}

enum Packet {
    /// Packet analysis failed, should abort here
    Invalid(),
    /// Need few more bytes
    TruncatedHeader,
    /// Packet not fits in the buffer.
    /// Assuming udp mtu is greatly smaller than buf size, it's unlikely that a truncated packet
    /// would fit. Having a separate field for this case should be less error prone.
    Truncated(usize),
    /// Packet may be sent over an unreliable channel
    Traffic(usize),
    /// Packet should be sent over a reliable channel
    Meta(usize),
    MetaInit(usize),
}

impl Packet {
    fn is_traffic(&self) -> bool {
        matches!(self, Packet::Traffic(_))
    }
}

/// Yggdrasil has a simple packet encoding, it starts with a varint containing packet size,
/// followed by a single byte for packet type

fn parse_yggdrasil_packet(buf: &[u8]) -> Packet {
    // Meta the first packet sent in the connection
    if buf.starts_with(b"meta") {
        if buf.len() < 6 {
            return Packet::TruncatedHeader;
        }
        let len = 6 + u16::from_be_bytes([buf[4], buf[5]]) as usize;
        return if len <= buf.len() {
            Packet::MetaInit(len)
        } else {
            Packet::Truncated(len)
        };
    }

    let (len, var_len) = match decode_varint(buf) {
        Varint::Ok { value, varint_len } => (value as usize, varint_len),
        Varint::Truncated => return Packet::TruncatedHeader,
        Varint::Invalid => return Packet::Invalid(),
    };

    // TODO: sanity check length
    if var_len + len > buf.len() {
        return Packet::Truncated(var_len + len);
    }
    let Some(&packet_type) = buf.get(var_len) else {
        return Packet::Invalid();
    };

    debug!("Received packet type is {packet_type}");

    // https://github.com/Arceliar/ironwood/blob/main/network/wire.go
    let to_bypass = match packet_type {
        // 0 => true, // dummy
        // 1 => true, // keep alive
        9 => true, // traffic
        _ => false,
    };

    if to_bypass {
        Packet::Traffic(var_len + len)
    } else {
        Packet::Meta(var_len + len)
    }
}


fn parse_yggdrasil_packet_circ(meta_seen: bool, buf: &CircularBuffer<FRAG_BUF_SIZE, u8>) -> Packet {
    // Meta the first packet sent in the connection
    if buf.len() < 6{
        return Packet::TruncatedHeader;
    }
    let mut iter = buf.iter().copied(); 
    let header: Vec<u8>  = iter.by_ref().take(4).collect();
    if header == b"meta" {
        let len = 6 + u16::from_be_bytes([buf[4], buf[5]]) as usize;
        return if len <= buf.len() {
            Packet::MetaInit(len)
        } else {
            Packet::Truncated(len)
        };
    }
    let mut iter = buf.iter().copied(); 
    let header: Vec<u8> = iter.by_ref().take(10).collect();
    let (len, var_len) = match decode_varint(&header) {
        Varint::Ok { value, varint_len } => (value as usize, varint_len),
        Varint::Truncated => return Packet::TruncatedHeader,
        Varint::Invalid => return Packet::Invalid(),
    };

    if var_len + len > buf.len() {
        return Packet::Truncated(var_len + len);
    }
    let Some(&packet_type) = buf.get(var_len) else {
        return Packet::Invalid();
    };

    debug!("Received packet type is {packet_type}");

    // https://github.com/Arceliar/ironwood/blob/main/network/wire.go
    let to_bypass = match packet_type {
        // 0 => true, // dummy
        // 1 => true, // keep alive
        9 => true, // traffic
        _ => false,
    };

    if to_bypass {
        Packet::Traffic(var_len + len)
    } else {
        Packet::Meta(var_len + len)
    }
}

#[derive(Default)]
pub struct SendLossy {
// if skip == -1 then we have an unknown amount of truncated packet
    pub skip: usize,
    pub udp_mtu: usize,
    pub fallback_to_reliable: bool,
    pub permanent_fallback: bool,
    pub fragmentbuffer: CircularBuffer<FRAG_BUF_SIZE, u8>,
    pub meta_seen: bool,
}
/// end_read: non-inclusive
///
impl SendLossy {
    /// Returns amount of bytes left at the beginning of the buffer
    pub fn send(
        &mut self,
        send: &mut [u8],
        peer: &std::net::UdpSocket,
        kcp: &mut kcp::Kcp<impl Write>,
    ) -> IoResult<usize> {
        let _ = self.fragmentbuffer.write_all(&send);
        
        if self.permanent_fallback {
            return self.recover(send, kcp);
        }

        while !self.fragmentbuffer.is_empty() {
            match parse_yggdrasil_packet_circ(self.meta_seen, &self.fragmentbuffer) {
                Packet::Invalid() => {
                    debug!("Invalid packet");
                    return Ok(0);
                }
                Packet::TruncatedHeader => {
                    debug!("Truncated header");
                    return Ok(0);
                }
                Packet::Truncated(len) => {
                    debug!("Too long {} bytes", len);
                    return Ok(0);
                }
                Packet::Traffic(len) if len <= self.udp_mtu => {
                    debug!("Sending {} bytes via shortcut", len);
                    let drained = self.fragmentbuffer.drain(..len).collect::<Vec<u8>>();
                    let sent = peer.send(&drained)?;
                    assert_eq!(sent, len);
                }
                Packet::MetaInit(len) => {
                    debug!("Sending {} bytes backed up", len);
                    self.meta_seen = true;
                    let drained = self.fragmentbuffer.drain(..len).collect::<Vec<u8>>();
                    let sent = kcp.send(&drained)?;
                    assert_eq!(sent, len);
                }
                Packet::Meta(len) | Packet::Traffic(len) => {
                    debug!("Sending {} bytes backed up", len);
                    let drained = self.fragmentbuffer.drain(..len).collect::<Vec<u8>>();
                    let sent = kcp.send(&drained)?;
                    assert_eq!(sent, len);
                }

            }
        }

        Ok(0)
    }

    pub fn recover(&mut self, send: &[u8], kcp: &mut kcp::Kcp<impl Write>) -> IoResult<usize> {
        if !self.permanent_fallback {
            self.permanent_fallback = true;
            warn!("Failed to interpret yggdrasil packets, falling back to reliable channel");
        }

        debug!("Sending {} bytes backed up (fallback)", send.len());
        kcp.send(send)?;
        Ok(0)
    }
}

#[derive(Default)]
pub struct ReceiveLossy {
    pub peer_conv: u32,
    pub backlog: Vec<u8>,
    pub skip: usize,
    pub permanent_fallback: bool,
}

impl ReceiveLossy {
    /// Returns if the packet was accepted
    pub fn recv_lossy(&mut self, recv: &[u8], ygg: &mut std::net::TcpStream) -> IoResult<bool> {
        if self.permanent_fallback {
            return Ok(false);
        }

        if recv.starts_with(&self.peer_conv.to_le_bytes())
            || !parse_yggdrasil_packet(recv).is_traffic()
        {
            debug!("Received {} BAD bytes via shortcut", recv.len());
            return Ok(false);
        }

        debug!("Receiving {} bytes via shortcut", recv.len());
        if self.skip == 0 {
            ygg.write_all(recv)?;
        } else {
            self.backlog.extend(recv);
        }

        Ok(true)
    }

    /// Returns amount of bytes left at the beginning of the buffer
    pub fn read_reliable(
        &mut self,
        recv: &mut [u8],
        ygg: &mut std::net::TcpStream,
    ) -> IoResult<usize> {
        let mut to_write = &recv[..];
        // Number of bytes to flush in `to_write` slice
        let mut to_flush = 0;

        if self.permanent_fallback {
            return self.recover(to_write, ygg);
        }

        while to_flush != to_write.len() {
            if self.skip != 0 {
                let to_skip = self.skip.min(to_write.len() - to_flush);
                self.skip = match self.skip.checked_sub(to_skip) {
                    Some(skip) => skip,
                    None => return self.recover(to_write, ygg),
                };

                to_flush += to_skip;

                debug!("Skipped {} bytes, {} remaining", to_skip, self.skip);
            }

            while to_flush != to_write.len() && self.skip == 0 {
                match parse_yggdrasil_packet(&to_write[to_flush..]) {
                    Packet::Invalid() => return self.recover(to_write, ygg),
                    Packet::TruncatedHeader => {
                        ygg.write_all(&to_write[..to_flush])?;

                        let len = to_write.len() - to_flush;
                        let range = (recv.len() - len)..;
                        recv.copy_within(range, 0);

                        return Ok(len);
                    }
                    Packet::Traffic(len) | Packet::Meta(len) | Packet::MetaInit(len) => {
                        debug!("Sending packet {} bytes", len);
                        to_flush += len;
                        if !self.backlog.is_empty() {
                            debug!("Inserting backlog of {} bytes", self.backlog.len());
                            write_all_vectored(
                                ygg,
                                &mut [
                                    IoSlice::new(&to_write[..to_flush]),
                                    IoSlice::new(&self.backlog),
                                ],
                            )?;
                            to_write = &to_write[to_flush..];
                            to_flush = 0;
                            self.backlog.clear();
                        }
                    }
                    Packet::Truncated(len) => {
                        debug!("Too long {} bytes", len);
                        self.skip += len;
                    }
                }
            }
        }

        assert_eq!(to_flush, to_write.len());
        ygg.write_all(&to_write[..to_flush])?;

        Ok(0)
    }

    pub fn recover(&mut self, recv: &[u8], ygg: &mut std::net::TcpStream) -> IoResult<usize> {
        if !self.permanent_fallback {
            self.permanent_fallback = true;
            warn!("Failed to interpret yggdrasil packets, falling back to reliable channel");
            self.backlog.clear();
        }

        debug!("Sending packet {} bytes (fallback)", recv.len());
        ygg.write_all(recv)?;
        Ok(0)
    }
}

/// Taken from yet nightly [`std::io::Write::write_all_vectored`]
fn write_all_vectored(
    socket: &mut std::net::TcpStream,
    mut bufs: &mut [IoSlice<'_>],
) -> IoResult<()> {
    // Guarantee that bufs is empty if it contains no data,
    // to avoid calling write_vectored if there is no data to be written.
    IoSlice::advance_slices(&mut bufs, 0);
    while !bufs.is_empty() {
        match socket.write_vectored(bufs) {
            Ok(0) => return Err(ErrorKind::NotConnected.into()),
            Ok(read) => IoSlice::advance_slices(&mut bufs, read),
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint() {
        assert_eq!(
            decode_varint(&[0b10010110, 0b00000001]),
            Varint::Ok {
                value: 150,
                varint_len: 2
            }
        );
    }
}
