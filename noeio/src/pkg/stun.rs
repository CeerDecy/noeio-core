use crate::common;
use crate::pkg::stun;
use bytecodec::{DecodeExt, EncodeExt, Error as BytecodecError};
use core::net::SocketAddr;
use std::net;
use std::sync::Arc;
use stun_codec::rfc5389::Attribute;
use stun_codec::rfc5389::methods::BINDING;
use stun_codec::rfc5780::attributes::ChangeRequest;
use stun_codec::{DecodedMessage, Message, MessageDecoder, MessageEncoder};
use tokio::io;
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::broadcast::Receiver;

pub struct StunCollector {}

impl StunCollector {
    pub async fn new() -> StunCollector {
        let socket = UdpSocket::bind("0.0.0.0:3478").await.unwrap();
        let udp = Arc::new(socket);
        let builder = StunClientFactory::new(udp);

        StunCollector {}
    }
}

pub struct StunClientFactory {
    pub sender: tokio::sync::broadcast::Sender<Vec<u8>>,
    pub receiver: tokio::sync::broadcast::Receiver<Vec<u8>>,
    pub socket: Arc<UdpSocket>,
}

impl StunClientFactory {
    pub fn new(udp: Arc<UdpSocket>) -> StunClientFactory {
        let socket = Arc::clone(&udp);
        let (sender, receiver) = tokio::sync::broadcast::channel::<Vec<u8>>(1);

        let sender_clone = sender.clone();
        // tokio::spawn(async move {
        //     let mut buf = vec![0u8; 2048];
        //     loop {
        //         let Ok((size, _)) = socket.recv_from(&mut buf).await else {
        //             break;
        //         };
        //         let data = buf[..size].to_vec();
        //         sender_clone.send(data).unwrap();
        //     }
        // });

        StunClientFactory {
            sender,
            receiver,
            socket: udp,
        }
    }

    pub async fn create(
        &self,
        stun_server: &str,
    ) -> Result<StunClient, Box<dyn std::error::Error>> {
        // let stun_server = "stun.chat.bilibili.com:3478";

        let addrs: Vec<_> = lookup_host(stun_server).await?.collect();
        let server_addr = addrs
            .iter()
            .copied()
            .find(|addr| addr.is_ipv4())
            .or_else(|| addrs.first().copied())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "failed to resolve STUN server")
            })?;

        Ok(StunClient::new(
            self.socket.clone(),
            server_addr,
            self.sender.subscribe(),
        ))
    }
}

pub struct StunClient {
    pub socket: Arc<UdpSocket>,
    pub addr: SocketAddr,
    pub receiver: Receiver<Vec<u8>>,
}

impl StunClient {
    pub fn new(udp: Arc<UdpSocket>, addr: SocketAddr, receiver: Receiver<Vec<u8>>) -> StunClient {
        StunClient {
            socket: udp,
            addr,
            receiver,
        }
    }

    pub async fn get_address(&mut self) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        let tid = common::stun::generate_tid();
        let message: stun_codec::Message<ChangeRequest> =
            stun_codec::Message::new(stun_codec::MessageClass::Request, BINDING, tid);

        let mut encoder = MessageEncoder::new();
        let bytes = encoder.encode_into_bytes(message)?;

        let udp = Arc::clone(&self.socket);
        let stun_server_addr = self.addr.clone();

        udp.send_to(&bytes, stun_server_addr).await?;

        let recv_buf = self.receiver.recv().await?;

        let mut decoder = MessageDecoder::<Attribute>::new();
        let response = decoder
            .decode_from_bytes(&recv_buf)?
            .map_err(BytecodecError::from)?;

        let addr = self
            .parse_mapped_addr(response)
            .ok_or_else(|| "failed to parse mapped address".to_string())?;

        Ok(addr)
    }

    fn parse_mapped_addr(&self, response: Message<Attribute>) -> Option<SocketAddr> {
        for attr in response.attributes() {
            match attr {
                Attribute::MappedAddress(address) => return Some(address.address()),
                Attribute::XorMappedAddress(address) => return Some(address.address()),
                _ => {}
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time;
    #[tokio::test]
    async fn test_stun_client() {
        let factory =
            StunClientFactory::new(Arc::new(UdpSocket::bind("0.0.0.0:8080").await.unwrap()));
        let mut client = factory.create("stun.chat.bilibili.com:3478").await.unwrap();
        let addr = client.get_address().await.unwrap();
        println!("{}", addr);
        // time::sleep(Duration::from_secs(10000)).await;
    }
}
