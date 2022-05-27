use anyhow::Result;
use clap::Parser;
use thiserror::Error;
use tokio::net::UdpSocket;

const WAKE_ON_LAN_PACKET_LEN: usize = 6 + 16 * 6;
const MAGIC_PACKET: &[u8; 6] = &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

#[derive(Error, Debug)]
enum WakeError {
    #[error("Mac address is not of length 12 '{0}'")]
    MacNotLength12(String),
}

fn get_mac_bytes(mac: &str) -> Result<[u8; 6], WakeError> {
    let mut mac_bytes = [0; 6];

    let mac = mac.replace('-', "").replace(':', "");
    if mac.len() != 12 {
        return Err(WakeError::MacNotLength12(mac));
    }

    let mut i = 0;
    while i < 12 {
        mac_bytes[i / 2] = u8::from_str_radix(&mac[i..i + 2], 16).unwrap();
        i += 2;
    }

    Ok(mac_bytes)
}

fn get_wake_packet(mac: [u8; 6]) -> [u8; WAKE_ON_LAN_PACKET_LEN] {
    let mut packet = [0; WAKE_ON_LAN_PACKET_LEN];

    packet[0..6].copy_from_slice(MAGIC_PACKET);

    for i in 0..16 {
        packet[6 + i * 6 + 0] = mac[0];
        packet[6 + i * 6 + 1] = mac[1];
        packet[6 + i * 6 + 2] = mac[2];
        packet[6 + i * 6 + 3] = mac[3];
        packet[6 + i * 6 + 4] = mac[4];
        packet[6 + i * 6 + 5] = mac[5];
    }

    packet
}

#[derive(Parser, Debug)]
struct Args {
    /// MAC-Address of target device to send wake on lan packet
    #[clap(
        value_name = "MAC-Address",
        help = "MAC-Address of target device to send wake on lan packet"
    )]
    mac: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mac = args.mac;
    let mac_bytes = get_mac_bytes(&mac)?;
    let wake_packet = get_wake_packet(mac_bytes);

    let broadcast_ip = "255.255.255.255";
    let wake_on_lan_port = 7;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    println!(
        "Broadcasting wake on lan packet to {}:{} for {}",
        broadcast_ip, wake_on_lan_port, mac
    );

    socket
        .connect(format!("{}:{}", broadcast_ip, wake_on_lan_port))
        .await?;

    socket.send(&wake_packet).await?;

    Ok(())
}
