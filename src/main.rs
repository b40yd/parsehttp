use clap::{Parser, Subcommand};
use pcap::{Capture, Device, Linktype};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 从 pcap 文件解析
    File {
        #[arg(short, long)]
        path: String,
    },
    /// 实时抓包 (macOS lo0 请使用 sudo)
    Live {
        #[arg(short, long)]
        interface: String,
        #[arg(short, long, default_value = "tcp")]
        filter: String,
    },
    /// 列出网卡
    List,
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct FlowKey {
    addr_a: IpAddr,
    port_a: u16,
    addr_b: IpAddr,
    port_b: u16,
}

impl FlowKey {
    fn new(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> Self {
        let (a, pa, b, pb) = if (src, src_port) < (dst, dst_port) {
            (src, src_port, dst, dst_port)
        } else {
            (dst, dst_port, src, src_port)
        };
        FlowKey {
            addr_a: a,
            port_a: pa,
            addr_b: b,
            port_b: pb,
        }
    }
}

#[derive(PartialEq, Debug)]
enum TransactionState {
    RequestBody,
    ResponseHeader,
    ResponseBody,
}

struct HttpTransaction {
    req_header: String,
    req_body: Vec<u8>,
    expected_req_len: usize,
    res_header: String,
    res_body_raw: Vec<u8>,
    res_body_events: Vec<String>,
    expected_res_len: usize,
    is_sse: bool,
    state: TransactionState,
    req_printed: bool,
}

struct StreamBuffer {
    data: Vec<u8>,
    current_tx: Option<HttpTransaction>,
}

fn main() {
    let cli = Cli::parse();
    let mut streams: HashMap<FlowKey, StreamBuffer> = HashMap::new();

    match cli.command {
        Commands::List => {
            println!("\x1b[1m可用网卡列表:\x1b[0m");
            for d in Device::list().unwrap() {
                println!(" - {}", d.name);
            }
        }
        Commands::File { path } => {
            let cap = Capture::from_file(path).expect("无法打开文件");
            run_analysis(cap, &mut streams);
        }
        Commands::Live { interface, filter } => {
            let device = Device::list()
                .unwrap()
                .into_iter()
                .find(|d| d.name == interface)
                .expect("找不到网卡");
            let mut cap = Capture::from_device(device)
                .unwrap()
                .promisc(true)
                .snaplen(65535)
                .immediate_mode(true)
                .open()
                .unwrap();

            // 提示：在 lo0 上抓包，filter 建议直接用 "port 4081"
            cap.filter(&filter, true).unwrap();
            println!("\x1b[1;33m正在监听: {} (BPF: {})\x1b[0m", interface, filter);
            run_analysis(cap, &mut streams);
        }
    }
}

fn run_analysis<T: pcap::Activated>(
    mut cap: Capture<T>,
    streams: &mut HashMap<FlowKey, StreamBuffer>,
) {
    let link_type = cap.get_datalink();

    while let Ok(packet) = cap.next_packet() {
        let parsed = if link_type == Linktype::ETHERNET {
            parse_ethernet(&packet)
        } else if link_type == Linktype::NULL {
            parse_null_loopback(&packet)
        } else {
            None
        };

        if let Some((src, dst, ip_payload)) = parsed {
            if let Some(tcp) = TcpPacket::new(&ip_payload) {
                if tcp.payload().is_empty() {
                    continue;
                }
                let key = FlowKey::new(src, tcp.get_source(), dst, tcp.get_destination());
                let stream = streams.entry(key).or_insert(StreamBuffer {
                    data: Vec::new(),
                    current_tx: None,
                });
                stream.data.extend_from_slice(tcp.payload());
                process_stream(stream);
            }
        }
    }
}

fn parse_ethernet(packet: &pcap::Packet) -> Option<(IpAddr, IpAddr, Vec<u8>)> {
    let eth = EthernetPacket::new(packet.data)?;
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ip = Ipv4Packet::new(eth.payload())?;
            Some((
                ip.get_source().into(),
                ip.get_destination().into(),
                ip.payload().to_vec(),
            ))
        }
        EtherTypes::Ipv6 => {
            let ip = Ipv6Packet::new(eth.payload())?;
            Some((
                ip.get_source().into(),
                ip.get_destination().into(),
                ip.payload().to_vec(),
            ))
        }
        _ => None,
    }
}

fn parse_null_loopback(packet: &pcap::Packet) -> Option<(IpAddr, IpAddr, Vec<u8>)> {
    if packet.data.len() < 4 {
        return None;
    }
    // BSD Null Loopback 头部：4字节协议族标识
    let family = if packet.data[0] != 0 || packet.data[1] != 0 {
        u32::from_ne_bytes([
            packet.data[0],
            packet.data[1],
            packet.data[2],
            packet.data[3],
        ])
    } else {
        u32::from_be_bytes([
            packet.data[0],
            packet.data[1],
            packet.data[2],
            packet.data[3],
        ])
    };

    let payload = &packet.data[4..];
    match family {
        2 => {
            // IPv4
            let ip = Ipv4Packet::new(payload)?;
            Some((
                ip.get_source().into(),
                ip.get_destination().into(),
                ip.payload().to_vec(),
            ))
        }
        24 | 28 | 30 => {
            // IPv6 (不同系统的标识可能略有不同)
            let ip = Ipv6Packet::new(payload)?;
            Some((
                ip.get_source().into(),
                ip.get_destination().into(),
                ip.payload().to_vec(),
            ))
        }
        _ => None,
    }
}

fn process_stream(stream: &mut StreamBuffer) {
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut consumed = 0;

        if stream.current_tx.is_none() {
            let mut req = httparse::Request::new(&mut headers);
            if let Ok(httparse::Status::Complete(amt)) = req.parse(&stream.data) {
                let mut content_len = 0;
                let mut h_str = String::new();
                for h in req.headers.iter() {
                    let name = h.name.to_lowercase();
                    let val = String::from_utf8_lossy(h.value);
                    if name == "content-length" {
                        content_len = val.parse().unwrap_or(0);
                    }
                    h_str.push_str(&format!("  {}: {}\n", h.name, val));
                }
                stream.current_tx = Some(HttpTransaction {
                    req_header: format!(
                        "\x1b[1;32m▶ REQUEST: {} {}\x1b[0m\n{}",
                        req.method.unwrap_or(""),
                        req.path.unwrap_or(""),
                        h_str
                    ),
                    req_body: Vec::new(),
                    expected_req_len: content_len,
                    res_header: String::new(),
                    res_body_raw: Vec::new(),
                    res_body_events: Vec::new(),
                    expected_res_len: 0,
                    is_sse: false,
                    req_printed: false,
                    state: if content_len > 0 {
                        TransactionState::RequestBody
                    } else {
                        TransactionState::ResponseHeader
                    },
                });
                consumed = amt;
            }
        } else if let Some(tx) = &mut stream.current_tx {
            match tx.state {
                TransactionState::RequestBody => {
                    let take =
                        std::cmp::min(tx.expected_req_len - tx.req_body.len(), stream.data.len());
                    tx.req_body.extend_from_slice(&stream.data[..take]);
                    consumed = take;
                    if tx.req_body.len() >= tx.expected_req_len {
                        tx.state = TransactionState::ResponseHeader;
                    }
                }
                TransactionState::ResponseHeader => {
                    let mut res = httparse::Response::new(&mut headers);
                    if let Ok(httparse::Status::Complete(amt)) = res.parse(&stream.data) {
                        let mut clen = 0;
                        let mut h_str = String::new();
                        for h in res.headers.iter() {
                            let name = h.name.to_lowercase();
                            let val = String::from_utf8_lossy(h.value);
                            if name == "content-type" && val.contains("text/event-stream") {
                                tx.is_sse = true;
                            }
                            if name == "content-length" {
                                clen = val.parse().unwrap_or(0);
                            }
                            h_str.push_str(&format!("  {}: {}\n", h.name, val));
                        }
                        tx.res_header = format!(
                            "\x1b[1;34m◀ RESPONSE: {} {}\x1b[0m\n{}",
                            res.code.unwrap_or(0),
                            res.reason.unwrap_or(""),
                            h_str
                        );
                        tx.expected_res_len = clen;
                        tx.state = TransactionState::ResponseBody;
                        consumed = amt;
                        if !tx.is_sse && tx.expected_res_len == 0 {
                            output_transaction(tx);
                            stream.current_tx = None;
                        }
                    }
                }
                TransactionState::ResponseBody => {
                    if tx.is_sse {
                        let body = String::from_utf8_lossy(&stream.data).to_string();
                        let mut new_e = false;
                        for e in body.split("\n\n") {
                            if !e.trim().is_empty() {
                                tx.res_body_events.push(e.trim().to_string());
                                new_e = true;
                            }
                        }
                        consumed = stream.data.len();
                        if new_e {
                            output_transaction(tx);
                        }
                    } else {
                        let take = std::cmp::min(
                            tx.expected_res_len - tx.res_body_raw.len(),
                            stream.data.len(),
                        );
                        tx.res_body_raw.extend_from_slice(&stream.data[..take]);
                        consumed = take;
                        if tx.res_body_raw.len() >= tx.expected_res_len {
                            output_transaction(tx);
                            stream.current_tx = None;
                        }
                    }
                }
            }
        }
        if consumed > 0 {
            stream.data.drain(..consumed);
        } else {
            break;
        }
    }
}

fn output_transaction(tx: &mut HttpTransaction) {
    if tx.is_sse {
        println!(
            "\n\x1b[1;35m[SSE 会话更新 - 累计事件: {}]\x1b[0m",
            tx.res_body_events.len()
        );
        println!("{}", tx.req_header);
        if !tx.req_body.is_empty() {
            println!("  \x1b[90m[Request Body]\x1b[0m");
            pretty_json(&String::from_utf8_lossy(&tx.req_body), "    ");
        }
        println!("\n{}", tx.res_header);
        for (i, event) in tx.res_body_events.iter().enumerate() {
            if event.starts_with(": ping") {
                println!("    \x1b[90m[{}] {}\x1b[0m", i + 1, event);
            } else {
                println!("    \x1b[33m[Event {}]\x1b[0m", i + 1);
                pretty_json(event, "      ");
            }
        }
        println!("\x1b[1;35m{}\x1b[0m", "-".repeat(50));
    } else if !tx.req_printed {
        println!("\n\x1b[1;36m==================== TRANSACTION ====================\x1b[0m");
        println!("{}", tx.req_header);
        if !tx.req_body.is_empty() {
            println!("  \x1b[90m[Request Body]\x1b[0m");
            pretty_json(&String::from_utf8_lossy(&tx.req_body), "    ");
        }
        println!("\n{}", tx.res_header);
        if !tx.res_body_raw.is_empty() {
            println!("  \x1b[90m[Response Body]\x1b[0m");
            pretty_json(&String::from_utf8_lossy(&tx.res_body_raw), "    ");
        }
        println!("\x1b[1;36m=====================================================\x1b[0m\n");
        tx.req_printed = true;
    }
}

fn pretty_json(raw: &str, indent: &str) {
    let clean = if raw.starts_with("data: ") {
        raw.strip_prefix("data: ").unwrap_or(raw).trim()
    } else {
        raw.trim()
    };
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(clean) {
        if let Ok(p) = serde_json::to_string_pretty(&v) {
            for l in p.lines() {
                println!("{}{}", indent, l);
            }
            return;
        }
    }
    println!("{}{}", indent, raw);
}
