use pcap::Capture;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::{env, str};

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
}

struct StreamBuffer {
    data: Vec<u8>,
    current_tx: Option<HttpTransaction>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("用法: {} <pcap文件>", args[0]);
        return;
    }

    let mut cap = Capture::from_file(&args[1]).expect("无法打开 pcap 文件");
    let mut streams: HashMap<FlowKey, StreamBuffer> = HashMap::new();

    println!("\x1b[1;36m🚀 MCP 事务分析 - [逻辑状态机隔离模式]\x1b[0m\n");

    while let Ok(packet) = cap.next_packet() {
        if let Some(eth) = EthernetPacket::new(packet.data) {
            let info = match eth.get_ethertype() {
                EtherTypes::Ipv4 => Ipv4Packet::new(eth.payload()).map(|ip| {
                    (
                        ip.get_source().into(),
                        ip.get_destination().into(),
                        ip.payload().to_vec(),
                    )
                }),
                EtherTypes::Ipv6 => Ipv6Packet::new(eth.payload()).map(|ip| {
                    (
                        ip.get_source().into(),
                        ip.get_destination().into(),
                        ip.payload().to_vec(),
                    )
                }),
                _ => None,
            };

            if let Some((src, dst, ip_payload)) = info {
                if let Some(tcp) = TcpPacket::new(&ip_payload) {
                    let tcp_payload = tcp.payload();
                    if tcp_payload.is_empty() {
                        continue;
                    }

                    let key = FlowKey::new(src, tcp.get_source(), dst, tcp.get_destination());
                    let stream = streams.entry(key).or_insert(StreamBuffer {
                        data: Vec::new(),
                        current_tx: None,
                    });

                    stream.data.extend_from_slice(tcp_payload);
                    process_stream(stream);
                }
            }
        }
    }
    for (_, s) in streams {
        flush_tx(&s.current_tx);
    }
}

fn process_stream(stream: &mut StreamBuffer) {
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut consumed = 0;

        if stream.current_tx.is_none() {
            // 尝试解析 Request Header
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(&stream.data) {
                Ok(httparse::Status::Complete(amt)) => {
                    let mut content_len = 0;
                    let mut h_details = String::new();
                    for h in req.headers.iter() {
                        let name = h.name.to_lowercase();
                        let val = String::from_utf8_lossy(h.value);
                        if name == "content-length" {
                            content_len = val.parse::<usize>().unwrap_or(0);
                        }
                        h_details.push_str(&format!("  {}: {}\n", h.name, val));
                    }
                    stream.current_tx = Some(HttpTransaction {
                        req_header: format!(
                            "\x1b[1;32m▶ REQUEST: {} {}\x1b[0m\n{}",
                            req.method.unwrap_or(""),
                            req.path.unwrap_or(""),
                            h_details
                        ),
                        req_body: Vec::new(),
                        expected_req_len: content_len,
                        res_header: String::new(),
                        res_body_raw: Vec::new(),
                        res_body_events: Vec::new(),
                        expected_res_len: 0,
                        is_sse: false,
                        state: if content_len > 0 {
                            TransactionState::RequestBody
                        } else {
                            TransactionState::ResponseHeader
                        },
                    });
                    consumed = amt;
                }
                _ => break, // 数据不足或不是请求，跳出循环
            }
        } else if let Some(tx) = &mut stream.current_tx {
            match tx.state {
                TransactionState::RequestBody => {
                    let remaining = tx.expected_req_len - tx.req_body.len();
                    let take = std::cmp::min(remaining, stream.data.len());
                    tx.req_body.extend_from_slice(&stream.data[..take]);
                    consumed = take;
                    if tx.req_body.len() >= tx.expected_req_len {
                        tx.state = TransactionState::ResponseHeader;
                    }
                }
                TransactionState::ResponseHeader => {
                    let mut res = httparse::Response::new(&mut headers);
                    match res.parse(&stream.data) {
                        Ok(httparse::Status::Complete(amt)) => {
                            let mut content_len = 0;
                            let mut h_details = String::new();
                            for h in res.headers.iter() {
                                let name = h.name.to_lowercase();
                                let val = String::from_utf8_lossy(h.value);
                                if name == "content-type" && val.contains("text/event-stream") {
                                    tx.is_sse = true;
                                }
                                if name == "content-length" {
                                    content_len = val.parse::<usize>().unwrap_or(0);
                                }
                                h_details.push_str(&format!("  {}: {}\n", h.name, val));
                            }
                            tx.res_header = format!(
                                "\x1b[1;34m◀ RESPONSE: {} {}\x1b[0m\n{}",
                                res.code.unwrap_or(0),
                                res.reason.unwrap_or(""),
                                h_details
                            );
                            tx.expected_res_len = content_len;
                            tx.state = TransactionState::ResponseBody;
                            consumed = amt;
                        }
                        _ => break,
                    }
                }
                TransactionState::ResponseBody => {
                    if tx.is_sse {
                        let body_part = String::from_utf8_lossy(&stream.data).to_string();
                        // SSE 需要保存原始字符串进行按行切分
                        for event in body_part.split("\n\n") {
                            if !event.trim().is_empty() {
                                tx.res_body_events.push(event.trim().to_string());
                            }
                        }
                        consumed = stream.data.len();
                        // SSE 通常不自动关闭事务，等待下一个请求触发 Flush
                    } else {
                        let remaining = tx.expected_res_len - tx.res_body_raw.len();
                        let take = std::cmp::min(remaining, stream.data.len());
                        tx.res_body_raw.extend_from_slice(&stream.data[..take]);
                        consumed = take;
                        if tx.res_body_raw.len() >= tx.expected_res_len {
                            flush_tx(&stream.current_tx);
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

fn flush_tx(tx_opt: &Option<HttpTransaction>) {
    if let Some(tx) = tx_opt {
        if tx.req_header.is_empty() {
            return;
        }

        // --- 1. 打印 Request 块 ---
        println!("{}", tx.req_header);
        if !tx.req_body.is_empty() {
            println!("  \x1b[90m[Request Body]\x1b[0m");
            pretty_print_json(&String::from_utf8_lossy(&tx.req_body), "    ");
        }
        println!("");

        // --- 2. 打印 Response 块 ---
        if !tx.res_header.is_empty() {
            println!("{}", tx.res_header);
            if tx.is_sse {
                println!("  \x1b[90m(SSE Stream Events)\x1b[0m");
                for event in &tx.res_body_events {
                    if event.starts_with(": ping") {
                        println!("    \x1b[90m{}\x1b[0m", event);
                    } else {
                        println!("    \x1b[33m[Event]\x1b[0m");
                        pretty_print_json(event, "      ");
                    }
                }
            } else if !tx.res_body_raw.is_empty() {
                println!("  \x1b[90m[Response Body]\x1b[0m");
                pretty_print_json(&String::from_utf8_lossy(&tx.res_body_raw), "    ");
            }
        }
        println!("{}\n", "=".repeat(70));
    }
}

fn pretty_print_json(raw: &str, indent: &str) {
    // 自动剥离 SSE 的 data: 前缀
    let clean = if raw.starts_with("data: ") {
        raw.strip_prefix("data: ").unwrap_or(raw).trim()
    } else {
        raw.trim()
    };

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(clean) {
        if let Ok(pretty) = serde_json::to_string_pretty(&json) {
            for line in pretty.lines() {
                println!("{}{}", indent, line);
            }
            return;
        }
    }
    // 如果不是 JSON，直接缩进打印原文本
    println!("{}{}", indent, raw);
}
