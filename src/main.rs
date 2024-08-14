// 导入所需的标准库和外部库
use base64::prelude::*;
use clap::{error::KindFormatter, Parser};
use drillx::equix;
use futures_util::{SinkExt, StreamExt};
use rpassword::read_password;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signature},
    signer::Signer,
};
use std::{
    io::{self, Write},
    ops::{ControlFlow, Range},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc::UnboundedSender, Mutex};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        handshake::client::{generate_key, Request},
        Message,
    },
};

// 定义一个命令行工具的参数结构体
#[derive(Parser, Debug)]
#[command(version, author, about, long_about = None)]
struct Args {
    // 服务器的 URL 地址
    #[arg(
        long,
        value_name = "SERVER_URL",
        help = "URL of the server to connect to",
        global = true
    )]
    url: Option<String>,

    // 使用的 CPU 线程数量
    #[arg(long, default_value_t = 1, help = "Amount of CPU threads of mine with")]
    threads: u32,

    // 密钥文件路径
    #[arg(
        long,
        value_name = "KEYPAIR_PATH",
        help = "Filepath to keypair to use",
        global = true
    )]
    keypair: String,
    // 注释掉的参数，可用于设置每次交易的优先费用
    // #[arg(
    //     long,
    //     value_name = "MICROLAMPORTS",
    //     help = "Number of microlamports to pay as priority fee per transaction",
    //     default_value = "0",
    //     global = true
    // )]
    // priority_fee: Option<u64>,
}

// 定义一个用于接收服务器消息的枚举类型
#[derive(Debug)]
pub enum ServerMessage {
    StartMining([u8; 32], Range<u64>, u64),
}

// 程序的主入口，标记为异步
#[tokio::main]
async fn main() {
    let args = Args::parse(); // 解析命令行参数

    let keypair_path = std::path::Path::new(&args.keypair); // 从命令行参数获取密钥文件路径

    // 从文件读取密钥对，如果失败则打印错误并退出
    let key = read_keypair_file(keypair_path).expect(&format!(
        "Failed to load keypair from file: {}",
        args.keypair
    ));

    // 主循环，不断执行以下操作
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs(); // 获取当前 UNIX 时间戳

        let ts_msg = now.to_le_bytes(); // 将时间戳转换为字节序列

        let sig = key.sign_message(&ts_msg); // 使用密钥对时间戳消息进行签名

        // 构造 WebSocket 连接的 URL
        let mut url_str = args
            .url
            .clone()
            .unwrap_or("wss://domainexpansion.tech".to_string());
        if url_str.chars().last().unwrap() != '/' {
            url_str.push('/');
        }

        url_str.push_str(&format!("?timestamp={}", now));
        let url = url::Url::parse(&url_str).expect("Failed to parse server url"); // 解析 URL
        let host = url.host_str().expect("Invalid host in server url");
        let threads = args.threads; // 获取线程数量

        // 构造基本认证信息
        let auth = BASE64_STANDARD.encode(format!("{}:{}", key.pubkey(), sig));

        println!("Connecting to server...");
        // 构建 WebSocket 请求
        let request = Request::builder()
            .method("GET")
            .uri(url.to_string())
            .header("Sec-Websocket-Key", generate_key()) // 生成 WebSocket 密钥
            .header("Host", host)
            .header("Upgrade", "websocket")
            .header("Connection", "upgrade")
            .header("Sec-Websocket-Version", "13")
            .header("Authorization", format!("Basic {}", auth))
            .body(())
            .unwrap();

        // 尝试异步连接 WebSocket
        match connect_async(request).await {
            Ok((ws_stream, _)) => {
                // 连接成功
                println!("Connected to network!");

                let (mut sender, mut receiver) = ws_stream.split(); // 分割 WebSocket 流为发送和接收部分
                let (message_sender, mut message_receiver) =
                    tokio::sync::mpsc::unbounded_channel::<ServerMessage>();

                // 创建接收线程，不断读取并处理服务器发送的消息
                let receiver_thread = tokio::spawn(async move {
                    while let Some(Ok(message)) = receiver.next().await {
                        if process_message(message, message_sender.clone()).is_break() {
                            break;
                        }
                    }
                });

                // 发送“就绪”消息到服务器
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();

                let msg = now.to_le_bytes(); // 将当前时间戳转换为字节序列
                let sig = key.sign_message(&msg).to_string().as_bytes().to_vec(); // 对消息进行签名
                let mut bin_data: Vec<u8> = Vec::new();
                bin_data.push(0u8); // 消息类型为 0（例如，就绪消息）
                bin_data.extend_from_slice(&key.pubkey().to_bytes()); // 添加公钥字节
                bin_data.extend_from_slice(&msg); // 添加消息内容
                bin_data.extend(sig); // 添加签名

                let _ = sender.send(Message::Binary(bin_data)).await; // 发送二进制消息

                let sender = Arc::new(Mutex::new(sender));

                // 循环接收并处理来自服务器的消息
                let message_sender = sender.clone();
                while let Some(msg) = message_receiver.recv().await {
                    match msg {
                        ServerMessage::StartMining(challenge, nonce_range, cutoff) => {
                            println!("接收到开始挖矿的指令!");
                            println!("开始挖矿...");
                            println!("Nonce 范围: {} - {}", nonce_range.start, nonce_range.end);
                            let hash_timer = Instant::now(); // 计时开始
                            let core_ids = core_affinity::get_core_ids().unwrap(); // 获取 CPU 核心 ID
                            let nonces_per_thread = 10_000; // 每个线程处理的 nonce 数量
                            let handles = core_ids
                                .into_iter()
                                .map(|i| {
                                    std::thread::spawn({
                                        let mut memory = equix::SolverMemory::new();
                                        move || {
                                            if (i.id as u32).ge(&threads) {
                                                return None;
                                            }

                                            let _ = core_affinity::set_for_current(i);

                                            let first_nonce = nonce_range.start
                                                + (nonces_per_thread * (i.id as u64));
                                            let mut nonce = first_nonce;
                                            let mut best_nonce = nonce;
                                            let mut best_difficulty = 0;
                                            let mut best_hash = drillx::Hash::default();
                                            let mut total_hashes: u64 = 0;

                                            loop {
                                                // 创建哈希
                                                total_hashes += 1;
                                                if let Ok(hx) = drillx::hash_with_memory(
                                                    &mut memory,
                                                    &challenge,
                                                    &nonce.to_le_bytes(),
                                                ) {
                                                    let difficulty = hx.difficulty();
                                                    if difficulty.gt(&best_difficulty) {
                                                        best_nonce = nonce;
                                                        best_difficulty = difficulty;
                                                        best_hash = hx;
                                                    }
                                                }

                                                // 如果处理完当前范围内的 nonce，退出循环
                                                if nonce >= nonce_range.end {
                                                    break;
                                                }

                                                // 如果达到一定时间且找到足够困难的哈希，退出循环
                                                if nonce % 100 == 0 {
                                                    if hash_timer.elapsed().as_secs().ge(&cutoff) {
                                                        if best_difficulty.ge(&8) {
                                                            break;
                                                        }
                                                    }
                                                }

                                                // 自增 nonce
                                                nonce += 1;
                                            }

                                            // 返回找到的最好的 nonce
                                            Some((
                                                best_nonce,
                                                best_difficulty,
                                                best_hash,
                                                total_hashes,
                                            ))
                                        }
                                    })
                                })
                                .collect::<Vec<_>>();

                            // 汇总所有线程的结果，找到最好的 nonce
                            let mut best_nonce: u64 = 0;
                            let mut best_difficulty = 0;
                            let mut best_hash = drillx::Hash::default();
                            let mut total_nonces_checked = 0;
                            for h in handles {
                                if let Ok(Some((nonce, difficulty, hash, nonces_checked))) =
                                    h.join()
                                {
                                    total_nonces_checked += nonces_checked;
                                    if difficulty > best_difficulty {
                                        best_difficulty = difficulty;
                                        best_nonce = nonce;
                                        best_hash = hash;
                                    }
                                }
                            }

                            let hash_time = hash_timer.elapsed(); // 计算挖掘所用时间

                            println!("最高难度: {}", best_difficulty);
                            println!("Processed: {}", total_nonces_checked);
                            println!("Hash time: {:?}", hash_time);

                            let message_type = 2u8; // 1 u8 - 最佳解决方案消息
                            let best_hash_bin = best_hash.d; // 16 u8
                            let best_nonce_bin = best_nonce.to_le_bytes(); // 8 u8

                            let mut hash_nonce_message = [0; 24];
                            hash_nonce_message[0..16].copy_from_slice(&best_hash_bin);
                            hash_nonce_message[16..24].copy_from_slice(&best_nonce_bin);
                            let signature = key
                                .sign_message(&hash_nonce_message)
                                .to_string()
                                .as_bytes()
                                .to_vec();

                            let mut bin_data = [0; 57];
                            bin_data[00..1].copy_from_slice(&message_type.to_le_bytes());
                            bin_data[01..17].copy_from_slice(&best_hash_bin);
                            bin_data[17..25].copy_from_slice(&best_nonce_bin);
                            bin_data[25..57].copy_from_slice(&key.pubkey().to_bytes());

                            let mut bin_vec = bin_data.to_vec();
                            bin_vec.extend(signature);

                            {
                                let mut message_sender = message_sender.lock().await;
                                let _ = message_sender.send(Message::Binary(bin_vec)).await;
                            }

                            tokio::time::sleep(Duration::from_secs(3)).await;
                            // 发送新的就绪消息
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Time went backwards")
                                .as_secs();

                            let msg = now.to_le_bytes();
                            let sig = key.sign_message(&msg).to_string().as_bytes().to_vec();
                            let mut bin_data: Vec<u8> = Vec::new();
                            bin_data.push(0u8);
                            bin_data.extend_from_slice(&key.pubkey().to_bytes());
                            bin_data.extend_from_slice(&msg);
                            bin_data.extend(sig);
                            {
                                let mut message_sender = message_sender.lock().await;

                                let _ = message_sender.send(Message::Binary(bin_data)).await;
                            }
                        }
                    }
                }

                let _ = receiver_thread.await;
            }
            Err(e) => {
                match e {
                    tokio_tungstenite::tungstenite::Error::Http(e) => {
                        if let Some(body) = e.body() {
                            println!("websocket Error: {:?}", String::from_utf8(body.to_vec()));
                        } else {
                            println!("websocket Http Error: {:?}", e);
                        }
                    }
                    _ => {
                        println!("websocket 其他未知 Error: {:?}", e);
                    }
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

// 处理从服务器接收到的消息
fn process_message(
    msg: Message,
    message_channel: UnboundedSender<ServerMessage>,
) -> ControlFlow<(), ()> {
    match msg {
        Message::Text(t) => {
            println!("\n>>> 接收到服务器的消息: \n{}\n", t);
        }
        Message::Binary(b) => {
            let message_type = b[0];
            match message_type {
                0 => {
                    if b.len() < 49 {
                        println!("Invalid data for Message StartMining");
                    } else {
                        let mut hash_bytes = [0u8; 32];
                        // 从数据中提取 256 字节（32 个 uint8）作为哈希值
                        let mut b_index = 1;
                        for i in 0..32 {
                            hash_bytes[i] = b[i + b_index];
                        }
                        b_index += 32;

                        // 提取 64 字节（8 个 uint8）
                        let mut cutoff_bytes = [0u8; 8];
                        for i in 0..8 {
                            cutoff_bytes[i] = b[i + b_index];
                        }
                        b_index += 8;
                        let cutoff: u64 = u64::from_le_bytes(cutoff_bytes);

                        let mut nonce_start_bytes = [0u8; 8];
                        for i in 0..8 {
                            nonce_start_bytes[i] = b[i + b_index];
                        }
                        b_index += 8;
                        let nonce_start = u64::from_le_bytes(nonce_start_bytes);

                        let mut nonce_end_bytes = [0u8; 8];
                        for i in 0..8 {
                            nonce_end_bytes[i] = b[i + b_index];
                        }
                        let nonce_end = u64::from_le_bytes(nonce_end_bytes);

                        let msg =
                            ServerMessage::StartMining(hash_bytes, nonce_start..nonce_end, cutoff);

                        let _ = message_channel.send(msg);
                    }
                }
                _ => {
                    println!("Failed to parse server message type");
                }
            }
        }
        Message::Ping(v) => {
            println!("===Ping===: {:?}", v);
        }
        Message::Pong(v) => {
            println!("===Pong===: {:?}", v);
        }
        Message::Close(v) => {
            println!("close事件: {:?}", v);
            return ControlFlow::Break(());
        }
        _ => {
            println!("Got invalid message data");
        }
    }

    ControlFlow::Continue(())
}
