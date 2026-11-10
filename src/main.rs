//! SHARINGAN — Native Rust CLI & Embedded High-Speed HTTP Server
//! Author: Nino Zulfikar
//! License: MIT

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;

use sharingan::{inspect_image, sanitize_image};

const MAX_PAYLOAD_SIZE: usize = 25 * 1024 * 1024; // 25 MB limit

fn handle_client(mut stream: TcpStream, project_dir: PathBuf) {
    let mut buffer = Vec::new();
    let mut temp = [0u8; 8192];

    let header_end;
    let mut content_length = 0;

    // Read HTTP headers
    loop {
        match stream.read(&mut temp) {
            Ok(0) => return,
            Ok(n) => {
                buffer.extend_from_slice(&temp[..n]);
                if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = pos + 4;
                    let header_str = String::from_utf8_lossy(&buffer[..pos]);
                    for line in header_str.lines() {
                        if line.to_lowercase().starts_with("content-length:") {
                            if let Some(val) = line.split(':').nth(1) {
                                content_length = val.trim().parse::<usize>().unwrap_or(0);
                            }
                        }
                    }
                    break;
                }
            }
            Err(_) => return,
        }
    }

    if content_length > MAX_PAYLOAD_SIZE {
        send_response(&mut stream, 413, "application/json", b"{\"error\":\"Payload exceeds 25 MB security limit\"}");
        return;
    }

    // Read remaining body if Content-Length specified
    let needed = header_end + content_length;
    while buffer.len() < needed {
        match stream.read(&mut temp) {
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&temp[..n]),
            Err(_) => break,
        }
    }

    let header_part = String::from_utf8_lossy(&buffer[..header_end]);
    let first_line = header_part.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }

    let method = parts[0];
    let raw_path = parts[1].split('?').next().unwrap_or("/");

    if method == "POST" && (raw_path.ends_with("/api/inspect") || raw_path == "/api/inspect") {
        let body = &buffer[header_end..];
        let body_str = String::from_utf8_lossy(body);

        // Simple JSON extractor for "file"
        if let Some(b64) = extract_json_field(&body_str, "file") {
            let clean_b64 = if let Some(comma_pos) = b64.find(',') {
                &b64[comma_pos + 1..]
            } else {
                &b64
            };

            let decoded = decode_base64(clean_b64);
            let info = inspect_image(&decoded);

            let resp_json = format!(
                r#"{{"success":true,"data":{{"format":"{}","size_bytes":{},"size_formatted":"{}","width":{},"height":{},"dimensions":"{}","is_ai_detected":{},"detected_markers":{},"summary":"{}"}}}}"#,
                info.format,
                info.size_bytes,
                format_size(info.size_bytes),
                info.width,
                info.height,
                info.dimensions,
                info.is_ai_detected,
                markers_to_json(&info.detected_markers),
                info.summary
            );
            send_response(&mut stream, 200, "application/json", resp_json.as_bytes());
        } else {
            send_response(&mut stream, 400, "application/json", b"{\"error\":\"Missing file field\"}");
        }
    } else if method == "POST" && (raw_path.ends_with("/api/sanitize") || raw_path == "/api/sanitize") {
        let body = &buffer[header_end..];
        let body_str = String::from_utf8_lossy(body);

        let preset = extract_json_field(&body_str, "preset").unwrap_or_else(|| "canon_r5".to_string());
        let filename = extract_json_field(&body_str, "filename").unwrap_or_else(|| "image.png".to_string());

        if let Some(b64) = extract_json_field(&body_str, "file") {
            let clean_b64 = if let Some(comma_pos) = b64.find(',') {
                &b64[comma_pos + 1..]
            } else {
                &b64
            };

            let decoded = decode_base64(clean_b64);
            match sanitize_image(&decoded, &preset) {
                Ok(cleaned) => {
                    let cleaned_b64 = encode_base64(&cleaned);
                    let delta = (cleaned.len() as isize) - (decoded.len() as isize);
                    let out_name = format!("sanitized_{}", filename);

                    let resp_json = format!(
                        r#"{{"success":true,"filename":"{}","file":"{}","original_size":{},"cleaned_size":{},"delta_bytes":{},"preset":"{}"}}"#,
                        out_name, cleaned_b64, decoded.len(), cleaned.len(), delta, preset
                    );
                    send_response(&mut stream, 200, "application/json", resp_json.as_bytes());
                }
                Err(e) => {
                    let err_json = format!(r#"{{"success":false,"error":"{}"}}"#, e);
                    send_response(&mut stream, 500, "application/json", err_json.as_bytes());
                }
            }
        } else {
            send_response(&mut stream, 400, "application/json", b"{\"error\":\"Missing file field\"}");
        }
    } else if method == "GET" || method == "HEAD" {
        // Serve static files with strict Anti-Path-Traversal protection
        let req_path = if raw_path == "/" || raw_path.is_empty() || raw_path == "/sharingan" || raw_path == "/sharingan/" {
            "index.html"
        } else {
            raw_path.trim_start_matches('/').trim_start_matches("sharingan/").trim_start_matches('/')
        };

        if req_path.contains("..") || req_path.contains('\\') {
            send_response(&mut stream, 403, "text/plain", b"403 Forbidden");
            return;
        }

        let file_path = project_dir.join(req_path);
        if let (Ok(canon_file), Ok(canon_dir)) = (file_path.canonicalize(), project_dir.canonicalize()) {
            if canon_file.starts_with(&canon_dir) && canon_file.is_file() {
                if let Ok(bytes) = fs::read(&canon_file) {
                    let content_type = match canon_file.extension().and_then(|s| s.to_str()).unwrap_or("") {
                        "html" => "text/html; charset=utf-8",
                        "svg" => "image/svg+xml",
                        "woff2" => "font/woff2",
                        "png" => "image/png",
                        "jpg" | "jpeg" => "image/jpeg",
                        "json" => "application/json",
                        _ => "application/octet-stream",
                    };
                    if method == "HEAD" {
                        send_response_header_only(&mut stream, 200, content_type, bytes.len());
                    } else {
                        send_response(&mut stream, 200, content_type, &bytes);
                    }
                    return;
                }
            }
        }
        send_response(&mut stream, 404, "text/plain", b"404 Not Found");
    } else {
        send_response(&mut stream, 405, "text/plain", b"Method Not Allowed");
    }
}

fn send_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let status_line = match status {
        200 => "HTTP/1.1 200 OK",
        400 => "HTTP/1.1 400 Bad Request",
        403 => "HTTP/1.1 403 Forbidden",
        404 => "HTTP/1.1 404 Not Found",
        405 => "HTTP/1.1 405 Method Not Allowed",
        413 => "HTTP/1.1 413 Payload Too Large",
        _ => "HTTP/1.1 500 Internal Server Error",
    };

    let header = format!(
        "{}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        status_line, content_type, body.len()
    );

    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn send_response_header_only(stream: &mut TcpStream, status: u16, content_type: &str, content_length: usize) {
    let status_line = match status {
        200 => "HTTP/1.1 200 OK",
        400 => "HTTP/1.1 400 Bad Request",
        403 => "HTTP/1.1 403 Forbidden",
        404 => "HTTP/1.1 404 Not Found",
        405 => "HTTP/1.1 405 Method Not Allowed",
        413 => "HTTP/1.1 413 Payload Too Large",
        _ => "HTTP/1.1 500 Internal Server Error",
    };

    let header = format!(
        "{}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        status_line, content_type, content_length
    );

    let _ = stream.write_all(header.as_bytes());
    let _ = stream.flush();
}

fn format_size(bytes: usize) -> String {
    if bytes > 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    }
}

fn markers_to_json(markers: &[sharingan::DetectedMarker]) -> String {
    let mut parts = Vec::new();
    for m in markers {
        parts.push(format!(
            r#"{{"tag":"{}","type":"{}","size_bytes":{},"description":"{}"}}"#,
            m.tag, m.marker_type, m.size_bytes, m.description
        ));
    }
    format!("[{}]", parts.join(","))
}

fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\":", field);
    let idx = json.find(&key)? + key.len();
    let rest = json[idx..].trim_start();
    if rest.starts_with('"') {
        let after_quote = &rest[1..];
        let mut end = 0;
        let mut escaped = false;
        for (i, c) in after_quote.char_indices() {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                end = i;
                break;
            }
        }
        Some(after_quote[..end].to_string())
    } else {
        None
    }
}

// Minimal standard base64 codec
const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_base64(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        out.push(B64_CHARS[((n >> 18) & 63) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 63) as usize] as char);

        if chunk.len() > 1 {
            out.push(B64_CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(B64_CHARS[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn decode_base64(input: &str) -> Vec<u8> {
    let mut table = [0xFFu8; 256];
    for (i, &c) in B64_CHARS.iter().enumerate() {
        table[c as usize] = i as u8;
    }

    let clean: Vec<u8> = input.bytes().filter(|&b| b != b'\r' && b != b'\n' && b != b' ').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);

    for chunk in clean.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let b0 = table[chunk[0] as usize];
        let b1 = table[chunk[1] as usize];
        let b2 = if chunk.len() > 2 && chunk[2] != b'=' { table[chunk[2] as usize] } else { 0 };
        let b3 = if chunk.len() > 3 && chunk[3] != b'=' { table[chunk[3] as usize] } else { 0 };

        if b0 == 0xFF || b1 == 0xFF {
            continue;
        }

        let n = ((b0 as u32) << 18) | ((b1 as u32) << 12) | ((b2 as u32) << 6) | (b3 as u32);

        out.push(((n >> 16) & 0xFF) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            out.push((n & 0xFF) as u8);
        }
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut serve = false;
    let mut port = 5050u16;
    let mut custom_dir = None;
    let mut input_file = None;
    let mut output_file = None;
    let mut preset = "canon_r5".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--serve" => serve = true,
            "--port" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or(5050);
                    i += 1;
                }
            }
            "--dir" => {
                if i + 1 < args.len() {
                    custom_dir = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-i" | "--input" => {
                if i + 1 < args.len() {
                    input_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    output_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-p" | "--preset" => {
                if i + 1 < args.len() {
                    preset = args[i + 1].clone();
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("SHARINGAN (写輪眼) — Anti AI Detector in Rust");
                println!("\nUsage:");
                println!("  sharingan --serve [--port <port>] [--dir <path>] Launch embedded high-speed Web UI");
                println!("  sharingan -i <input> [-p <preset>] [-o <output>]  Sanitize image via CLI");
                println!("\nPresets:");
                println!("  canon_r5       Canon EOS R5 Studio Master (Default)");
                println!("  sony_a7m4      Sony Alpha 7 IV Street Natural");
                println!("  iphone_15_pro  iPhone 15 Pro Max Mobile Flagship");
                println!("  tsukuyomi_void 100% Stripped Zero-Metadata");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    let project_dir = if let Some(d) = custom_dir {
        PathBuf::from(d)
    } else {
        let current = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        if current.join("index.html").exists() {
            current
        } else if let Ok(exe) = env::current_exe() {
            if let Some(parent) = exe.parent() {
                if parent.join("index.html").exists() {
                    parent.to_path_buf()
                } else if let Some(grand) = parent.parent().and_then(|p| p.parent()) {
                    if grand.join("index.html").exists() {
                        grand.to_path_buf()
                    } else {
                        current
                    }
                } else {
                    current
                }
            } else {
                current
            }
        } else {
            current
        }
    };

    if serve || (input_file.is_none() && args.len() == 1) {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).expect("Failed to bind TCP listener");
        println!("=======================================================");
        println!("  SHARINGAN (写輪眼) — Pure Rust Native Engine");
        println!("  High-Speed Server active at: http://127.0.0.1:{}", port);
        println!("  Press Ctrl+C to terminate.");
        println!("=======================================================");

        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let p_dir = project_dir.clone();
                thread::spawn(move || {
                    handle_client(stream, p_dir);
                });
            }
        }
    } else if let Some(in_path) = input_file {
        let path = Path::new(&in_path);
        if !path.exists() {
            eprintln!("Error: File '{}' not found.", in_path);
            std::process::exit(1);
        }

        let raw = fs::read(path).expect("Failed to read input file");
        println!("[*] Reading '{}' ({} bytes)...", in_path, raw.len());
        let info = inspect_image(&raw);
        println!("    Format: {} | Dimensions: {}", info.format, info.dimensions);
        println!("    AI Signature Detected: {}", info.is_ai_detected);
        for m in &info.detected_markers {
            println!("      - [{}] {}: {} ({} bytes)", m.tag, m.marker_type, m.description, m.size_bytes);
        }

        println!("\n[*] Applying Genjutsu Cloak using preset '{}'...", preset);
        match sanitize_image(&raw, &preset) {
            Ok(cleaned) => {
                let out_dest = if let Some(out_p) = output_file {
                    PathBuf::from(out_p)
                } else {
                    path.parent().unwrap_or_else(|| Path::new(".")).join(format!("sanitized_{}", path.file_name().unwrap().to_str().unwrap()))
                };

                fs::write(&out_dest, &cleaned).expect("Failed to write output");
                let delta = (cleaned.len() as isize) - (raw.len() as isize);
                println!("[+] Output written to: {:?}", out_dest);
                println!("    Cleaned size: {} bytes (Delta: {:+} bytes)", cleaned.len(), delta);
                println!("    Status: 100% Bit-for-Bit Lossless Preservation in Rust.");
            }
            Err(e) => {
                eprintln!("Error during sanitization: {}", e);
                std::process::exit(1);
            }
        }
    }
}
