//! SHARINGAN — Anti AI Detector Genjutsu in Pure Rust
//! Author: Nino Zulfikar
//! License: MIT

pub const PNG_MAGIC: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
pub const JPEG_MAGIC: &[u8; 2] = b"\xff\xd8";

/// Standard IEEE 802.3 CRC32 calculation
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[derive(Debug, Clone)]
pub struct DetectedMarker {
    pub tag: String,
    pub marker_type: String,
    pub size_bytes: usize,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct InspectionResult {
    pub format: String,
    pub size_bytes: usize,
    pub width: u32,
    pub height: u32,
    pub dimensions: String,
    pub is_ai_detected: bool,
    pub detected_markers: Vec<DetectedMarker>,
    pub summary: String,
}

pub fn create_camera_exif_bytes(preset: &str) -> Vec<u8> {
    if preset == "tsukuyomi_void" {
        return Vec::new();
    }

    let (make, model, software, lens_model, iso, f_num, exp_time, focal_len) = match preset {
        "sony_a7m4" => (
            b"Sony\0".as_slice(),
            b"ILCE-7M4\0".as_slice(),
            b"Adobe Photoshop Lightroom Classic 13.0\0".as_slice(),
            b"FE 35mm F1.8\0".as_slice(),
            200u16,
            (18u32, 10u32),
            (1u32, 250u32),
            (350u32, 10u32),
        ),
        "iphone_15_pro" => (
            b"Apple\0".as_slice(),
            b"iPhone 15 Pro Max\0".as_slice(),
            b"18.1\0".as_slice(),
            b"iPhone 15 Pro Max back triple camera 6.86mm f/1.78\0".as_slice(),
            64u16,
            (178u32, 100u32),
            (1u32, 120u32),
            (686u32, 100u32),
        ),
        _ => (
            // Default: canon_r5
            b"Canon\0".as_slice(),
            b"Canon EOS R5\0".as_slice(),
            b"Adobe Photoshop 25.0 (Windows)\0".as_slice(),
            b"RF50mm F1.2 L USM\0".as_slice(),
            100u16,
            (12u32, 10u32),
            (1u32, 160u32),
            (500u32, 10u32),
        ),
    };

    let now_str = b"2026:11:10 12:00:00\0";
    let mut buf = Vec::with_capacity(512);

    // TIFF Header: Little-endian ('II'), magic 42, offset to IFD0 = 8
    buf.extend_from_slice(b"II*\x00\x08\x00\x00\x00");

    let ifd0_entries: u16 = 6;
    buf.extend_from_slice(&ifd0_entries.to_le_bytes());

    let data_offset_base = 8 + 2 + (ifd0_entries as usize * 12) + 4;
    let mut data_bank = Vec::new();

    let mut add_data = |d: &[u8]| -> u32 {
        let off = (data_offset_base + data_bank.len()) as u32;
        data_bank.extend_from_slice(d);
        if d.len() % 2 != 0 {
            data_bank.push(0);
        }
        off
    };

    let make_off = add_data(make);
    let model_off = add_data(model);
    let soft_off = add_data(software);
    let now_off = add_data(now_str);

    // 1. Make (0x010F) - ASCII
    buf.extend_from_slice(&0x010Fu16.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&(make.len() as u32).to_le_bytes());
    buf.extend_from_slice(&make_off.to_le_bytes());

    // 2. Model (0x0110) - ASCII
    buf.extend_from_slice(&0x0110u16.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&(model.len() as u32).to_le_bytes());
    buf.extend_from_slice(&model_off.to_le_bytes());

    // 3. Orientation (0x0112) - SHORT = 1
    buf.extend_from_slice(&0x0112u16.to_le_bytes());
    buf.extend_from_slice(&3u16.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    // 4. Software (0x0131) - ASCII
    buf.extend_from_slice(&0x0131u16.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&(software.len() as u32).to_le_bytes());
    buf.extend_from_slice(&soft_off.to_le_bytes());

    // 5. DateTime (0x0132) - ASCII
    buf.extend_from_slice(&0x0132u16.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&(now_str.len() as u32).to_le_bytes());
    buf.extend_from_slice(&now_off.to_le_bytes());

    // 6. ExifIFDPointer (0x8769)
    let exif_ifd_entries: u16 = 8;
    let exif_ifd_offset = (data_offset_base + data_bank.len()) as u32;
    buf.extend_from_slice(&0x8769u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&exif_ifd_offset.to_le_bytes());

    // Next IFD = 0
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&data_bank);

    // Write Exif Sub-IFD
    buf.extend_from_slice(&exif_ifd_entries.to_le_bytes());
    let sub_data_offset_base = exif_ifd_offset as usize + 2 + (exif_ifd_entries as usize * 12) + 4;
    let mut sub_data_bank = Vec::new();

    let mut add_sub_data = |d: &[u8]| -> u32 {
        let off = (sub_data_offset_base + sub_data_bank.len()) as u32;
        sub_data_bank.extend_from_slice(d);
        if d.len() % 2 != 0 {
            sub_data_bank.push(0);
        }
        off
    };

    let mut exp_bytes = Vec::new();
    exp_bytes.extend_from_slice(&exp_time.0.to_le_bytes());
    exp_bytes.extend_from_slice(&exp_time.1.to_le_bytes());
    let exp_off = add_sub_data(&exp_bytes);

    let mut f_bytes = Vec::new();
    f_bytes.extend_from_slice(&f_num.0.to_le_bytes());
    f_bytes.extend_from_slice(&f_num.1.to_le_bytes());
    let f_off = add_sub_data(&f_bytes);

    let date_orig_off = add_sub_data(now_str);
    let date_dig_off = add_sub_data(now_str);

    let mut focal_bytes = Vec::new();
    focal_bytes.extend_from_slice(&focal_len.0.to_le_bytes());
    focal_bytes.extend_from_slice(&focal_len.1.to_le_bytes());
    let focal_off = add_sub_data(&focal_bytes);

    let lens_off = add_sub_data(lens_model);

    // Sub-IFD entries
    // 1. ExposureTime (0x829A) - RATIONAL
    buf.extend_from_slice(&0x829Au16.to_le_bytes());
    buf.extend_from_slice(&5u16.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&exp_off.to_le_bytes());

    // 2. FNumber (0x829D) - RATIONAL
    buf.extend_from_slice(&0x829Du16.to_le_bytes());
    buf.extend_from_slice(&5u16.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&f_off.to_le_bytes());

    // 3. ISOSpeedRatings (0x8827) - SHORT
    buf.extend_from_slice(&0x8827u16.to_le_bytes());
    buf.extend_from_slice(&3u16.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&iso.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    // 4. DateTimeOriginal (0x9003) - ASCII
    buf.extend_from_slice(&0x9003u16.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&(now_str.len() as u32).to_le_bytes());
    buf.extend_from_slice(&date_orig_off.to_le_bytes());

    // 5. DateTimeDigitized (0x9004) - ASCII
    buf.extend_from_slice(&0x9004u16.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&(now_str.len() as u32).to_le_bytes());
    buf.extend_from_slice(&date_dig_off.to_le_bytes());

    // 6. FocalLength (0x920A) - RATIONAL
    buf.extend_from_slice(&0x920Au16.to_le_bytes());
    buf.extend_from_slice(&5u16.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&focal_off.to_le_bytes());

    // 7. ColorSpace (0xA001) - SHORT = 1 (sRGB)
    buf.extend_from_slice(&0xA001u16.to_le_bytes());
    buf.extend_from_slice(&3u16.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    // 8. LensModel (0xA434) - ASCII
    buf.extend_from_slice(&0xA434u16.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&(lens_model.len() as u32).to_le_bytes());
    buf.extend_from_slice(&lens_off.to_le_bytes());

    // Next Sub-IFD = 0
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&sub_data_bank);

    buf
}

pub fn inspect_image(bytes: &[u8]) -> InspectionResult {
    let size_bytes = bytes.len();
    let mut detected_markers = Vec::new();
    let mut width = 0u32;
    let mut height = 0u32;
    let mut format = "UNKNOWN".to_string();

    if bytes.starts_with(PNG_MAGIC) {
        format = "PNG".to_string();
        let mut idx = 8;
        while idx + 8 <= size_bytes {
            let length = u32::from_be_bytes([bytes[idx], bytes[idx+1], bytes[idx+2], bytes[idx+3]]) as usize;
            let ctype = &bytes[idx+4..idx+8];

            if idx + 8 + length > size_bytes {
                break;
            }
            let chunk_data = &bytes[idx+8..idx+8+length];

            if ctype == b"IHDR" && length >= 8 {
                width = u32::from_be_bytes([chunk_data[0], chunk_data[1], chunk_data[2], chunk_data[3]]);
                height = u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]]);
            }

            if ctype == b"caBX" {
                detected_markers.push(DetectedMarker {
                    tag: "caBX".to_string(),
                    marker_type: "C2PA JUMBF Manifest Chunk".to_string(),
                    size_bytes: length,
                    description: "Cryptographic Content Credentials manifest (OpenAI / Truepic / Adobe CA signed)".to_string(),
                });
            }

            if ctype == b"tEXt" || ctype == b"zTXt" || ctype == b"iTXt" {
                let lower: Vec<u8> = chunk_data.iter().map(|b| b.to_ascii_lowercase()).collect();
                for kw in &[b"c2pa".as_slice(), b"trainedalgorithmicmedia", b"midjourney", b"stablediffusion", b"prompt"] {
                    if lower.windows(kw.len()).any(|w| w == *kw) {
                        detected_markers.push(DetectedMarker {
                            tag: String::from_utf8_lossy(ctype).to_string(),
                            marker_type: "Synthetic AI Prompt / Workflow".to_string(),
                            size_bytes: length,
                            description: format!("Contains synthetic signature keyword '{}'", String::from_utf8_lossy(kw)),
                        });
                        break;
                    }
                }
            }

            idx += 12 + length;
        }
    } else if bytes.starts_with(JPEG_MAGIC) {
        format = "JPEG".to_string();
        let mut idx = 2;
        while idx + 2 <= size_bytes {
            if bytes[idx] != 0xff {
                break;
            }
            let m = bytes[idx+1];
            if m == 0xd9 || m == 0xda {
                break;
            }
            if idx + 4 > size_bytes {
                break;
            }
            let seg_len = u16::from_be_bytes([bytes[idx+2], bytes[idx+3]]) as usize;
            if idx + 2 + seg_len > size_bytes {
                break;
            }
            let seg_data = &bytes[idx+4..idx+2+seg_len];

            // APP11 C2PA
            if m == 0xeb {
                detected_markers.push(DetectedMarker {
                    tag: "APP11".to_string(),
                    marker_type: "C2PA JUMBF Segment".to_string(),
                    size_bytes: seg_len,
                    description: "JPEG C2PA digital provenance container".to_string(),
                });
            }

            // APP1 XMP
            if m == 0xe1 {
                let lower: Vec<u8> = seg_data.iter().map(|b| b.to_ascii_lowercase()).collect();
                if lower.windows(22).any(|w| w == b"trainedalgorithmicmedia") || lower.windows(4).any(|w| w == b"c2pa") {
                    detected_markers.push(DetectedMarker {
                        tag: "APP1 (XMP)".to_string(),
                        marker_type: "AI Provenance Manifest".to_string(),
                        size_bytes: seg_len,
                        description: "digitalSourceType: trainedAlgorithmicMedia found in XMP".to_string(),
                    });
                }
            }

            if (m == 0xc0 || m == 0xc2) && seg_data.len() >= 5 {
                height = u16::from_be_bytes([seg_data[1], seg_data[2]]) as u32;
                width = u16::from_be_bytes([seg_data[3], seg_data[4]]) as u32;
            }

            idx += 2 + seg_len;
        }
    }

    let is_ai = !detected_markers.is_empty();
    InspectionResult {
        format,
        size_bytes,
        width,
        height,
        dimensions: format!("{} × {} px", width, height),
        is_ai_detected: is_ai,
        detected_markers,
        summary: if is_ai { "AI Provenance Identified".to_string() } else { "Clean / Physical Optical Profile".to_string() },
    }
}

pub fn sanitize_png_lossless(bytes: &[u8], preset: &str) -> Result<Vec<u8>, String> {
    if !bytes.starts_with(PNG_MAGIC) {
        return Err("Not a valid PNG file".to_string());
    }

    let size_bytes = bytes.len();
    let mut idx = 8;
    let mut kept_chunks = Vec::new();
    let mut ihdr_data = Vec::new();

    while idx + 8 <= size_bytes {
        let length = u32::from_be_bytes([bytes[idx], bytes[idx+1], bytes[idx+2], bytes[idx+3]]) as usize;
        let ctype = &bytes[idx+4..idx+8];

        if idx + 12 + length > size_bytes {
            break;
        }
        let chunk_data = &bytes[idx+8..idx+8+length];

        match ctype {
            b"IHDR" => {
                ihdr_data = chunk_data.to_vec();
            }
            b"caBX" | b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"sRGB" | b"pHYs" | b"gAMA" => {
                // Stripped
            }
            _ => {
                kept_chunks.push((ctype.to_vec(), chunk_data.to_vec()));
            }
        }

        idx += 12 + length;
    }

    if ihdr_data.is_empty() {
        return Err("Missing IHDR chunk".to_string());
    }

    let mut out = Vec::with_capacity(size_bytes);
    out.extend_from_slice(PNG_MAGIC);

    let mut write_chunk = |tag: &[u8], data: &[u8]| {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(tag);
        out.extend_from_slice(data);
        let mut crc_payload = Vec::with_capacity(tag.len() + data.len());
        crc_payload.extend_from_slice(tag);
        crc_payload.extend_from_slice(data);
        let c = crc32(&crc_payload);
        out.extend_from_slice(&c.to_be_bytes());
    };

    // 1. IHDR
    write_chunk(b"IHDR", &ihdr_data);

    // 2. Camera Profile
    if preset != "tsukuyomi_void" {
        // sRGB perceptual
        write_chunk(b"sRGB", &[0]);
        // pHYs 300 DPI
        let mut phys = Vec::new();
        phys.extend_from_slice(&11811u32.to_be_bytes());
        phys.extend_from_slice(&11811u32.to_be_bytes());
        phys.push(1);
        write_chunk(b"pHYs", &phys);
        // eXIf
        let exif = create_camera_exif_bytes(preset);
        if !exif.is_empty() {
            write_chunk(b"eXIf", &exif);
        }
    }

    // 3. IDAT & remaining chunks
    for (tag, data) in kept_chunks {
        write_chunk(&tag, &data);
    }

    Ok(out)
}

pub fn sanitize_jpeg_lossless(bytes: &[u8], preset: &str) -> Result<Vec<u8>, String> {
    if !bytes.starts_with(JPEG_MAGIC) {
        return Err("Not a valid JPEG file".to_string());
    }

    let size_bytes = bytes.len();
    let mut idx = 2;
    let mut kept_segments = Vec::new();

    while idx + 2 <= size_bytes {
        if bytes[idx] != 0xff {
            break;
        }
        let m = bytes[idx+1];

        // SOS (Start of Scan) - rest of file is entropy stream
        if m == 0xda {
            kept_segments.push(bytes[idx..].to_vec());
            break;
        }

        if idx + 4 > size_bytes {
            break;
        }
        let seg_len = u16::from_be_bytes([bytes[idx+2], bytes[idx+3]]) as usize;
        if idx + 2 + seg_len > size_bytes {
            break;
        }
        let seg_full = &bytes[idx..idx+2+seg_len];
        let seg_data = &bytes[idx+4..idx+2+seg_len];

        // Strip C2PA APP11
        if m == 0xeb {
            // Strip
        } else if m == 0xe1 {
            let lower: Vec<u8> = seg_data.iter().map(|b| b.to_ascii_lowercase()).collect();
            if lower.windows(22).any(|w| w == b"trainedalgorithmicmedia") || lower.windows(4).any(|w| w == b"c2pa") {
                // Strip
            } else {
                kept_segments.push(seg_full.to_vec());
            }
        } else if m == 0xfe {
            // Strip Comment
        } else {
            kept_segments.push(seg_full.to_vec());
        }

        idx += 2 + seg_len;
    }

    let mut out = Vec::with_capacity(size_bytes);
    out.extend_from_slice(JPEG_MAGIC);

    if preset != "tsukuyomi_void" {
        let exif_raw = create_camera_exif_bytes(preset);
        if !exif_raw.is_empty() {
            let mut app1_payload = Vec::new();
            app1_payload.extend_from_slice(b"Exif\0\0");
            app1_payload.extend_from_slice(&exif_raw);
            let total_len = (app1_payload.len() + 2) as u16;
            out.extend_from_slice(b"\xff\xe1");
            out.extend_from_slice(&total_len.to_be_bytes());
            out.extend_from_slice(&app1_payload);
        }
    }

    for s in kept_segments {
        out.extend_from_slice(&s);
    }

    Ok(out)
}

pub fn sanitize_image(bytes: &[u8], preset: &str) -> Result<Vec<u8>, String> {
    if bytes.starts_with(PNG_MAGIC) {
        sanitize_png_lossless(bytes, preset)
    } else if bytes.starts_with(JPEG_MAGIC) {
        sanitize_jpeg_lossless(bytes, preset)
    } else {
        Err("Unsupported image format. Supports PNG and JPEG.".to_string())
    }
}

// ---------------------------------------------------------------------------
// WebAssembly (WASM) C-ABI Exports (Zero Dependencies, runs in browser)
// ---------------------------------------------------------------------------
#[no_mangle]
pub extern "C" fn sharingan_alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn sharingan_dealloc(ptr: *mut u8, size: usize) {
    let _ = Vec::from_raw_parts(ptr, 0, size);
}

#[no_mangle]
pub unsafe extern "C" fn sharingan_sanitize_wasm(
    in_ptr: *const u8,
    in_len: usize,
    preset_ptr: *const u8,
    preset_len: usize,
    out_len_ptr: *mut usize,
) -> *mut u8 {
    let in_bytes = std::slice::from_raw_parts(in_ptr, in_len);
    let preset_bytes = std::slice::from_raw_parts(preset_ptr, preset_len);
    let preset = std::str::from_utf8(preset_bytes).unwrap_or("canon_r5");

    match sanitize_image(in_bytes, preset) {
        Ok(mut cleaned) => {
            *out_len_ptr = cleaned.len();
            let ptr = cleaned.as_mut_ptr();
            std::mem::forget(cleaned);
            ptr
        }
        Err(_) => {
            *out_len_ptr = 0;
            std::ptr::null_mut()
        }
    }
}
