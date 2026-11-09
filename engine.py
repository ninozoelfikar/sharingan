#!/usr/bin/env python3
"""
SHARINGAN Engine — Core Lossless Metadata Sanitizer & Camera EXIF Spoofer
Author: Nino Zulfikar
License: MIT
"""

import io
import struct
import zlib
import time
from typing import Dict, Any, Tuple, Optional

PNG_MAGIC = b'\x89PNG\r\n\x1a\n'
JPEG_MAGIC = b'\xff\xd8'
RIFF_MAGIC = b'RIFF'
WEBP_MAGIC = b'WEBP'

AI_SIGNATURE_KEYWORDS = [
    b'c2pa', b'jumbf', b'cabx', b'trainedalgorithmicmedia',
    b'midjourney', b'stablediffusion', b'dall-e', b'prompt',
    b'workflow', b'parameters', b'generation_time', b'comfyui'
]


def create_camera_exif_bytes(preset: str, width: int = 1254, height: int = 1254) -> bytes:
    """
    Constructs realistic, bit-for-bit valid binary TIFF EXIF data for the selected camera preset.
    Presets: 'canon_r5', 'sony_a7m4', 'iphone_15_pro', 'tsukuyomi_void'.
    """
    if preset == 'tsukuyomi_void':
        return b''

    now_str = time.strftime("%Y:%m:%d %H:%M:%S", time.localtime()).encode('ascii') + b'\x00'

    if preset == 'canon_r5':
        make = b"Canon\x00"
        model = b"Canon EOS R5\x00"
        software = b"Adobe Photoshop 25.0 (Windows)\x00"
        lens_model = b"RF50mm F1.2 L USM\x00"
        iso = 100
        f_num = (12, 10)       # f/1.2
        exp_time = (1, 160)     # 1/160 s
        focal_len = (500, 10)   # 50.0 mm
    elif preset == 'sony_a7m4':
        make = b"Sony\x00"
        model = b"ILCE-7M4\x00"
        software = b"Adobe Photoshop Lightroom Classic 13.0\x00"
        lens_model = b"FE 35mm F1.8\x00"
        iso = 200
        f_num = (18, 10)       # f/1.8
        exp_time = (1, 250)     # 1/250 s
        focal_len = (350, 10)   # 35.0 mm
    elif preset == 'iphone_15_pro':
        make = b"Apple\x00"
        model = b"iPhone 15 Pro Max\x00"
        software = b"18.1\x00"
        lens_model = b"iPhone 15 Pro Max back triple camera 6.86mm f/1.78\x00"
        iso = 64
        f_num = (178, 100)     # f/1.78
        exp_time = (1, 120)     # 1/120 s
        focal_len = (686, 100)  # 6.86 mm
    else:
        # Default fallback to Canon EOS R5
        return create_camera_exif_bytes('canon_r5', width, height)

    buf = byteio = io.BytesIO()
    # TIFF Header: Little-endian ('II'), magic 42, offset to IFD0 = 8
    buf.write(b'II*\x00\x08\x00\x00\x00')

    # IFD0 entries count
    ifd0_entries = 6
    buf.write(struct.pack('<H', ifd0_entries))

    # IFD0 directory space: 2 bytes count + (entries * 12) + 4 bytes next_ifd = 78 bytes.
    # Data offset starts at 8 + 78 = 86
    data_offset = 8 + 2 + (ifd0_entries * 12) + 4
    data_bank = bytearray()

    def add_data(d: bytes) -> int:
        nonlocal data_offset
        off = data_offset + len(data_bank)
        data_bank.extend(d)
        if len(d) % 2 != 0:
            data_bank.extend(b'\x00')  # Word alignment
        return off

    make_off = add_data(make)
    model_off = add_data(model)
    soft_off = add_data(software)
    now_off = add_data(now_str)

    # 1. Make (0x010F)
    buf.write(struct.pack('<HHII', 0x010F, 2, len(make), make_off))
    # 2. Model (0x0110)
    buf.write(struct.pack('<HHII', 0x0110, 2, len(model), model_off))
    # 3. Orientation (0x0112) = 1 (Normal)
    buf.write(struct.pack('<HHIHH', 0x0112, 3, 1, 1, 0))
    # 4. Software (0x0131)
    buf.write(struct.pack('<HHII', 0x0131, 2, len(software), soft_off))
    # 5. DateTime (0x0132)
    buf.write(struct.pack('<HHII', 0x0132, 2, len(now_str), now_off))

    # 6. ExifIFDPointer (0x8769)
    # Exif IFD will be placed after data_bank
    exif_ifd_entries = 8
    exif_ifd_offset = data_offset + len(data_bank)
    buf.write(struct.pack('<HHII', 0x8769, 4, 1, exif_ifd_offset))

    # Next IFD pointer = 0 (No IFD1)
    buf.write(struct.pack('<I', 0))

    # Write data bank of IFD0
    buf.write(data_bank)

    # Now write Exif Sub-IFD
    buf.write(struct.pack('<H', exif_ifd_entries))
    sub_data_offset = exif_ifd_offset + 2 + (exif_ifd_entries * 12) + 4
    sub_data_bank = bytearray()

    def add_sub_data(d: bytes) -> int:
        nonlocal sub_data_offset
        off = sub_data_offset + len(sub_data_bank)
        sub_data_bank.extend(d)
        if len(d) % 2 != 0:
            sub_data_bank.extend(b'\x00')
        return off

    exp_off = add_sub_data(struct.pack('<II', exp_time[0], exp_time[1]))
    f_off = add_sub_data(struct.pack('<II', f_num[0], f_num[1]))
    date_orig_off = add_sub_data(now_str)
    date_dig_off = add_sub_data(now_str)
    focal_off = add_sub_data(struct.pack('<II', focal_len[0], focal_len[1]))
    lens_off = add_sub_data(lens_model)

    # 1. ExposureTime (0x829A) - RATIONAL
    buf.write(struct.pack('<HHII', 0x829A, 5, 1, exp_off))
    # 2. FNumber (0x829D) - RATIONAL
    buf.write(struct.pack('<HHII', 0x829D, 5, 1, f_off))
    # 3. ISOSpeedRatings (0x8827) - SHORT
    buf.write(struct.pack('<HHIHH', 0x8827, 3, 1, iso, 0))
    # 4. DateTimeOriginal (0x9003) - ASCII
    buf.write(struct.pack('<HHII', 0x9003, 2, len(now_str), date_orig_off))
    # 5. DateTimeDigitized (0x9004) - ASCII
    buf.write(struct.pack('<HHII', 0x9004, 2, len(now_str), date_dig_off))
    # 6. FocalLength (0x920A) - RATIONAL
    buf.write(struct.pack('<HHII', 0x920A, 5, 1, focal_off))
    # 7. ColorSpace (0xA001) = 1 (sRGB)
    buf.write(struct.pack('<HHIHH', 0xA001, 3, 1, 1, 0))
    # 8. LensModel (0xA434) - ASCII
    buf.write(struct.pack('<HHII', 0xA434, 2, len(lens_model), lens_off))

    # Next Exif IFD = 0
    buf.write(struct.pack('<I', 0))
    buf.write(sub_data_bank)

    return buf.getvalue()


def inspect_image(raw_bytes: bytes, filename: str = "") -> Dict[str, Any]:
    """
    Deep inspection of image headers, chunks, and metadata for synthetic AI watermarks and signatures.
    """
    size_bytes = len(raw_bytes)
    detected_markers = []
    chunk_list = []
    width = 0
    height = 0
    image_format = "UNKNOWN"

    if raw_bytes.startswith(PNG_MAGIC):
        image_format = "PNG"
        idx = 8
        while idx < size_bytes:
            if idx + 8 > size_bytes:
                break
            length, chunk_type = struct.unpack('>I4s', raw_bytes[idx:idx+8])
            ctype = chunk_type.decode('ascii', errors='ignore')
            chunk_list.append(ctype)
            chunk_data = raw_bytes[idx+8:idx+8+length]

            if ctype == 'IHDR' and length >= 8:
                width, height = struct.unpack('>II', chunk_data[:8])

            # Check for caBX (C2PA chunk in PNG)
            if ctype == 'caBX':
                detected_markers.append({
                    "tag": "caBX",
                    "type": "C2PA JUMBF Manifest Chunk",
                    "size_bytes": length,
                    "description": "Cryptographic Content Credentials manifest (OpenAI / Truepic / Adobe CA signed)"
                })

            # Check for prompt or workflow chunks
            if ctype in ('tEXt', 'zTXt', 'iTXt'):
                lower_data = chunk_data.lower()
                for kw in AI_SIGNATURE_KEYWORDS:
                    if kw in lower_data:
                        detected_markers.append({
                            "tag": ctype,
                            "type": "Synthetic AI Metadata / Prompt",
                            "size_bytes": length,
                            "description": f"Contains keyword reference '{kw.decode('ascii')}'"
                        })
                        break

            idx += 12 + length

    elif raw_bytes.startswith(JPEG_MAGIC):
        image_format = "JPEG"
        idx = 2
        while idx < size_bytes:
            if idx + 2 > size_bytes:
                break
            marker = raw_bytes[idx:idx+2]
            if marker[0] != 0xff:
                break
            m = marker[1]
            if m in (0xd9, 0xda):  # EOI or SOS
                break
            if idx + 4 > size_bytes:
                break
            seg_len = struct.unpack('>H', raw_bytes[idx+2:idx+4])[0]
            seg_data = raw_bytes[idx+4:idx+2+seg_len]

            # APP11 (0xFFEB): C2PA Manifest in JPEG
            if m == 0xeb:
                if b'JP' in seg_data[:4] or b'c2pa' in seg_data.lower():
                    detected_markers.append({
                        "tag": "APP11",
                        "type": "C2PA JUMBF Segment",
                        "size_bytes": seg_len,
                        "description": "JPEG C2PA digital provenance container"
                    })

            # APP1 (0xFFE1): XMP / Exif
            if m == 0xe1:
                lower = seg_data.lower()
                if b'trainedalgorithmicmedia' in lower or b'c2pa' in lower:
                    detected_markers.append({
                        "tag": "APP1 (XMP)",
                        "type": "AI Provenance Manifest",
                        "size_bytes": seg_len,
                        "description": "digitalSourceType: trainedAlgorithmicMedia found in XMP"
                    })

            # SOF0 / SOF2 for dimensions
            if m in (0xc0, 0xc2) and len(seg_data) >= 5:
                height, width = struct.unpack('>HH', seg_data[1:5])

            idx += 2 + seg_len

    elif raw_bytes.startswith(RIFF_MAGIC) and raw_bytes[8:12] == WEBP_MAGIC:
        image_format = "WEBP"
        idx = 12
        while idx < size_bytes:
            if idx + 8 > size_bytes:
                break
            chunk_type, chunk_len = struct.unpack('<4sI', raw_bytes[idx:idx+8])
            ctype = chunk_type.decode('ascii', errors='ignore')
            chunk_list.append(ctype)
            chunk_data = raw_bytes[idx+8:idx+8+chunk_len]

            if ctype in ('XMP ', 'EXIF'):
                lower = chunk_data.lower()
                for kw in AI_SIGNATURE_KEYWORDS:
                    if kw in lower:
                        detected_markers.append({
                            "tag": ctype.strip(),
                            "type": "WebP AI Signature Chunk",
                            "size_bytes": chunk_len,
                            "description": f"Contains reference '{kw.decode('ascii')}'"
                        })
                        break

            # Pad byte for RIFF chunks of odd length
            padded_len = chunk_len + (chunk_len % 2)
            idx += 8 + padded_len

    is_ai = len(detected_markers) > 0

    return {
        "filename": filename,
        "format": image_format,
        "size_bytes": size_bytes,
        "size_formatted": f"{size_bytes / (1024 * 1024):.2f} MB" if size_bytes > 1024*1024 else f"{size_bytes / 1024:.1f} KB",
        "width": width,
        "height": height,
        "dimensions": f"{width} × {height} px" if width and height else "Unknown",
        "chunks": list(dict.fromkeys(chunk_list)),
        "is_ai_detected": is_ai,
        "detected_markers": detected_markers,
        "summary": "AI Provenance Identified" if is_ai else "Clean / Physical Optical Profile"
    }


def sanitize_png_lossless(raw_bytes: bytes, preset: str = "canon_r5") -> bytes:
    """
    Sanitizes PNG files losslessly:
    - Strips caBX (C2PA) and synthetic text/metadata chunks.
    - Preserves IDAT (image compressed stream) bit-for-bit without recompression.
    - Injects clean camera EXIF and standard sRGB/pHYs headers.
    """
    assert raw_bytes.startswith(PNG_MAGIC), "Invalid PNG header"
    size_bytes = len(raw_bytes)
    idx = 8
    width, height = 1254, 1254
    kept_chunks = []

    while idx < size_bytes:
        if idx + 8 > size_bytes:
            break
        length, chunk_type = struct.unpack('>I4s', raw_bytes[idx:idx+8])
        ctype = chunk_type.decode('ascii', errors='ignore')
        chunk_data = raw_bytes[idx+8:idx+8+length]
        crc = raw_bytes[idx+8+length:idx+12+length]

        if ctype == 'IHDR' and length >= 8:
            width, height = struct.unpack('>II', chunk_data[:8])
            kept_chunks.append((ctype, chunk_data))
        elif ctype == 'caBX':
            # Strip C2PA Manifest
            pass
        elif ctype in ('tEXt', 'zTXt', 'iTXt'):
            # Strip text prompts, generation parameters, workflow JSON
            pass
        elif ctype in ('eXIf', 'sRGB', 'pHYs', 'gAMA'):
            # Replaced with verified camera profile
            pass
        elif ctype in ('IDAT', 'PLTE', 'tRNS', 'IEND'):
            kept_chunks.append((ctype, chunk_data))
        else:
            # Preserve standard auxiliary chunks
            kept_chunks.append((ctype, chunk_data))

        idx += 12 + length

    # Reconstruct PNG
    out = io.BytesIO()
    out.write(PNG_MAGIC)

    def write_chunk(ctype_str: str, data: bytes):
        c_bytes = ctype_str.encode('ascii')
        out.write(struct.pack('>I', len(data)))
        out.write(c_bytes)
        out.write(data)
        computed_crc = zlib.crc32(c_bytes + data) & 0xffffffff
        out.write(struct.pack('>I', computed_crc))

    # 1. Write IHDR
    ihdr_data = next((d for c, d in kept_chunks if c == 'IHDR'), None)
    if ihdr_data:
        write_chunk('IHDR', ihdr_data)

    # 2. Write Color & Physical Aspect (Standard 300 DPI, sRGB Perceptual)
    if preset != 'tsukuyomi_void':
        # sRGB chunk (rendering intent 0: Perceptual)
        write_chunk('sRGB', b'\x00')
        # pHYs chunk: 300 DPI = 11811 pixels per meter (unit 1 = meter)
        write_chunk('pHYs', struct.pack('>IIB', 11811, 11811, 1))
        # eXIf chunk with genuine camera TIFF metadata
        exif_bytes = create_camera_exif_bytes(preset, width, height)
        if exif_bytes:
            write_chunk('eXIf', exif_bytes)

    # 3. Write IDAT and other kept chunks
    for ctype, data in kept_chunks:
        if ctype != 'IHDR':
            write_chunk(ctype, data)

    return out.getvalue()


def sanitize_jpeg_lossless(raw_bytes: bytes, preset: str = "canon_r5") -> bytes:
    """
    Sanitizes JPEG files losslessly:
    - Strips APP11 (C2PA) and AI XMP APP1 segments.
    - Preserves SOS scan data without decompression or generational loss.
    - Injects clean camera EXIF APP1.
    """
    assert raw_bytes.startswith(JPEG_MAGIC), "Invalid JPEG header"
    size_bytes = len(raw_bytes)
    idx = 2
    kept_segments = []
    width, height = 1254, 1254

    while idx < size_bytes:
        if idx + 2 > size_bytes:
            break
        marker = raw_bytes[idx:idx+2]
        if marker[0] != 0xff:
            break
        m = marker[1]

        # SOS (Start of Scan): image entropy data begins, read until end
        if m == 0xda:
            kept_segments.append(('SOS', raw_bytes[idx:]))
            break

        if idx + 4 > size_bytes:
            break
        seg_len = struct.unpack('>H', raw_bytes[idx+2:idx+4])[0]
        seg_full = raw_bytes[idx:idx+2+seg_len]
        seg_data = raw_bytes[idx+4:idx+2+seg_len]

        # Strip APP11 (C2PA)
        if m == 0xeb:
            pass
        # Strip APP1 if it contains XMP with AI keywords
        elif m == 0xe1 and (b'trainedalgorithmicmedia' in seg_data.lower() or b'c2pa' in seg_data.lower()):
            pass
        # Strip Comment markers (prompts)
        elif m == 0xfe:
            pass
        else:
            if m in (0xc0, 0xc2) and len(seg_data) >= 5:
                height, width = struct.unpack('>HH', seg_data[1:5])
            kept_segments.append(('SEG', seg_full))

        idx += 2 + seg_len

    out = io.BytesIO()
    out.write(JPEG_MAGIC)

    # Inject Camera EXIF APP1 if not void
    if preset != 'tsukuyomi_void':
        exif_raw = create_camera_exif_bytes(preset, width, height)
        if exif_raw:
            # JPEG EXIF APP1 header: 'Exif\x00\x00' + TIFF data
            exif_app1_payload = b'Exif\x00\x00' + exif_raw
            total_len = len(exif_app1_payload) + 2
            out.write(b'\xff\xe1' + struct.pack('>H', total_len) + exif_app1_payload)

    for stype, sdata in kept_segments:
        out.write(sdata)

    return out.getvalue()


def sanitize_image(raw_bytes: bytes, filename: str = "", preset: str = "canon_r5") -> Tuple[bytes, str]:
    """
    Unified entry point for lossless image sanitization.
    Returns (cleaned_bytes, output_filename).
    """
    clean_name = f"sanitized_{filename}" if filename else "sanitized_image"

    if raw_bytes.startswith(PNG_MAGIC):
        cleaned = sanitize_png_lossless(raw_bytes, preset)
        if not clean_name.lower().endswith('.png'):
            clean_name += '.png'
        return cleaned, clean_name

    elif raw_bytes.startswith(JPEG_MAGIC):
        cleaned = sanitize_jpeg_lossless(raw_bytes, preset)
        if not (clean_name.lower().endswith('.jpg') or clean_name.lower().endswith('.jpeg')):
            clean_name += '.jpg'
        return cleaned, clean_name

    else:
        # Fallback for WebP or other formats via lossless container rewrite or strip
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(raw_bytes))
            out = io.BytesIO()
            if img.format == 'PNG':
                cleaned = sanitize_png_lossless(raw_bytes, preset)
                return cleaned, clean_name
            elif img.format in ('JPEG', 'JPG'):
                cleaned = sanitize_jpeg_lossless(raw_bytes, preset)
                return cleaned, clean_name
            else:
                # Save without extra metadata
                img.save(out, format=img.format)
                return out.getvalue(), clean_name
        except Exception:
            return raw_bytes, clean_name


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        fpath = sys.argv[1]
        with open(fpath, "rb") as f:
            data = f.read()
        res = inspect_image(data, fpath)
        print("Inspection Result:", res)
