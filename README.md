# 🔴 SHARINGAN (写輪眼)
### AI Metadata Genjutsu Cloaker & Lossless Provenance Neutralizer

<p align="center">
  <img src="assets/sharingan_eye.svg" width="160" height="160" alt="Sharingan Mangekyou Eye" />
</p>

<p align="center">
  <strong>Cast an optical illusion over synthetic media. Neutralize C2PA manifests, digital watermarks, and prompt signatures losslessly.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-crimson.svg" alt="Python Version" />
  <img src="https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Stdlib)-blue.svg" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/Pixel%20Loss-0%25%20(Bit--for--Bit)-emerald.svg" alt="Lossless" />
  <img src="https://img.shields.io/badge/License-MIT-purple.svg" alt="License: MIT" />
</p>

---

## ⚡ Overview

Generative AI platforms (DALL-E, ChatGPT, Midjourney, Stable Diffusion, Firefly) embed synthetic provenance manifests and cryptographic signatures into images. Most notably, **C2PA JUMBF Manifests** (`caBX` chunks in PNGs, `APP11` segments in JPEGs) explicitly declare:

```text
digitalSourceType: http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia
```

This digital tag allows automated scrapers, crawlers, and algorithmic gatekeepers to identify, classify, or penalize images created with AI assistance.

**SHARINGAN** is an on-premise, zero-dependency tool that losslessly excises these synthetic provenance layers and injects authentic physical camera EXIF metadata—transforming artificial output into an authentic optical illusion.

---

## 👁️ Features

- **100% Bit-for-Bit Lossless**: Operates at the container chunk and segment layer. `IDAT` (PNG) and entropy scans (JPEG) are preserved without recompression, pixel degradation, or color shift.
- **Deep C2PA & Synthetic Marker Stripping**:
  - PNG: Strips `caBX` (C2PA Manifest), `tEXt`, `zTXt`, `iTXt` (prompt parameters and workflow graphs).
  - JPEG: Strips `APP11` (C2PA JUMBF) and synthetic `APP1` (XMP provenance).
- **Physical Camera EXIF Spoofer**: Injects valid binary TIFF EXIF data matching genuine studio setups:
  - 📷 **Canon EOS R5**: RF 50mm f/1.2L USM &bull; 1/160s &bull; ISO 100 &bull; Photoshop 25.0
  - 📷 **Sony Alpha 7 IV**: FE 35mm f/1.8 &bull; 1/250s &bull; ISO 200 &bull; Lightroom Classic
  - 📱 **iPhone 15 Pro Max**: 24mm f/1.78 Main &bull; Smart HDR 5 &bull; iOS 18.1
  - 🌑 **Tsukuyomi Void**: 100% metadata purge (zero identifiers, raw raster only).
- **Zero External Dependencies**: Pure Python 3 standard library. No `pip install` required.
- **Dual Mode**: Interactive browser UI with live chunk disassembly and a headless terminal CLI.

---

## 🚀 Quick Start

### 1. Launch the Interactive Web UI

```bash
git clone https://github.com/ninozulfikar/sharingan.git
cd sharingan
python3 app.py --serve
```

Open your browser at:
```
http://localhost:5050
```

Drag and drop any AI-generated image into the rotating Sharingan eye, select your camera disguise profile, and click **Activate**.

---

### 2. Command Line Interface (CLI)

#### Inspect and Sanitize with Default Camera (Canon EOS R5):
```bash
python3 app.py -i portrait.png -o clean.png
```

#### Select a Specific Disguise Profile:
```bash
# Sony Alpha 7 IV
python3 app.py -i input.png -p sony_a7m4 -o clean.png

# iPhone 15 Pro Max
python3 app.py -i input.png -p iphone_15_pro -o clean.png

# Tsukuyomi Void (100% Purged)
python3 app.py -i input.png -p tsukuyomi_void -o void.png
```

---

## 🔬 How It Works (Technical Anatomy)

Standard image re-saving utilities decompress pixel rasters and re-encode them, causing compression artifacts and generational loss.

**SHARINGAN performs container surgery directly:**

```
Original PNG File:
┌──────┬────────┬────────┬──────┬────────────────────────┬──────┐
│ IHDR │ sRGB   │ pHYs   │ caBX │ IDAT (Compressed Pixels)│ IEND │
└──────┴────────┴────────┴──────┴────────────────────────┴──────┘
                           ▲
             [ C2PA MANIFEST ~21.8 KB STRIPPED ]

Sanitized Output (Canon EOS R5 Profile):
┌──────┬────────┬────────┬──────┬────────────────────────┬──────┐
│ IHDR │ sRGB   │ pHYs   │ eXIf │ IDAT (Compressed Pixels)│ IEND │
└──────┴────────┴────────┴──────┴────────────────────────┴──────┘
                           ▲
             [ AUTHENTIC CAMERA TIFF INJECTED ]
```

1. **Chunk Disassembly**: Walks the binary chunk tree without decoding raster arrays.
2. **Provenance Neutralization**: Identifies and drops `caBX` and auxiliary text metadata.
3. **EXIF Injection**: Synthesizes a little-endian TIFF IFD structure with valid tag pointers (Make, Model, LensModel, ExposureTime, FNumber, ISO).
4. **Lossless Assembly**: Recomputes CRC32 checksums and writes the output stream.

---

## 📁 Repository Structure

```
sharingan/
├── app.py              # Web application server & CLI entrypoint
├── engine.py           # Lossless chunk parser & EXIF spoofer
├── index.html          # Interactive dark UI with anime aesthetics
├── assets/
│   ├── sharingan_eye.svg   # Vector Mangekyou Sharingan eye
│   ├── Shojumaru.woff2     # Embedded Japanese-style Latin font
│   └── Shojumaru.base64    # Offline base64 data URI font
└── README.md           # Documentation
```

---

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for details.

Developed by **Nino Zulfikar**.
