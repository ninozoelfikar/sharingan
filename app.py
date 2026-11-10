#!/usr/bin/env python3
"""
SHARINGAN — Web Application & CLI Runner
Run local web UI:
    python3 app.py --serve
CLI usage:
    python3 app.py -i <image_path> [-p <preset>] [-o <output_path>]
Author: Nino Zulfikar
License: MIT
"""

import os
import sys
import json
import base64
import argparse
from typing import Optional
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path

# Add project root to sys.path
PROJECT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_DIR))

from engine import inspect_image, sanitize_image

MAX_PAYLOAD_SIZE = 25 * 1024 * 1024  # 25 MB max body size limit (Anti-DoS)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


STAGED_FILES = {}  # file_id -> {"data": bytes, "filename": str, "time": float}


class SharinganHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PROJECT_DIR), **kwargs)

    def do_GET(self):
        clean_path = self.path.split('?')[0].rstrip('/')
        if clean_path in ('', '/', '/index.html', '/sharingan', '/sharingan/index.html'):
            self.path = '/index.html'
            super().do_GET()
        elif clean_path.startswith('/assets/') or clean_path.startswith('/sharingan/assets/'):
            if clean_path.startswith('/sharingan/assets/'):
                self.path = clean_path.replace('/sharingan/assets/', '/assets/', 1)
            super().do_GET()
        else:
            self.send_error(404, "File not found")

    def do_POST(self):
        clean_path = self.path.split('?')[0].rstrip('/')
        if clean_path.endswith('/api/stage'):
            self._handle_stage()
        elif clean_path.endswith('/api/inspect'):
            self._handle_inspect()
        elif clean_path.endswith('/api/sanitize'):
            self._handle_sanitize()
        else:
            self.send_error(404, "Endpoint not found")

    def _read_json_body(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length <= 0:
            return None
        if content_length > MAX_PAYLOAD_SIZE:
            self._send_json(413, {"error": "Payload exceeds 25 MB security limit"})
            return None
        body = self.rfile.read(content_length)
        try:
            return json.loads(body.decode('utf-8'))
        except Exception:
            return None

    def _send_json(self, status_code: int, data: dict):
        response = json.dumps(data).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response)

    def _handle_stage(self):
        payload = self._read_json_body()
        if not payload or 'file' not in payload:
            self._send_json(400, {"error": "Missing 'file' field in JSON payload"})
            return

        try:
            raw_b64 = payload['file']
            if ',' in raw_b64:
                raw_b64 = raw_b64.split(',', 1)[1]
            raw_bytes = base64.b64decode(raw_b64)
            filename = payload.get('filename', 'upload.png')
            info = inspect_image(raw_bytes, filename)

            import time, uuid
            file_id = f"fid_{int(time.time()*1000)}_{uuid.uuid4().hex[:8]}"

            # Clean expired
            now = time.time()
            expired = [k for k, v in STAGED_FILES.items() if now - v.get('time', 0) > 900]
            for k in expired:
                STAGED_FILES.pop(k, None)

            STAGED_FILES[file_id] = {
                "data": raw_bytes,
                "filename": filename,
                "time": now
            }

            self._send_json(200, {
                "success": True,
                "file_id": file_id,
                "filename": filename,
                "data": info
            })
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _handle_inspect(self):
        payload = self._read_json_body()
        if not payload or 'file' not in payload:
            self._send_json(400, {"error": "Missing 'file' field in JSON payload"})
            return

        try:
            raw_b64 = payload['file']
            if ',' in raw_b64:
                raw_b64 = raw_b64.split(',', 1)[1]
            raw_bytes = base64.b64decode(raw_b64)
            filename = payload.get('filename', 'upload')
            info = inspect_image(raw_bytes, filename)
            self._send_json(200, {"success": True, "data": info})
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _handle_sanitize(self):
        payload = self._read_json_body()
        if not payload:
            self._send_json(400, {"error": "Missing JSON payload"})
            return

        try:
            file_id = payload.get('file_id')
            preset = payload.get('preset', 'canon_r5')

            if file_id and file_id in STAGED_FILES:
                entry = STAGED_FILES[file_id]
                raw_bytes = entry["data"]
                filename = entry["filename"]
            elif 'file' in payload:
                raw_b64 = payload['file']
                if ',' in raw_b64:
                    raw_b64 = raw_b64.split(',', 1)[1]
                raw_bytes = base64.b64decode(raw_b64)
                filename = payload.get('filename', 'image.png')
            else:
                self._send_json(400, {"error": "Missing 'file_id' or 'file' field"})
                return

            cleaned_bytes, out_filename = sanitize_image(raw_bytes, filename, preset)
            cleaned_b64 = base64.b64encode(cleaned_bytes).decode('ascii')

            delta_bytes = len(cleaned_bytes) - len(raw_bytes)

            self._send_json(200, {
                "success": True,
                "filename": out_filename,
                "file": cleaned_b64,
                "original_size": len(raw_bytes),
                "cleaned_size": len(cleaned_bytes),
                "delta_bytes": delta_bytes,
                "preset": preset
            })
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()


def run_server(host: str = "127.0.0.1", port: int = 5050):
    server = ThreadedHTTPServer((host, port), SharinganHTTPHandler)
    print(f"\n=======================================================")
    print(f"  SHARINGAN • Anti AI Detector Genjutsu")
    print(f"  Local Server active at: http://{host}:{port}")
    print(f"  Press Ctrl+C to terminate.")
    print(f"=======================================================\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSharingan server stopped.")
    finally:
        server.server_close()


def run_cli(input_path: str, preset: str, output_path: Optional[str]):
    p = Path(input_path)
    if not p.exists():
        print(f"Error: File '{input_path}' not found.")
        sys.exit(1)

    with open(p, "rb") as f:
        raw_bytes = f.read()

    print(f"[*] Reading '{p.name}' ({len(raw_bytes):,} bytes)...")
    info = inspect_image(raw_bytes, p.name)
    print(f"    Format: {info['format']} | Dimensions: {info['dimensions']}")
    print(f"    AI Signature Detected: {info['is_ai_detected']}")
    for m in info['detected_markers']:
        print(f"      - [{m['tag']}] {m['type']}: {m['description']} ({m.get('size_bytes', 0):,} bytes)")

    print(f"\n[*] Applying Genjutsu Cloak using preset '{preset}'...")
    cleaned_bytes, default_name = sanitize_image(raw_bytes, p.name, preset)

    out_file = Path(output_path) if output_path else p.parent / default_name
    with open(out_file, "wb") as f:
        f.write(cleaned_bytes)

    delta = len(cleaned_bytes) - len(raw_bytes)
    print(f"[+] Output written to: {out_file.resolve()}")
    print(f"    Cleaned size: {len(cleaned_bytes):,} bytes (Delta: {delta:+,} bytes)")
    print(f"    Status: 100% Bit-for-Bit Lossless Preservation.")


def main():
    parser = argparse.ArgumentParser(description="SHARINGAN — Anti AI Detector Genjutsu")
    parser.add_argument("--serve", action="store_true", help="Launch local web application UI")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Binding host (default: 127.0.0.1 for security)")
    parser.add_argument("--port", type=int, default=5050, help="Web server port (default: 5050)")
    parser.add_argument("-i", "--input", type=str, help="Input image file path")
    parser.add_argument("-p", "--preset", type=str, default="canon_r5",
                        choices=["canon_r5", "sony_a7m4", "iphone_15_pro", "tsukuyomi_void"],
                        help="Camera EXIF spoof preset (default: canon_r5)")
    parser.add_argument("-o", "--output", type=str, help="Output image file path")

    args = parser.parse_args()

    if args.serve or (not args.input and len(sys.argv) == 1):
        run_server(args.host, args.port)
    elif args.input:
        run_cli(args.input, args.preset, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
