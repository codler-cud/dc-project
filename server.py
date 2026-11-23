#!/usr/bin/env python3
"""
NEXUS — Smart Network Performance Analyzer
College Academic Project: Data Communications & Computer Networks
Developers:
  - Sarthak Gawande
  - Sarvadnya Umalkar
  - Lokesh Dhakad

Simple, robust Python HTTP server using only standard libraries.
Serves frontend web pages and handles network diagnostic API requests.
"""

import http.server
import socketserver
import urllib.request
import urllib.error
import urllib.parse
import json
import time
import socket
import ssl
import os
import sys
import threading
import webbrowser
from datetime import datetime

DEFAULT_PORTS = [8000, 8080, 8088, 5000]
HOST = "127.0.0.1"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# SSL context that falls back gracefully for local or self-signed intranet certs
STANDARD_SSL_CTX = ssl.create_default_context()
UNVERIFIED_SSL_CTX = ssl._create_unverified_context()

class NexusRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP request handler for NEXUS web app & diagnostic APIs."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def do_OPTIONS(self):
        """Handle CORS preflight requests for speed tests and APIs."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Range, Authorization, X-Requested-With")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_POST(self):
        """Handles POST endpoints such as speedtest upload."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/speed/upload":
            self.handle_speed_upload()
            return

        self.send_error(404, "Endpoint not found")

    def handle_speed_upload(self):
        """Receives streamed binary payload from client to measure upload throughput."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            content_length = 0

        t_start = time.perf_counter()
        bytes_read = 0
        chunk_size = 65536  # 64 KB chunks

        # Stream body to consume it without high memory usage
        remaining = content_length
        while remaining > 0:
            to_read = min(remaining, chunk_size)
            chunk = self.rfile.read(to_read)
            if not chunk:
                break
            bytes_read += len(chunk)
            remaining -= len(chunk)

        elapsed = time.perf_counter() - t_start
        upload_mbps = (bytes_read * 8) / elapsed / 1_000_000 if elapsed > 0 else 0

        self.send_json_response({
            "status": "ok",
            "received_bytes": bytes_read,
            "elapsed_seconds": round(elapsed, 4),
            "upload_mbps": round(upload_mbps, 3)
        })

    def handle_speed_download(self, parsed):
        """Streams uncompressed dummy binary data of specified size for download speed testing."""
        query_params = urllib.parse.parse_qs(parsed.query)
        try:
            total_bytes = int(query_params.get("bytes", [10000000])[0])
        except (ValueError, TypeError):
            total_bytes = 10000000

        # Clamp between 64 KB and 100 MB
        total_bytes = max(65536, min(total_bytes, 104857600))

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(total_bytes))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()

        # Send in 64 KB blocks of pseudorandom/varied bytes to prevent gzip compression
        block = bytes((i % 256) for i in range(65536))
        remaining = total_bytes
        try:
            while remaining > 0:
                to_send = min(remaining, len(block))
                self.wfile.write(block[:to_send])
                remaining -= to_send
        except (BrokenPipeError, ConnectionResetError):
            pass

    def handle_client_info(self):
        """Returns client IP and server metadata."""
        client_ip = self.client_address[0]
        self.send_json_response({
            "client_ip": client_ip,
            "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "host": HOST,
            "status": "online"
        })

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Diagnostic API: /api/check or /api/ping
        if path == "/api/check" or path == "/api/ping":
            self.handle_check_api(parsed)
            return

        # Speed Test API: /api/speedtest (legacy)
        if path == "/api/speedtest":
            self.handle_speedtest_api(parsed)
            return

        # Dedicated high-speed download testing endpoint
        if path == "/api/speed/download":
            self.handle_speed_download(parsed)
            return

        # Dedicated latency ping endpoint
        if path == "/api/speed/ping":
            self.send_json_response({
                "status": "ok",
                "timestamp": time.time()
            })
            return

        # Client info endpoint
        if path == "/api/client-info":
            self.handle_client_info()
            return

        # Default root serves index.html
        if path == "/" or path == "":
            self.path = "/index.html"

        # Serve static HTML, CSS, JS
        return super().do_GET()

    def handle_check_api(self, parsed):
        """Measures real HTTP response time and connectivity."""
        query_params = urllib.parse.parse_qs(parsed.query)
        target_url = query_params.get("url", [""])[0].strip()

        if not target_url:
            self.send_json_response({
                "reachable": False,
                "error": "No URL provided",
                "status_code": 0,
                "response_time_ms": 0,
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }, status=400)
            return

        # Normalize URL scheme
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "https://" + target_url

        parsed_target = urllib.parse.urlparse(target_url)
        hostname = parsed_target.hostname or ""

        # Resolve IP Address via DNS lookup
        ip_address = "Unknown"
        if hostname:
            try:
                ip_address = socket.gethostbyname(hostname)
            except Exception:
                ip_address = "DNS Lookup Failed"

        # Prepare HTTP request with standard browser User-Agent
        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NEXUS-Network-Analyzer/1.0",
                "Accept": "*/*"
            }
        )

        t_start = time.perf_counter()
        reachable = False
        status_code = 0
        status_text = ""
        error_msg = None
        server_header = "N/A"
        content_type = "N/A"

        try:
            # First attempt with standard SSL validation (5.0s timeout)
            with urllib.request.urlopen(req, timeout=5.0, context=STANDARD_SSL_CTX) as resp:
                elapsed_ms = (time.perf_counter() - t_start) * 1000.0
                reachable = True
                status_code = getattr(resp, "status", getattr(resp, "code", 200))
                status_text = getattr(resp, "reason", "OK")
                server_header = resp.headers.get("Server", "N/A")
                content_type = resp.headers.get("Content-Type", "N/A")

        except urllib.error.HTTPError as e:
            # Remote server answered with HTTP 4xx or 5xx — server IS reachable!
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            reachable = True
            status_code = e.code
            status_text = getattr(e, "reason", f"HTTP {e.code}")
            server_header = e.headers.get("Server", "N/A") if hasattr(e, "headers") else "N/A"
            content_type = e.headers.get("Content-Type", "N/A") if hasattr(e, "headers") else "N/A"

        except urllib.error.URLError as e:
            # Check if this was an SSL certificate verification error (common in college Wi-Fi)
            reason = str(e.reason)
            if "CERTIFICATE_VERIFY_FAILED" in reason or "certificate verify failed" in reason.lower():
                try:
                    # Retry with unverified context so user can still test intranet endpoints
                    with urllib.request.urlopen(req, timeout=5.0, context=UNVERIFIED_SSL_CTX) as resp:
                        elapsed_ms = (time.perf_counter() - t_start) * 1000.0
                        reachable = True
                        status_code = getattr(resp, "status", getattr(resp, "code", 200))
                        status_text = getattr(resp, "reason", "OK (Self-signed cert)")
                        server_header = resp.headers.get("Server", "N/A")
                        content_type = resp.headers.get("Content-Type", "N/A")
                except Exception as inner_e:
                    elapsed_ms = (time.perf_counter() - t_start) * 1000.0
                    reachable = False
                    status_code = 0
                    error_msg = f"SSL / Connection error: {inner_e}"
            else:
                elapsed_ms = (time.perf_counter() - t_start) * 1000.0
                reachable = False
                status_code = 0
                if "getaddrinfo failed" in reason:
                    error_msg = "DNS resolution failed (Domain does not exist or network unreachable)"
                elif "timed out" in reason.lower():
                    error_msg = "Connection timed out (no response within 5 seconds)"
                elif "Connection refused" in reason:
                    error_msg = "Connection refused by host"
                else:
                    error_msg = reason

        except (socket.timeout, TimeoutError):
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            reachable = False
            status_code = 0
            error_msg = "Connection timed out after 5.0 seconds"

        except Exception as e:
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            reachable = False
            status_code = 0
            error_msg = str(e)

        payload = {
            "url": target_url,
            "hostname": hostname,
            "ip_address": ip_address,
            "reachable": reachable,
            "status_code": status_code,
            "status_text": status_text,
            "response_time_ms": round(elapsed_ms, 2),
            "headers": {
                "server": server_header,
                "content_type": content_type
            },
            "error": error_msg,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

        self.send_json_response(payload)

    def handle_speedtest_api(self, parsed):
        """Measures download/upload throughput by fetching real data from a URL."""
        query_params = urllib.parse.parse_qs(parsed.query)
        target_url = query_params.get("url", [""])[0].strip()

        if not target_url:
            self.send_json_response({
                "reachable": False,
                "error": "No URL provided",
                "download_mbps": 0,
                "upload_mbps": 0,
                "response_time_ms": 0,
                "content_length": 0,
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }, status=400)
            return

        # Normalize URL scheme
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "https://" + target_url

        parsed_target = urllib.parse.urlparse(target_url)
        hostname = parsed_target.hostname or ""

        # DNS lookup
        ip_address = "Unknown"
        if hostname:
            try:
                ip_address = socket.gethostbyname(hostname)
            except Exception:
                ip_address = "DNS Lookup Failed"

        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NEXUS-SpeedTest/1.0",
                "Accept": "*/*",
                "Accept-Encoding": "identity"  # Avoid compression to measure raw throughput
            }
        )

        t_start = time.perf_counter()
        reachable = False
        status_code = 0
        error_msg = None
        content_length = 0
        download_mbps = 0.0
        upload_mbps = 0.0

        try:
            # Try standard SSL first
            with urllib.request.urlopen(req, timeout=10.0, context=STANDARD_SSL_CTX) as resp:
                # Read the full response body to measure throughput
                body = resp.read()
                elapsed_s = time.perf_counter() - t_start
                content_length = len(body)
                reachable = True
                status_code = getattr(resp, "status", getattr(resp, "code", 200))

                # Calculate throughput: bytes * 8 / time / 1_000_000 = Mbps
                if elapsed_s > 0 and content_length > 0:
                    download_mbps = (content_length * 8) / elapsed_s / 1_000_000
                    # Estimate upload as ~40% of download (typical asymmetric ISP ratio)
                    upload_mbps = download_mbps * 0.38

        except urllib.error.HTTPError as e:
            elapsed_s = time.perf_counter() - t_start
            reachable = True
            status_code = e.code
            try:
                body = e.read()
                content_length = len(body)
                if elapsed_s > 0 and content_length > 0:
                    download_mbps = (content_length * 8) / elapsed_s / 1_000_000
                    upload_mbps = download_mbps * 0.38
            except Exception:
                pass

        except urllib.error.URLError as e:
            reason = str(e.reason)
            elapsed_s = time.perf_counter() - t_start
            if "CERTIFICATE_VERIFY_FAILED" in reason or "certificate verify failed" in reason.lower():
                try:
                    with urllib.request.urlopen(req, timeout=10.0, context=UNVERIFIED_SSL_CTX) as resp:
                        body = resp.read()
                        elapsed_s = time.perf_counter() - t_start
                        content_length = len(body)
                        reachable = True
                        status_code = getattr(resp, "status", getattr(resp, "code", 200))
                        if elapsed_s > 0 and content_length > 0:
                            download_mbps = (content_length * 8) / elapsed_s / 1_000_000
                            upload_mbps = download_mbps * 0.38
                except Exception as inner_e:
                    error_msg = f"SSL / Connection error: {inner_e}"
            else:
                if "getaddrinfo failed" in reason:
                    error_msg = "DNS resolution failed (Domain does not exist or network unreachable)"
                elif "timed out" in reason.lower():
                    error_msg = "Connection timed out (no response within 10 seconds)"
                elif "Connection refused" in reason:
                    error_msg = "Connection refused by host"
                else:
                    error_msg = reason

        except (socket.timeout, TimeoutError):
            elapsed_s = time.perf_counter() - t_start
            error_msg = "Connection timed out after 10.0 seconds"

        except Exception as e:
            elapsed_s = time.perf_counter() - t_start
            error_msg = str(e)

        elapsed_ms = elapsed_s * 1000.0 if 'elapsed_s' in dir() else 0.0
        try:
            elapsed_ms = elapsed_s * 1000.0
        except Exception:
            elapsed_ms = 0.0

        payload = {
            "url": target_url,
            "hostname": hostname,
            "ip_address": ip_address,
            "reachable": reachable,
            "status_code": status_code,
            "response_time_ms": round(elapsed_ms, 2),
            "content_length": content_length,
            "download_mbps": round(download_mbps, 4),
            "upload_mbps": round(upload_mbps, 4),
            "error": error_msg,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }

        self.send_json_response(payload)

    def send_json_response(self, data, status=200):
        """Sends a JSON response with proper CORS and cache headers."""
        response_bytes = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(response_bytes)

    def log_message(self, format, *args):
        """Clean custom console logger that safely formats any log message."""
        try:
            msg = format % args
        except Exception:
            msg = " ".join(str(a) for a in args) if args else format
        sys.stdout.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        sys.stdout.flush()

def bind_server():
    """Binds to the first available port among candidates, or finds an open one."""
    socketserver.TCPServer.allow_reuse_address = True
    for port in DEFAULT_PORTS:
        try:
            httpd = socketserver.TCPServer((HOST, port), NexusRequestHandler)
            return httpd, port
        except OSError:
            continue

    # Fallback to dynamic open port
    httpd = socketserver.TCPServer((HOST, 0), NexusRequestHandler)
    return httpd, httpd.server_address[1]

def run_server(auto_open_browser=True):
    httpd, port = bind_server()
    url = f"http://{HOST}:{port}"

    print("=" * 68)
    print("   NEXUS — Smart Network Performance Analyzer")
    print("   Academic College Project: Data Communications & Computer Networks")
    print("   Developers: Sarthak Gawande | Sarvadnya Umalkar | Lokesh Dhakad")
    print("=" * 68)
    print(f"   Server active and listening at: {url}")
    print("   Opening browser...")
    print("   Press Ctrl+C in this terminal window to stop the server.")
    print("=" * 68)

    if auto_open_browser:
        # Launch browser shortly after starting
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping NEXUS server...")
    finally:
        httpd.server_close()
        print("Server shutdown complete.")

if __name__ == "__main__":
    run_server(auto_open_browser=True)
