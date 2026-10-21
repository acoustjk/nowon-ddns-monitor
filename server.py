import concurrent.futures
import json
import os
import re
import socket
import subprocess
import sys
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "hosts.json")
INDEX_FILE = os.path.join(BASE_DIR, "index.html")
PORT = int(os.environ.get("PORT", 8765))


def load_hosts():
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_hosts(hosts):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(hosts, f, ensure_ascii=False, indent=2)


def parse_host_and_port(raw_host, explicit_port=None):
    cleaned = str(raw_host or "").strip()
    cleaned = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.split("/")[0].strip()
    port = None
    if explicit_port is not None and str(explicit_port).strip().isdigit():
        port = int(str(explicit_port).strip())
    if ":" in cleaned:
        parts = cleaned.rsplit(":", 1)
        if parts[1].isdigit():
            cleaned = parts[0]
            if port is None:
                port = int(parts[1])
    return cleaned, port


def tcp_ping(ip_or_host, port, timeout=1.8):
    start = time.perf_counter()
    try:
        with socket.create_connection((ip_or_host, int(port)), timeout=timeout):
            elapsed = round((time.perf_counter() - start) * 1000)
            return True, max(1, elapsed), None
    except socket.timeout:
        return False, None, f"포트 {port} 응답 없음(Timeout)"
    except ConnectionRefusedError:
        return False, None, f"포트 {port} 거부됨(닫힘)"
    except Exception:
        return False, None, f"포트 {port} 연결 실패"


def icmp_ping(target, timeout_ms=1200):
    """Windows 및 Linux(클라우드 배포 환경) 모두 지원하는 ICMP Ping 함수"""
    is_win = sys.platform.startswith("win")
    startupinfo = None
    creationflags = 0

    if is_win:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags = subprocess.CREATE_NO_WINDOW
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), target]
        encoding = "cp949"
    else:
        timeout_sec = max(1, round(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), target]
        encoding = "utf-8"

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            creationflags=creationflags,
            timeout=(timeout_ms / 1000.0) + 1.2,
        )
        elapsed_fallback = round((time.perf_counter() - start) * 1000)
        output = proc.stdout.decode(encoding, errors="ignore")

        if proc.returncode == 0 and ("TTL=" in output.upper()):
            match = re.search(r"(?:시간|time)[=<]\s*([\d.]+)\s*ms", output, re.IGNORECASE)
            if match:
                ms = round(float(match.group(1)))
                return True, max(1, ms), None
            return True, max(1, elapsed_fallback), None
        return False, None, "Ping 응답 없음"
    except Exception as e:
        return False, None, str(e)


def check_single_host(item):
    raw_host = item.get("host", "")
    explicit_port = item.get("port")
    hostname, port = parse_host_and_port(raw_host, explicit_port)
    checked_at = datetime.now().strftime("%H:%M:%S")

    if not hostname:
        return {
            "id": item.get("id"),
            "online": False,
            "portOpen": False,
            "icmpOnline": False,
            "ms": None,
            "ip": "-",
            "port": port,
            "method": "-",
            "error": "주소 비어있음",
            "checkedAt": checked_at,
        }

    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except Exception:
        return {
            "id": item.get("id"),
            "online": False,
            "portOpen": False,
            "icmpOnline": False,
            "ms": None,
            "ip": "DNS 미등록/실패",
            "port": port,
            "method": f"TCP:{port}" if port else "PING",
            "error": "DDNS 도메인 IP 조회 실패",
            "checkedAt": checked_at,
        }

    icmp_ok, icmp_ms, icmp_err = icmp_ping(resolved_ip, timeout_ms=1200)

    if port:
        tcp_ok, tcp_ms, tcp_err = tcp_ping(resolved_ip, port, timeout=1.8)
        online = tcp_ok
        ms = tcp_ms if tcp_ok else icmp_ms
        if tcp_ok:
            err_msg = None
        elif icmp_ok:
            err_msg = f"공유기 Ping은 정상, 포트({port}) 닫힘"
        else:
            err_msg = f"오프라인 (포트 {port} 및 Ping 무응답)"
        return {
            "id": item.get("id"),
            "online": online,
            "portOpen": tcp_ok,
            "icmpOnline": icmp_ok,
            "ms": ms,
            "tcpMs": tcp_ms,
            "icmpMs": icmp_ms,
            "ip": resolved_ip,
            "port": port,
            "method": f"TCP:{port}",
            "error": err_msg,
            "checkedAt": checked_at,
        }
    else:
        return {
            "id": item.get("id"),
            "online": icmp_ok,
            "portOpen": None,
            "icmpOnline": icmp_ok,
            "ms": icmp_ms,
            "tcpMs": None,
            "icmpMs": icmp_ms,
            "ip": resolved_ip,
            "port": None,
            "method": "PING",
            "error": None if icmp_ok else (icmp_err or "응답 없음"),
            "checkedAt": checked_at,
        }


def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            with open(INDEX_FILE, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        elif parsed.path == "/api/hosts":
            self._send_json({"hosts": load_hosts()})
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            payload = json.loads(raw_body)
        except Exception:
            payload = {}

        if parsed.path == "/api/hosts":
            hosts = payload.get("hosts", [])
            save_hosts(hosts)
            self._send_json({"ok": True, "hosts": hosts})

        elif parsed.path == "/api/ping":
            hosts = load_hosts()
            target_ids = payload.get("ids")
            if target_ids:
                id_set = set(target_ids)
                targets = [h for h in hosts if h.get("id") in id_set]
            else:
                targets = hosts

            results = {}
            if targets:
                max_workers = min(60, max(10, len(targets)))
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_map = {executor.submit(check_single_host, h): h["id"] for h in targets}
                    for future in concurrent.futures.as_completed(future_map):
                        res = future.result()
                        results[res["id"]] = res

            self._send_json({
                "ok": True,
                "checkedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "results": results,
            })
        else:
            self.send_error(404)


def main():
    load_hosts()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), DashboardHandler)
    local_url = f"http://127.0.0.1:{PORT}"
    lan_url = f"http://{get_local_ip()}:{PORT}"
    print("=" * 64)
    print(" [DDNS & 포트 통합 관리 대시보드 실행 중]")
    print(f" - 내 PC 접속 주소     : {local_url}")
    print(f" - 같은 네트워크(팀원) : {lan_url}")
    print(f" - 데이터 파일         : {DATA_FILE}")
    print(" (이 창을 닫으면 대시보드 서버가 종료됩니다)")
    print("=" * 64)

    if "--no-browser" not in sys.argv and os.environ.get("RENDER") is None:
        webbrowser.open(local_url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n서버를 종료합니다.")
        server.server_close()


if __name__ == "__main__":
    main()
