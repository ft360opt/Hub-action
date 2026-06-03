import os
import sys
import time
import json
import base64
import socket
import urllib.request
import urllib.parse
import subprocess
import tempfile
import logging
import platform
import random
import http.server
import socketserver
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= 配置区 =================
MIHOMO_BINARY = os.environ.get("MIHOMO_BINARY", "./mihomo")
CHUNK_SIZE = 50                                            
API_STARTUP_TIMEOUT = 30                                   
TEST_URL = "http://www.gstatic.com/generate_204"           
# ==========================================

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def download_mihomo_core():
    abs_binary_path = os.path.abspath(MIHOMO_BINARY)
    if os.path.exists(abs_binary_path): return
    logger.info(f"Downloading Mihomo core...")
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "amd64" if machine in ("x86_64", "amd64") else ("arm64" if machine in ("aarch64", "arm64") else machine)
    if system == "linux":
        download_url = f"https://github.com/MetaCubeX/mihomo/releases/download/v1.18.10/mihomo-linux-{arch}-v1.18.10.gz"
    elif system == "darwin":
        download_url = f"https://github.com/MetaCubeX/mihomo/releases/download/v1.18.10/mihomo-darwin-{arch}-v1.18.10.gz"
    else: raise RuntimeError(f"Unsupported OS: {system}")
    gz_file = "mihomo.gz"
    try:
        req = urllib.request.Request(download_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(gz_file, 'wb') as out_file:
            out_file.write(response.read())
        import gzip
        with gzip.open(gz_file, 'rb') as f_in, open(abs_binary_path, 'wb') as f_out:
            f_out.write(f_in.read())
        os.chmod(abs_binary_path, 0o755)
        if os.path.exists(gz_file): os.remove(gz_file)
    except Exception as e: logger.error(f"Failed to download Mihomo: {e}"); raise

def sanitize_uri(uri: str) -> str:
    if '#' in uri:
        main, frag = uri.split('#', 1)
        return f"{main}#{urllib.parse.quote(frag)}"
    return uri

def is_valid_node_format(node: str) -> bool:
    if not node or "://" not in node: return False
    scheme, _, rest = node.partition("://")
    scheme = scheme.lower()
    if scheme not in {"vmess", "vless", "ss", "trojan", "ssr", "hysteria", "hysteria2", "tuic", "snell"}: return False
    if scheme == "vmess":
        try:
            payload = rest.split('?')[0].split('#')[0]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            data = json.loads(base64.b64decode(payload).decode('utf-8', errors='ignore'))
            if not isinstance(data, dict) or not data.get("add") or not data.get("port") or not data.get("id"): return False
            for v in data.values():
                if v is None: return False
            return True
        except: return False
    elif scheme in ("vless", "trojan"):
        try: return bool(urllib.parse.urlparse(node.split('#')[0]).hostname)
        except: return False
    elif scheme == "ss":
        try: return bool(urllib.parse.urlparse(node.split('#')[0]).hostname)
        except: return False
    return len(rest.split('#')[0]) > 10

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0)); return s.getsockname()[1]

def wait_for_api_ready(api_port, process, timeout=API_STARTUP_TIMEOUT):
    api_url = f"http://127.0.0.1:{api_port}/version"
    for attempt in range(timeout):
        if process.poll() is not None: return False
        try:
            with urllib.request.urlopen(urllib.request.Request(api_url, method="GET"), timeout=1): return True
        except: time.sleep(1)
    return False

# 【核心修改】：捕获并返回真实的测速失败原因
def test_proxy_delay(api_port, proxy_name, timeout_ms):
    encoded_name = urllib.parse.quote(proxy_name)
    url = f"http://127.0.0.1:{api_port}/proxies/{encoded_name}/delay?url={urllib.parse.quote(TEST_URL)}&timeout={timeout_ms}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=8) as res:
            data = json.loads(res.read().decode())
            if "delay" in data and data["delay"] > 0:
                return proxy_name, data["delay"], None
            else:
                return None, None, data.get("message", "unknown error")
    except Exception as e:
        return None, None, str(e)

class SubscriptionHandler(http.server.BaseHTTPRequestHandler):
    payload = ""
    def do_GET(self):
        payload_b64 = base64.b64encode(self.payload.encode('utf-8'))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload_b64)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload_b64)
    def log_message(self, format, *args): pass

def process_chunk(chunk_nodes, timeout_ms, chunk_idx):
    valid_nodes = []
    api_port = get_free_port()
    sanitized_nodes = [sanitize_uri(n) for n in chunk_nodes]
    SubscriptionHandler.payload = "\n".join(sanitized_nodes)
    
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SubscriptionHandler)
    sub_port = httpd.server_address[1]
    server_thread = threading.Thread(target=httpd.serve_forever); server_thread.daemon = True; server_thread.start()
    
    cache_file = tempfile.mktemp(suffix='.yaml')
    config_yaml = f"""
port: 7890
socks-port: 7891
external-controller: 127.0.0.1:{api_port}
log-level: silent
proxy-providers:
  chunk-provider:
    type: http
    url: "http://127.0.0.1:{sub_port}/sub"
    interval: 3600
    path: "{cache_file}"
    health-check: {{ enable: false }}
proxy-groups:
  - name: ChunkGroup
    type: select
    use: [chunk-provider]
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
        f.write(config_yaml); config_file = f.name
        
    process = None
    try:
        process = subprocess.Popen([MIHOMO_BINARY, "-d", ".", "-f", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=".")
        if not wait_for_api_ready(api_port, process): return valid_nodes
            
        req = urllib.request.Request(f"http://127.0.0.1:{api_port}/providers/proxies/chunk-provider", method="GET")
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read().decode())
            provider_proxies = [p for p in data.get("proxies", []) if p["name"] not in ("DIRECT", "REJECT", "GLOBAL")]

        if provider_proxies:
            error_counts = {}
            with ThreadPoolExecutor(max_workers=20) as executor: # 降低并发，防止瞬间请求过多被拒
                futures = {executor.submit(test_proxy_delay, api_port, p["name"], timeout_ms): idx for idx, p in enumerate(provider_proxies)}
                for future in as_completed(futures):
                    proxy_name, delay, err_msg = future.result()
                    if proxy_name:
                        valid_nodes.append(chunk_nodes[futures[future]])
                    elif err_msg:
                        error_counts[err_msg] = error_counts.get(err_msg, 0) + 1
            
            # 【验尸报告】：打印该批次节点测速失败的真实原因
            if error_counts:
                logger.warning(f"Speedtest failed reasons for chunk {chunk_idx}:")
                for err, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:3]:
                    logger.warning(f"  > {err} ({count} nodes)")
                        
    except Exception as e: logger.error(f"Error processing chunk: {e}")
    finally:
        try: httpd.shutdown(); server_thread.join(timeout=2)
        except: pass
        if process and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=2)
            except: process.kill()
        for f in [config_file, cache_file]:
            if os.path.exists(f): os.remove(f)
    return valid_nodes

def validate_nodes_with_mihomo(input_file: str, timeout_ms: int = 5000) -> list:
    logger.info("Initializing node testing validation process via Mihomo Core (Chunked mode)...")
    with open(input_file, 'r', encoding='utf-8') as f:
        raw_nodes = [line.strip() for line in f if line.strip() and "://" in line]
    clean_nodes = [node for node in raw_nodes if is_valid_node_format(node)]
    logger.info(f"Total valid-format nodes to test: {len(clean_nodes)}")
    
    all_valid = []
    total = (len(clean_nodes) + CHUNK_SIZE - 1) // CHUNK_SIZE
    for i in range(0, len(clean_nodes), CHUNK_SIZE):
        chunk = clean_nodes[i:i+CHUNK_SIZE]
        logger.info(f"Processing chunk {i//CHUNK_SIZE+1}/{total} ({len(chunk)} nodes)...")
        valid = process_chunk(chunk, timeout_ms, i//CHUNK_SIZE+1)
        all_valid.extend(valid)
        logger.info(f"Chunk {i//CHUNK_SIZE+1} complete: {len(valid)} nodes passed.")
    return all_valid

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if not os.path.exists(MIHOMO_BINARY): download_mihomo_core()
        results = validate_nodes_with_mihomo(sys.argv[1])
        print(f"Final valid count: {len(results)}")
