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
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================= 配置区 =================
MIHOMO_BINARY = os.environ.get("MIHOMO_BINARY", "./mihomo")
CHUNK_SIZE = 500                                           
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
    else:
        raise RuntimeError(f"Unsupported OS: {system}")

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
    except Exception as e:
        logger.error(f"Failed to download Mihomo: {e}")
        raise

def sanitize_uri(uri: str) -> str:
    if '#' in uri:
        main, frag = uri.split('#', 1)
        safe_frag = urllib.parse.quote(frag)
        return f"{main}#{safe_frag}"
    return uri

def is_valid_node_format(node: str) -> bool:
    if not node or "://" not in node: return False
    scheme, _, rest = node.partition("://")
    scheme = scheme.lower()
    
    valid_schemes = {"vmess", "vless", "ss", "trojan", "ssr", "hysteria", "hysteria2", "tuic", "snell"}
    if scheme not in valid_schemes: return False
        
    if scheme == "vmess":
        try:
            payload = rest.split('?')[0].split('#')[0]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            data = json.loads(decoded)
            if not isinstance(data, dict): return False
            if not data.get("add") or not data.get("port") or not data.get("id"): return False
            for v in data.values():
                if v is None: return False
            return True
        except Exception: return False
            
    elif scheme in ("vless", "trojan"):
        try:
            parsed = urllib.parse.urlparse(node.split('#')[0])
            return bool(parsed.hostname and parsed.port and parsed.username)
        except Exception: return False

    elif scheme == "ss":
        try:
            parsed = urllib.parse.urlparse(node.split('#')[0])
            return bool(parsed.hostname)
        except Exception: return False

    elif scheme in ("ssr", "hysteria", "hysteria2", "tuic", "snell"):
        return len(rest.split('#')[0]) > 10
        
    return False

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def wait_for_api_ready(api_port, process, timeout=API_STARTUP_TIMEOUT):
    api_url = f"http://127.0.0.1:{api_port}/version"
    for attempt in range(timeout):
        if process.poll() is not None: return False
        try:
            req = urllib.request.Request(api_url, method="GET")
            with urllib.request.urlopen(req, timeout=1) as res: return True
        except Exception: time.sleep(1)
    return False

def test_proxy_delay(api_port, proxy_name, timeout_ms):
    encoded_name = urllib.parse.quote(proxy_name)
    url = f"http://127.0.0.1:{api_port}/proxies/{encoded_name}/delay?url={urllib.parse.quote(TEST_URL)}&timeout={timeout_ms}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=8) as res:
            data = json.loads(res.read().decode())
            if "delay" in data and data["delay"] > 0:
                return proxy_name, data["delay"]
    except Exception: pass
    return None, None

def process_chunk(chunk_nodes, timeout_ms):
    valid_nodes = []
    api_port = get_free_port()
    
    sanitized_nodes = [sanitize_uri(n) for n in chunk_nodes]
    raw_text = "\n".join(sanitized_nodes)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
        f.write(raw_text)
        sub_file = f.name
        
    # 【关键修改】：将 log-level 改为 info，捕获所有解析警告
    config_yaml = f"""
port: 7890
socks-port: 7891
external-controller: 127.0.0.1:{api_port}
log-level: info
proxy-providers:
  chunk-provider:
    type: file
    format: text
    path: "{sub_file}"
    health-check:
      enable: false
proxy-groups:
  - name: ChunkGroup
    type: select
    use:
      - chunk-provider
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
        f.write(config_yaml)
        config_file = f.name
        
    log_file = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False, encoding='utf-8')
    log_file_name = log_file.name
    log_file.close()

    process = None
    try:
        process = subprocess.Popen(
            [MIHOMO_BINARY, "-d", ".", "-f", config_file],
            stdout=subprocess.DEVNULL,
            stderr=open(log_file_name, 'a'),
            cwd="."
        )
        
        if not wait_for_api_ready(api_port, process, timeout=API_STARTUP_TIMEOUT):
            return valid_nodes
            
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{api_port}/providers/proxies/chunk-provider", method="GET")
            with urllib.request.urlopen(req, timeout=3) as res:
                data = json.loads(res.read().decode())
                provider_proxies = [p for p in data.get("proxies", []) if p["name"] not in ("DIRECT", "REJECT", "GLOBAL")]
        except Exception as e:
            logger.error(f"Failed to get provider proxies from API: {e}")
            return valid_nodes

        if len(provider_proxies) != len(chunk_nodes):
            logger.warning(f"Proxy count mismatch! Expected {len(chunk_nodes)}, got {len(provider_proxies)}.")
            try:
                with open(log_file_name, 'r', encoding='utf-8') as lf:
                    logs = [line.strip() for line in lf if line.strip()]
                    # 提取包含解析失败关键字的日志
                    parse_errors = [l for l in logs if any(k in l.lower() for k in ['parse', 'fail', 'error', 'unsupported', 'invalid', 'reject', 'unknown'])]
                    if parse_errors:
                        logger.warning(f"Mihomo rejected nodes. Sample errors:")
                        unique_errors = list(set([e.split('msg=')[-1].strip('"') if 'msg=' in e else e for e in parse_errors]))[:5]
                        for err in unique_errors:
                            logger.warning(f"  > {err}")
                    elif logs:
                        logger.warning(f"Mihomo log (no specific parse errors found, showing raw):")
                        for l in logs[:3]:
                            logger.warning(f"  > {l}")
            except Exception as e:
                logger.warning(f"Failed to read Mihomo log: {e}")
                
            # 【终极诊断】：抽样打印被 Python 认为 valid，但被 Mihomo 丢弃的节点真面目
            samples = random.sample(chunk_nodes, min(3, len(chunk_nodes)))
            logger.warning(f"Sample 'valid' nodes that Mihomo might be rejecting:")
            for s in samples:
                logger.warning(f"  > {s[:120]}...")

        if provider_proxies:
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {
                    executor.submit(test_proxy_delay, api_port, p["name"], timeout_ms): idx 
                    for idx, p in enumerate(provider_proxies)
                }
                for future in as_completed(futures):
                    idx = futures[future]
                    proxy_name, delay = future.result()
                    if proxy_name:
                        valid_nodes.append(chunk_nodes[idx])
                        
    except Exception as e:
        logger.error(f"Error processing chunk: {e}")
    finally:
        if process and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill()
            
        for tmp_file in [sub_file, config_file, log_file_name]:
            if os.path.exists(tmp_file):
                try: os.remove(tmp_file)
                except OSError: pass
                    
    return valid_nodes

def validate_nodes_with_mihomo(input_file: str, timeout_ms: int = 5000) -> list:
    logger.info("Initializing node testing validation process via Mihomo Core (Chunked mode)...")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_nodes = [line.strip() for line in f if line.strip() and "://" in line]
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        return []
        
    clean_nodes = [node for node in raw_nodes if is_valid_node_format(node)]
    filtered_count = len(raw_nodes) - len(clean_nodes)
    if filtered_count > 0:
        logger.warning(f"Pre-validation filtered out {filtered_count} malformed/unsupported nodes.")
        
    logger.info(f"Total valid-format nodes to test: {len(clean_nodes)}")
    
    all_valid_nodes = []
    total_chunks = (len(clean_nodes) + CHUNK_SIZE - 1) // CHUNK_SIZE
    
    for i in range(0, len(clean_nodes), CHUNK_SIZE):
        chunk = clean_nodes[i:i+CHUNK_SIZE]
        chunk_idx = (i // CHUNK_SIZE) + 1
        logger.info(f"Processing chunk {chunk_idx}/{total_chunks} ({len(chunk)} nodes)...")
        
        valid_in_chunk = process_chunk(chunk, timeout_ms)
        all_valid_nodes.extend(valid_in_chunk)
        logger.info(f"Chunk {chunk_idx} complete: {len(valid_in_chunk)} nodes passed.")
        
    logger.info(f"Validation complete: {len(all_valid_nodes)} nodes passed out of {len(clean_nodes)}")
    return all_valid_nodes

if __name__ == "__main__":
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        if not os.path.exists(MIHOMO_BINARY):
            download_mihomo_core()
        results = validate_nodes_with_mihomo(test_file, timeout_ms=5000)
        print(f"Final valid count: {len(results)}")
    else:
        logger.info("Usage: python validate_nodes_mihomo.py <input_file.txt>")
