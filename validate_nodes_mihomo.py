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
    """下载适用于当前环境的 Mihomo 内核"""
    abs_binary_path = os.path.abspath(MIHOMO_BINARY)
    if os.path.exists(abs_binary_path):
        logger.info(f"Mihomo binary already exists at {abs_binary_path}")
        return

    logger.info(f"Downloading Mihomo core to {abs_binary_path}...")
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        arch = machine

    if system == "linux":
        download_url = f"https://github.com/MetaCubeX/mihomo/releases/download/v1.18.0/mihomo-linux-{arch}-v1.18.0.gz"
    elif system == "darwin":
        download_url = f"https://github.com/MetaCubeX/mihomo/releases/download/v1.18.0/mihomo-darwin-{arch}-v1.18.0.gz"
    else:
        raise RuntimeError(f"Unsupported OS: {system}")

    gz_file = "mihomo.gz"
    try:
        req = urllib.request.Request(download_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(gz_file, 'wb') as out_file:
            out_file.write(response.read())
        
        import gzip
        with gzip.open(gz_file, 'rb') as f_in:
            with open(abs_binary_path, 'wb') as f_out:
                f_out.write(f_in.read())
        
        os.chmod(abs_binary_path, 0o755)
        if os.path.exists(gz_file):
            os.remove(gz_file)
        logger.info(f"Successfully downloaded and extracted to {abs_binary_path}")
    except Exception as e:
        logger.error(f"Failed to download Mihomo core: {e}")
        raise

def is_valid_node_format(node: str) -> bool:
    """预清洗：拦截会导致 Mihomo 解析 Panic 的畸形链接"""
    if not node or "://" not in node:
        return False
    scheme, _, rest = node.partition("://")
    scheme = scheme.lower()
    
    if scheme == "vmess":
        try:
            payload = rest
            payload += "=" * ((4 - len(payload) % 4) % 4)
            decoded = base64.b64decode(payload).decode('utf-8')
            data = json.loads(decoded)
            return bool(data.get("add") and data.get("port") and data.get("id"))
        except Exception:
            return False
            
    elif scheme in ("ss", "ssr", "trojan", "vless", "hysteria", "hysteria2", "tuic", "snell"):
        return len(rest) > 10 and (":" in rest or "@" in rest)
        
    return True

def get_free_port():
    """获取一个操作系统分配的空闲端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def wait_for_api_ready(api_port, process, timeout=API_STARTUP_TIMEOUT):
    """等待 API 就绪，并增加进程崩溃检测"""
    api_url = f"http://127.0.0.1:{api_port}/version"
    logger.info(f"Waiting for API to be ready at {api_url}...")
    
    for attempt in range(timeout):
        if process.poll() is not None:
            err = process.stderr.read().decode('utf-8', errors='ignore') if process.stderr else "No stderr"
            logger.error(f"Mihomo crashed on startup (Exit: {process.returncode}). Error:\n{err}")
            return False
            
        try:
            req = urllib.request.Request(api_url, method="GET")
            with urllib.request.urlopen(req, timeout=1) as res:
                data = json.loads(res.read().decode())
                logger.info(f"API ready: {data.get('version', 'unknown')}")
                return True
        except Exception:
            time.sleep(1)
            
    logger.error("API failed to start within timeout")
    return False

def test_proxy_delay(api_port, proxy_name, timeout_ms):
    """测试单个代理的延迟"""
    encoded_name = urllib.parse.quote(proxy_name)
    url = f"http://127.0.0.1:{api_port}/proxies/{encoded_name}/delay?url={urllib.parse.quote(TEST_URL)}&timeout={timeout_ms}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=8) as res:
            data = json.loads(res.read().decode())
            if "delay" in data and data["delay"] > 0:
                return proxy_name, data["delay"]
    except Exception:
        pass
    return None, None

def process_chunk(chunk_nodes, timeout_ms):
    """处理单个分块的节点"""
    valid_nodes = []
    api_port = get_free_port()
    
    # 【核心修复】：type: file 的 proxy-providers 不支持 Base64 自动解码！
    # 必须直接写入明文（每行一个节点链接），Mihomo 才能正确解析。
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
        f.write("\n".join(chunk_nodes))
        sub_file = f.name
        
    config_yaml = f"""
port: 7890
socks-port: 7891
external-controller: 127.0.0.1:{api_port}
log-level: silent
proxy-providers:
  chunk-provider:
    type: file
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

    process = None
    try:
        process = subprocess.Popen(
            [MIHOMO_BINARY, "-d", ".", "-f", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
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
            logger.warning(f"Proxy count mismatch! Expected {len(chunk_nodes)}, got {len(provider_proxies)}. Mapping might be inaccurate.")

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
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                
        for tmp_file in [sub_file, config_file]:
            if os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except OSError:
                    pass
                    
    return valid_nodes

def validate_nodes_with_mihomo(input_file: str, timeout_ms: int = 5000) -> list:
    """主入口：读取文件，内部分块处理，返回有效节点原始链接列表"""
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
        logger.warning(f"Pre-validation filtered out {filtered_count} malformed nodes to prevent Mihomo panic.")
        
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
