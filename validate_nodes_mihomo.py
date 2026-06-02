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
MIHOMO_BINARY = os.environ.get("MIHOMO_BINARY", "mihomo")
CHUNK_SIZE = 500                                           # 每批处理节点数，避免 GitHub Actions OOM
API_STARTUP_TIMEOUT = 30                                   # API 启动等待超时(秒)
TEST_URL = "http://www.gstatic.com/generate_204"           # 测速目标 URL
# ==========================================

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def download_mihomo_core():
    """下载适用于当前环境的 Mihomo 内核 (补回此函数以兼容您的 GitHub Actions)"""
    if os.path.exists(MIHOMO_BINARY):
        logger.info(f"Mihomo binary already exists at {MIHOMO_BINARY}")
        return

    logger.info("Downloading Mihomo core...")
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # 映射架构名称以匹配 Mihomo 的发布命名规范
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        arch = machine

    if system == "linux":
        # 使用 meta 版本的稳定 release (可根据需要调整为具体版本号或 latest)
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
        
        # 解压
        import gzip
        with gzip.open(gz_file, 'rb') as f_in:
            with open(MIHOMO_BINARY, 'wb') as f_out:
                f_out.write(f_in.read())
        
        # 赋予执行权限
        os.chmod(MIHOMO_BINARY, 0o755)
        os.remove(gz_file)
        logger.info(f"Successfully downloaded and extracted {MIHOMO_BINARY}")
    except Exception as e:
        logger.error(f"Failed to download Mihomo core: {e}")
        raise

def get_free_port():
    """获取一个操作系统分配的空闲端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def wait_for_api_ready(api_port, process, timeout=API_STARTUP_TIMEOUT):
    """等待 API 就绪，并增加进程崩溃检测（优化2）"""
    api_url = f"http://127.0.0.1:{api_port}/version"
    logger.info(f"Waiting for API to be ready at {api_url}...")
    
    for attempt in range(timeout):
        # 检查进程是否已经崩溃退出
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
        with urllib.request.urlopen(req, timeout=5) as res: # API 调用本身给 5s 超时
            data = json.loads(res.read().decode())
            if "delay" in data and data["delay"] > 0:
                return proxy_name, data["delay"]
    except Exception:
        pass
    return None, None

def process_chunk(chunk_nodes, timeout_ms):
    """处理单个分块的节点（优化1 + 优化3）"""
    valid_nodes = []
    api_port = get_free_port()
    
    # 1. 将当前 chunk 的原始链接转为 Base64，写入临时订阅文件
    b64_payload = base64.b64encode("\n".join(chunk_nodes).encode('utf-8')).decode('utf-8')
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
        f.write(b64_payload)
        sub_file = f.name
        
    # 2. 生成极简的 Mihomo 配置文件，使用 proxy-providers 加载上述文件
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
        # 3. 启动 Mihomo (开启 stderr 捕获)
        process = subprocess.Popen(
            [MIHOMO_BINARY, "-d", ".", "-f", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            cwd="."
        )
        
        # 4. 等待 API 就绪
        if not wait_for_api_ready(api_port, process, timeout=API_STARTUP_TIMEOUT):
            return valid_nodes
            
        # 5. 获取该 provider 解析后的所有代理列表
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{api_port}/providers/proxies/chunk-provider", method="GET")
            with urllib.request.urlopen(req, timeout=3) as res:
                data = json.loads(res.read().decode())
                provider_proxies = data.get("proxies", [])
        except Exception as e:
            logger.error(f"Failed to get provider proxies from API: {e}")
            return valid_nodes

        # 6. 并发测速
        if provider_proxies:
            with ThreadPoolExecutor(max_workers=50) as executor:
                # 提交测速任务，并保留原始索引以便映射
                futures = {
                    executor.submit(test_proxy_delay, api_port, p["name"], timeout_ms): idx 
                    for idx, p in enumerate(provider_proxies)
                }
                
                for future in as_completed(futures):
                    idx = futures[future]
                    proxy_name, delay = future.result()
                    if proxy_name:
                        # 测速通过，通过索引取回原始链接！
                        valid_nodes.append(chunk_nodes[idx])
                        
    except Exception as e:
        logger.error(f"Error processing chunk: {e}")
    finally:
        # 7. 严格清理资源，防止 GitHub Actions 资源泄漏
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

def validate_nodes_with_mihomo(input_file: str, timeout_ms: int = 3000) -> list:
    """
    主入口：读取文件，内部分块处理，返回有效节点原始链接列表 (优化3)
    调用者 (fetch_nodes.py) 无需任何修改即可使用此函数。
    """
    logger.info("Initializing node testing validation process via Mihomo Core (Chunked mode)...")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_nodes = [line.strip() for line in f if line.strip() and "://" in line]
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        return []
        
    logger.info(f"Total unique raw nodes found: {len(raw_nodes)}")
    
    all_valid_nodes = []
    total_chunks = (len(raw_nodes) + CHUNK_SIZE - 1) // CHUNK_SIZE
    
    for i in range(0, len(raw_nodes), CHUNK_SIZE):
        chunk = raw_nodes[i:i+CHUNK_SIZE]
        chunk_idx = (i // CHUNK_SIZE) + 1
        logger.info(f"Processing chunk {chunk_idx}/{total_chunks} ({len(chunk)} nodes)...")
        
        valid_in_chunk = process_chunk(chunk, timeout_ms)
        all_valid_nodes.extend(valid_in_chunk)
        logger.info(f"Chunk {chunk_idx} complete: {len(valid_in_chunk)} nodes passed.")
        
    logger.info(f"Validation complete: {len(all_valid_nodes)} nodes passed out of {len(raw_nodes)}")
    return all_valid_nodes

# 如果直接运行此脚本，可用于独立测试
if __name__ == "__main__":
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        # 独立测试时也可选择先下载内核
        if not os.path.exists(MIHOMO_BINARY):
            download_mihomo_core()
        results = validate_nodes_with_mihomo(test_file, timeout_ms=3000)
        print(f"Final valid count: {len(results)}")
    else:
        logger.info("Usage: python validate_nodes_mihomo.py <input_file.txt>")
