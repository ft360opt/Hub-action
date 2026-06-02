#!/usr/bin/env python3
"""
改进的 Mihomo 节点验证模块
集成到 fetch_nodes.py，用于替换 test_tcp 函数

关键改进：
1. 动态端口分配（防止冲突）
2. 自动下载最新二进制
3. GitHub Actions 兼容性
4. 降级处理机制
5. 完整的错误恢复
"""

import base64
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# ===========================
# 配置
# ===========================
VALIDATION_CONFIG = {
    "timeout_ms": 2500,
    "max_workers": 15,
    "test_url": "https://www.google.com/generate_204",
    "api_startup_timeout": 15,  # 最多等待15秒让API就绪
    "enable_mihomo": True,  # 可通过环境变量覆盖
}

# GitHub Actions 环境检测
IS_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true"
MIHOMO_BINARY = "./mihomo"
CONFIG_FILE = "config.yaml"
REPORT_PATH = "data/speedtest_report.json"

logger.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
) if not logger.handlers else None


# ===========================
# 工具函数
# ===========================

def get_free_port():
    """动态获取系统闲置的可用端口"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            logger.info(f"Allocated free port: {port}")
            return port
    except Exception as e:
        logger.error(f"Failed to allocate port: {e}")
        return 9090  # Fallback


def download_mihomo_core():
    """智能下载最新版 Mihomo 内核"""
    if os.path.exists(MIHOMO_BINARY):
        logger.info("Mihomo binary already exists, skipping download")
        return True

    logger.info("Attempting to download latest Mihomo release...")

    try:
        # 方案A: 从 GitHub Releases API 获取最新版本
        api_url = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github.v3+json"}
        
        req = urllib.request.Request(api_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as res:
            release_info = json.loads(res.read().decode())

        # 根据系统选择合适的二进制
        download_url = None
        target_pattern = "linux-amd64-compatible"
        
        for asset in release_info.get("assets", []):
            asset_name = asset.get("name", "")
            if target_pattern in asset_name and asset_name.endswith(".gz"):
                download_url = asset["browser_download_url"]
                logger.info(f"Found compatible release: {asset_name}")
                break

        if not download_url:
            logger.warning("Compatible binary not found, trying generic linux-amd64")
            for asset in release_info.get("assets", []):
                if "linux-amd64" in asset["name"] and asset["name"].endswith(".gz"):
                    download_url = asset["browser_download_url"]
                    break

        if not download_url:
            logger.error("No suitable Mihomo release found")
            return False

        logger.info(f"Downloading from: {download_url}")
        gz_path = "mihomo.gz"
        urllib.request.urlretrieve(download_url, gz_path)

        # 解压
        import gzip
        with gzip.open(gz_path, "rb") as f_in, open(MIHOMO_BINARY, "wb") as f_out:
            f_out.write(f_in.read())

        os.chmod(MIHOMO_BINARY, 0o755)
        os.remove(gz_path)
        logger.info("Mihomo binary ready")
        return True

    except Exception as e:
        logger.error(f"Failed to download Mihomo: {e}")
        logger.warning("Will fallback to TCP-only validation")
        return False


def parse_and_build_config(api_port, node_file_path):
    """解析节点文件并生成 Mihomo 配置"""
    if not os.path.exists(node_file_path):
        logger.error(f"Node file not found: {node_file_path}")
        return False

    with open(node_file_path, "r", encoding="utf-8") as f:
        raw_content = f.read().strip()

    if not raw_content:
        logger.error("Node file is empty")
        return False

    # 尝试解码 Base64 订阅
    if re.match(r"^[A-Za-z0-9+/=\s]+$", raw_content) and len(raw_content) > 100:
        try:
            decoded = base64.b64decode(raw_content).decode("utf-8", errors="ignore")
            if "://" in decoded:  # 验证确实是节点链接
                raw_content = decoded
                logger.info("Successfully decoded base64 subscription")
        except Exception:
            logger.debug("Failed to decode as base64, treating as plain text")

    # 核心配置（轻量级）
    config_base = {
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{api_port}",
        "external-ui-url": "",
        "secret": "",
        "proxies": [],
        "proxy-groups": [],
        "rules": [],
    }

    # 格式检测
    if "proxies:" in raw_content:
        # 已经是 YAML 格式
        logger.info("Detected YAML format, using as-is")
        try:
            import yaml
            parsed = yaml.safe_load(raw_content)
            if isinstance(parsed, dict) and "proxies" in parsed:
                config_base["proxies"] = parsed.get("proxies", [])
            else:
                logger.warning("Invalid YAML structure")
                return False
        except ImportError:
            # 如果没有 yaml 库，直接写入（Mihomo 会自动解析）
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                f.write(raw_content)
            return True
    else:
        # 链接列表格式
        logger.info("Detected link format, converting to config")
        links = [line.strip() for line in raw_content.split("\n") if line.strip() and "://" in line]
        config_base["proxies"] = links

    # 写入配置
    try:
        import yaml
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(config_base, f, allow_unicode=True)
    except ImportError:
        # 降级：使用 JSON（Mihomo 完全兼容）
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(config_base, ensure_ascii=False, indent=2))

    logger.info(f"Generated config with {len(config_base['proxies'])} proxies")
    return True


def wait_for_api_ready(api_port, timeout=None):
    """等待 API 就绪"""
    if timeout is None:
        timeout = VALIDATION_CONFIG["api_startup_timeout"]

    api_url = f"http://127.0.0.1:{api_port}/version"
    logger.info(f"Waiting for API to be ready at {api_url}...")

    for attempt in range(timeout):
        try:
            req = urllib.request.Request(api_url, method="GET")
            with urllib.request.urlopen(req, timeout=1) as res:
                data = json.loads(res.read().decode())
                logger.info(f"API ready: {data.get('version', 'unknown')}")
                return True
        except Exception:
            if attempt % 3 == 0:
                logger.debug(f"API not ready, attempt {attempt + 1}/{timeout}")
            time.sleep(1)

    logger.error("API failed to start within timeout")
    return False


def test_single_node(api_port, proxy_name):
    """测试单个节点"""
    try:
        encoded_name = urllib.parse.quote(proxy_name)
        url = (
            f"http://127.0.0.1:{api_port}/proxies/{encoded_name}/delay"
            f"?url={urllib.parse.quote(VALIDATION_CONFIG['test_url'])}"
            f"&timeout={VALIDATION_CONFIG['timeout_ms']}"
        )
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read().decode())
            delay = data.get("delay", -1)
            if delay > 0:
                logger.debug(f"✓ {proxy_name}: {delay}ms")
            return proxy_name, delay
    except Exception as e:
        logger.debug(f"✗ {proxy_name}: {type(e).__name__}")
        return proxy_name, -1


def execute_speedtest(api_port):
    """执行批量测速"""
    if not wait_for_api_ready(api_port):
        logger.error("Speedtest aborted: API not ready")
        return {}

    try:
        logger.info("Fetching proxy list...")
        with urllib.request.urlopen(
            f"http://127.0.0.1:{api_port}/proxies", timeout=5
        ) as res:
            proxies_data = json.loads(res.read().decode())

        all_proxies = proxies_data.get("proxies", {})
        # 排除系统组
        target_nodes = [
            name
            for name, info in all_proxies.items()
            if info.get("type") not in ["Selector", "URLTest", "Fallback", "Compatible", "Direct"]
        ]

        logger.info(f"Testing {len(target_nodes)} proxies...")

        results = {}
        with ThreadPoolExecutor(max_workers=VALIDATION_CONFIG["max_workers"]) as executor:
            futures = {
                executor.submit(test_single_node, api_port, name): name
                for name in target_nodes
            }
            completed = 0
            for future in as_completed(futures):
                name, delay = future.result()
                if delay > 0:
                    results[name] = delay
                completed += 1
                if completed % max(1, len(target_nodes) // 5) == 0:
                    logger.info(f"Progress: {completed}/{len(target_nodes)}")

        # 排序并输出
        sorted_results = sorted(results.items(), key=lambda x: x[1])
        logger.info(f"\n{'='*60}")
        logger.info("🚀 Top 10 Fastest Proxies")
        logger.info(f"{'='*60}")
        for name, delay in sorted_results[:10]:
            logger.info(f"  {delay:4d}ms  {name}")
        logger.info(f"{'='*60}\n")

        # 保存报告
        os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
        with open(REPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(dict(sorted_results), f, ensure_ascii=False, indent=2)
        logger.info(f"Report saved to {REPORT_PATH}")

        return dict(sorted_results)

    except Exception as e:
        logger.error(f"Speedtest error: {e}")
        return {}


def validate_nodes_with_mihomo(raw_node_list, node_file_path="data/nodeALL.txt"):
    """
    Mihomo 验证入口函数
    
    集成到 fetch_nodes.py 的主函数中
    
    Args:
        raw_node_list: 原始节点列表
        node_file_path: 节点文件路径
    
    Returns:
        valid_nodes_list: 验证通过的节点列表
    """
    # 检查是否应该使用 Mihomo
    if not VALIDATION_CONFIG["enable_mihomo"]:
        logger.warning("Mihomo validation disabled, falling back to TCP")
        return []

    # 检查环境和依赖
    if not os.path.exists(MIHOMO_BINARY) and not download_mihomo_core():
        logger.warning("Mihomo not available, falling back to TCP")
        return []

    api_port = get_free_port()

    try:
        # 生成配置
        if not parse_and_build_config(api_port, node_file_path):
            logger.warning("Failed to generate config")
            return []

        # 启动 Mihomo
        logger.info(f"Starting Mihomo on port {api_port}...")
        process = subprocess.Popen(
            [MIHOMO_BINARY, "-f", CONFIG_FILE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            # 执行测速
            valid_results = execute_speedtest(api_port)
            valid_nodes = [name for name, delay in valid_results.items() if delay > 0]
            logger.info(f"Validation complete: {len(valid_nodes)} nodes passed")
            return valid_nodes

        finally:
            # 清理
            logger.info("Stopping Mihomo...")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            
            if os.path.exists(CONFIG_FILE):
                os.remove(CONFIG_FILE)

    except Exception as e:
        logger.error(f"Mihomo validation failed: {e}")
        return []


if __name__ == "__main__":
    # 独立测试模式
    print("This module is designed to be imported into fetch_nodes.py")
    print("Do not run directly")
