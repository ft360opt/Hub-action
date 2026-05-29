import os
import re
import json
import base64
import socket
import logging
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging - safe for CI/CD environments
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# 1. 配置搜索与测速参数
# 【优化】针对中国大陆用户的搜索关键词，包含中文和GFW绕过相关术语
SEARCH_KEYWORDS = [
    "v2ray-china",           # 明确指向中国用户
    "clash-china",           # 在中国很受欢迎
    "free-ssr",              # SSR在中国仍然流行
    "shadowsocks-share",     # 中国常见的协议
    "trojan-subscribe",      # 越来越流行
    "warp-config",           # Cloudflare WARP在中国是常见的绕过方式
    "bypass-gfw",            # 直接指向GFW绕过需求
    "china-nodes",           # 明确的中国焦点
    "v2ray-share",           # 保留原有的通用关键词
    "free-nodes",            # 保留原有的通用关键词
    "订阅",                   # 中文：订阅
    "节点",                   # 中文：节点
    "梯子",                   # 中文俚语：梯子（代理工具）
    "翻墙",                   # 中文：越墙（绕过审查）
]

MAX_REPOS_TO_CHECK = 10       # 每个关键词检查的最新仓库数（从5增加到10以获得更多结果）
TIMEOUT_SECONDS = 3.0         # 节点延迟测试超时时间（秒）
MAX_WORKERS = 50              # 测速并发线程数

# BUG FIX #1: 添加更多文件名组合，包含扩展名
POSSIBLE_FILES = [
    'sub', 'sub.txt', 'sub.yaml', 'sub.yml',
    'v2ray', 'v2ray.txt', 'v2ray.yaml', 'v2ray.yml',
    'node.txt', 'nodes.txt', 'nodes.yaml', 'nodes.yml',
    'subscribe.txt', 'subscribe.yaml', 'subscribe.yml',
    'clash', 'clash.txt', 'clash.yaml', 'clash.yml',
    'proxy.txt', 'proxy.yaml',
]

def get_github_raw_links():
    """动态从 GitHub 搜索最新更新的仓库，并精准生成 Raw 原始文件链接"""
    links = []
    token = os.getenv("GITHUB_TOKEN")
    headers = {"User-Agent": "Mozilla/5.0"}
    if token:
        headers["Authorization"] = f"token {token}"
        # Log safely without exposing the token
        logger.info("✓ GitHub token loaded from environment")
    else:
        logger.warning("⚠ No GitHub token found, using unauthenticated requests")
        
    for kw in SEARCH_KEYWORDS:
        # 正确做法：关键词进行编码，排序使用 &sort=updated 独立参数
        encoded_kw = urllib.parse.quote(kw)
        url = f"https://api.github.com/search/repositories?q={encoded_kw}&sort=updated&order=desc&per_page={MAX_REPOS_TO_CHECK}"
        
        # Safe logging: show keyword instead of full URL
        logger.info(f"🔍 Searching repositories with keyword: '{kw}'")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                items = data.get('items', [])
                logger.info(f"   Found {len(items)} recently updated repos for '{kw}'")
                
                for item in items:
                    owner = item['owner']['login']
                    repo = item['name']
                    # 动态获取默认分支 (master 或 main)
                    branch = item.get('default_branch', 'main')
                    
                    # BUG FIX #1: 使用改进的文件列表，包含扩展名
                    for file in POSSIBLE_FILES:
                        # 【核心修复】必须是 raw.githubusercontent.com 且注意各处的正斜杠 /
                        links.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file}")
        except Exception as e:
            # Safe error logging without exposing sensitive details
            logger.error(f"❌ Failed to search keyword '{kw}': {type(e).__name__}")
            logger.debug(f"   Error details: {str(e)}")
            
    return list(set(links))


def parse_clash_yaml(content):
    """
    使用正则纯手工解析 Clash YAML 格式中的 proxies 节点。
    支持 type 为 ss, vmess, vless, trojan 的转换。
    """
    extracted_nodes = []
    # 正则提取 proxies 列表区块（粗略匹配）
    proxies_match = re.search(r'proxies:\s*\n(.*?)(\n\s*\n|\n\S|$)', content, re.DOTALL)
    if not proxies_match:
        return extracted_nodes
        
    proxy_block = proxies_match.group(1)
    # 按 yaml 中的每一个节点项 `- name:` 割开
    items = re.split(r'\n\s*-\s*', proxy_block)
    
    # BUG FIX #2: 移除第一项的前导空白，确保正确解析
    if items:
        items[0] = items[0].lstrip()
    
    for item in items:
        if not item.strip():
            continue
        
        # 提取公共字段
        p_type = re.search(r'type:\s*([a-zA-Z0-9_-]+)', item)
        server = re.search(r'server:\s*([^\s]+)', item)
        port = re.search(r'port:\s*([0-9]+)', item)
        # BUG FIX #7: 改进名称提取，正确处理引号
        name_match = re.search(r'name:\s*(?:["\']([^"\']+)["\']|([^\s]+))', item)
        
        if not (p_type and server and port):
            continue
            
        t = p_type.group(1).lower()
        srv = server.group(1).strip("'\"")
        # BUG FIX #3: 将端口转换为整数，保持一致性
        pt = int(port.group(1))
        # 提取名称
        if name_match:
            nm = urllib.parse.quote((name_match.group(1) or name_match.group(2)).strip())
        else:
            nm = "ClashNode"
        
        # 针对不同协议提取关键字段并拼装成通用方舟链接
        if t == "ss":
            cipher = re.search(r'cipher:\s*([^\s]+)', item)
            pwd = re.search(r'password:\s*([^\s]+)', item)
            if cipher and pwd:
                c = cipher.group(1).strip("'\"")
                p = pwd.group(1).strip("'\"")
                # ss://base64(cipher:password)@server:port#name
                userinfo = base64.b64encode(f"{c}:{p}".encode()).decode().strip()
                extracted_nodes.append(f"ss://{userinfo}@{srv}:{pt}#{nm}")
                
        elif t == "vmess":
            uuid = re.search(r'uuid:\s*([^\s]+)', item)
            if uuid:
                uid = uuid.group(1).strip("'\"")
                # 构造 vmess 标准 json 结构
                v_json = {"v": "2", "ps": nm, "add": srv, "port": str(pt), "id": uid, "aid": "0", "scy": "auto", "net": "tcp", "type": "none", "host": "", "path": "", "tls": ""}
                # 如果有 tls 或 transport
                if "tls: true" in item: v_json["tls"] = "tls"
                v_b64 = base64.b64encode(json.dumps(v_json).encode()).decode().strip()
                extracted_nodes.append(f"vmess://{v_b64}")
                
        elif t == "vless":
            uuid = re.search(r'uuid:\s*([^\s]+)', item)
            if uuid:
                uid = uuid.group(1).strip("'\"")
                extracted_nodes.append(f"vless://{uid}@{srv}:{pt}?encryption=none#{nm}")
                
        elif t == "trojan":
            pwd = re.search(r'password:\s*([^\s]+)', item)
            if pwd:
                p = pwd.group(1).strip("'\"")
                extracted_nodes.append(f"trojan://{p}@{srv}:{pt}#{nm}")
                
    return extracted_nodes

def extract_and_decode(url):
    """请求源内容，并智能兼容 Base64 订阅和 Clash YAML 格式"""
    nodes = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            content = resp.read().decode('utf-8', errors='ignore').strip()
            if not content:
                return nodes
            
            # 判断如果是 Clash YAML 格式
            if "proxies:" in content and ("server:" in content or "port:" in content):
                return parse_clash_yaml(content)
            
            # 如果可能是 Base64 编码格式
            if not any(p in content for p in ["vmess://", "vless://", "ss://", "trojan://"]):
                try:
                    padded_content = content + "=" * ((4 - len(content) % 4) % 4)
                    content = base64.b64decode(padded_content).decode('utf-8', errors='ignore')
                except Exception as e:
                    # BUG FIX #5: 添加日志而不是silent pass
                    logger.debug(f"Base64 decode failed for {url[:50]}...: {type(e).__name__}")
                    pass
            
            # 正则提取标准链接
            protocol_pattern = r'(vmess|vless|ss|trojan):\/\/[^\s]+'
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if re.match(protocol_pattern, line):
                    nodes.append(line)
    except Exception as e:
        logger.debug(f"Failed to extract nodes from URL: {type(e).__name__}")
    return nodes

def get_node_signature(node):
    """
    BUG FIX #4: 提取节点的真实 server:port 签名用于去重。
    这确保相同 server:port 的节点被正确识别为重复，无论名称如何。
    """
    server, port = parse_server_port(node)
    return f"{server}:{port}" if (server and port) else None

def parse_server_port(node):
    """从节点 URL ���提取服务器 IP/域名 和 端口，用于连接测试"""
    try:
        if node.startswith("vmess://"):
            # vmess 需要解开其内部的 base64 json
            b64_str = node.split("vmess://")[1].strip()
            padded = b64_str + "=" * ((4 - len(b64_str) % 4) % 4)
            cfg = json.loads(base64.b64decode(padded).decode('utf-8', errors='ignore'))
            return cfg.get("add"), int(cfg.get("port"))
        else:
            # vless, ss, trojan 格式类似: protocol://userinfo@server:port#name
            main_part = node.split("://")[1].split("#")[0]
            if "@" in main_part:
                main_part = main_part.split("@")[1]
            # 去掉可能存在的 URL 参数
            main_part = main_part.split("?")[0]
            
            if ":" in main_part:
                # BUG FIX #3: 正确处理端口解析（保持一致的整数类型）
                server, port_str = main_part.rsplit(":", 1)  # 从右边分割以处理IPv6
                return server, int(port_str)
    except Exception as e:
        logger.debug(f"Failed to parse server/port from node: {type(e).__name__}")
        pass
    return None, None

def test_tcp_connectivity(node):
    """通过 TCP 三次握手测试服务器断网/死活（不检测是否被墙，但能过滤大批死节点）"""
    server, port = parse_server_port(node)
    if not server or not port:
        return None
    try:
        # 使用 Socket 尝试建立底层 TCP 连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SECONDS)
        sock.connect((server, port))
        sock.close()
        return node  # 连接成功，保留
    # BUG FIX #6: 改进异常处理，添加日志
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        logger.debug(f"Node connectivity failed ({server}:{port}): {type(e).__name__}")
        return None
    except Exception as e:
        logger.debug(f"Unexpected error testing node ({server}:{port}): {type(e).__name__}")
        return None

def main():
    # 确保数据目录存在
    os.makedirs("data", exist_ok=True)
    
    logger.info("1. Retrieving latest GitHub node repositories...")
    raw_urls = get_github_raw_links()
    logger.info(f"Found {len(raw_urls)} potential target file links.")
    
    # 2. 抓取与清洗
    all_raw_nodes = []
    for url in raw_urls:
        all_raw_nodes.extend(extract_and_decode(url))
    logger.info(f"2. Node extraction complete. Raw total: {len(all_raw_nodes)}")
    
    # 3. BUG FIX #4: 改进去重逻辑，基于真实的 server:port 而不是完整 URL
    unique_nodes = []
    seen_signatures = set()
    for node in all_raw_nodes:
        signature = get_node_signature(node)
        if signature and signature not in seen_signatures:
            seen_signatures.add(signature)
            unique_nodes.append(node)
    logger.info(f"3. Core deduplication complete. Remaining unique nodes: {len(unique_nodes)}")
    
    # 【新增】将未测速的原始节点列表进行 Base64 编码并保存到 data/nodeALL.txt
    all_merged_text = "\n".join(unique_nodes)
    all_b64_output = base64.b64encode(all_merged_text.encode('utf-8')).decode('utf-8')
    with open("data/nodeALL.txt", "w", encoding="utf-8") as f:
        f.write(all_b64_output)
    logger.info(f"📝 Raw unique node list saved to: data/nodeALL.txt ({len(all_b64_output)} bytes)")
    
    # 4. 高并发多线程测速筛选
    logger.info(f"4. Starting multi-threaded speed test (threads: {MAX_WORKERS})...")
    live_nodes = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_tcp_connectivity, node): node for node in unique_nodes}
        for future in as_completed(futures):
            res = future.result()
            if res:
                live_nodes.append(res)
                
    logger.info(f"5. Filtering complete. Live usable nodes: {len(live_nodes)} / {len(unique_nodes)}")
    
    # 5. 打包测速通过的节点为 Base64 格式并保存到 data/nodes.txt
    merged_text = "\n".join(live_nodes)
    b64_output = base64.b64encode(merged_text.encode('utf-8')).decode('utf-8')
    
    with open("data/nodes.txt", "w", encoding="utf-8") as f:
        f.write(b64_output)
        
    logger.info(f"🎉 Automation complete, speed-tested subscription saved to: data/nodes.txt ({len(b64_output)} bytes)")

if __name__ == "__main__":
    main()
