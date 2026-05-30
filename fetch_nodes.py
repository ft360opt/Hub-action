# =========================
# fetch_nodes.py
# PART 1/2
# =========================

import os
import re
import json
import base64
import socket
import hashlib
import logging
import urllib.request
import urllib.parse
import yaml
import time
import csv
import struct

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# CONFIG
# =========================

SEARCH_KEYWORDS = [
    "v2ray-china",
    "clash-china",
    "free-ssr",
    "shadowsocks-share",
    "trojan-subscribe",
    "warp-config",
    "bypass-gfw",
    "china-nodes",
    "v2ray-share",
    "free-nodes",
    "订阅",
    "节点",
    "梯子",
    "翻墙",
]

MAX_REPOS_PER_KEYWORD = 10
MAX_WORKERS = 80
TIMEOUT_SECONDS = 5
ENABLE_TCP_CHECK = True
ENABLE_PROTOCOL_VALIDATION = True

POSSIBLE_KEYWORDS = [
    "sub",
    "subscribe",
    "node",
    "nodes",
    "clash",
    "proxy",
    "vpn",
    "config",
    "free",
    "share",
]

VALID_EXTENSIONS = [
    ".txt",
    ".yaml",
    ".yml",
    ".conf",
    ".json",
]

OUTPUT_DIR = Path("data")
OUTPUT_DIR.mkdir(exist_ok=True)

# =========================
# LOGGING
# =========================

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

logger = logging.getLogger(__name__)

# =========================
# GITHUB API
# =========================

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"
    logger.info("✓ GitHub token loaded")
else:
    logger.warning("⚠ No GitHub token found")

# =========================
# SOURCE QUALITY TRACKING
# =========================

class SourceQuality:
    def __init__(self):
        self.repo_stats = {}
        self.url_to_repo = {}
        self.protocol_stats = {}
    
    def register_repo(self, owner, repo, stars=0, forks=0, size=0):
        """Register a repository with its metadata"""
        key = f"{owner}/{repo}"
        self.repo_stats[key] = {
            "owner": owner,
            "repo": repo,
            "stars": stars,
            "forks": forks,
            "size": size,
            "files_found": 0,
            "nodes_extracted": 0,
            "nodes_valid": 0,
            "extraction_success": 0,
            "extraction_failed": 0,
        }
        return key
    
    def register_url(self, url, repo_key):
        """Map URL to its source repository"""
        self.url_to_repo[url] = repo_key
    
    def record_file_found(self, repo_key):
        """Increment file count for repo"""
        if repo_key in self.repo_stats:
            self.repo_stats[repo_key]["files_found"] += 1
    
    def record_extraction(self, url, node_count, success=True):
        """Record extraction attempt"""
        repo_key = self.url_to_repo.get(url)
        if repo_key and repo_key in self.repo_stats:
            if success:
                self.repo_stats[repo_key]["nodes_extracted"] += node_count
                self.repo_stats[repo_key]["extraction_success"] += 1
            else:
                self.repo_stats[repo_key]["extraction_failed"] += 1
    
    def record_node_validation(self, node, repo_key):
        """Record if a node passed validation"""
        if repo_key in self.repo_stats:
            self.repo_stats[repo_key]["nodes_valid"] += 1
    
    def record_protocol_validation(self, protocol, valid, error_type=None):
        """Record protocol-specific validation stats"""
        if protocol not in self.protocol_stats:
            self.protocol_stats[protocol] = {
                "total": 0,
                "valid": 0,
                "failed": 0,
                "errors": {}
            }
        
        self.protocol_stats[protocol]["total"] += 1
        if valid:
            self.protocol_stats[protocol]["valid"] += 1
        else:
            self.protocol_stats[protocol]["failed"] += 1
            if error_type:
                self.protocol_stats[protocol]["errors"][error_type] = \
                    self.protocol_stats[protocol]["errors"].get(error_type, 0) + 1
    
    def get_repo_score(self, repo_key):
        """Calculate quality score for a repository (0-100)"""
        if repo_key not in self.repo_stats:
            return 0
        
        stats = self.repo_stats[repo_key]
        
        # Stars: 0-30 points (max at 100 stars)
        stars_score = min(stats["stars"] / 100, 1.0) * 30
        
        # Forks: 0-20 points (max at 50 forks)
        forks_score = min(stats["forks"] / 50, 1.0) * 20
        
        # Extraction success rate: 0-25 points
        total_attempts = stats["extraction_success"] + stats["extraction_failed"]
        if total_attempts > 0:
            success_rate = stats["extraction_success"] / total_attempts
        else:
            success_rate = 0
        success_score = success_rate * 25
        
        # Node validity rate: 0-25 points
        if stats["nodes_extracted"] > 0:
            node_ratio = stats["nodes_valid"] / stats["nodes_extracted"]
        else:
            node_ratio = 0
        node_score = node_ratio * 25
        
        return round(stars_score + forks_score + success_score + node_score, 2)
    
    def export_json(self, filepath):
        """Export quality stats as JSON"""
        stats_list = []
        for repo_key, stats in sorted(
            self.repo_stats.items(),
            key=lambda x: self.get_repo_score(x[0]),
            reverse=True
        ):
            score = self.get_repo_score(repo_key)
            stats_with_score = stats.copy()
            stats_with_score["quality_score"] = score
            stats_list.append(stats_with_score)
        
        # Add protocol stats
        output = {
            "repositories": stats_list,
            "protocol_stats": self.protocol_stats,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        logger.info(f"✓ Saved {filepath}")
    
    def export_csv(self, filepath):
        """Export quality stats as CSV"""
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Repository",
                "Owner",
                "Stars",
                "Forks",
                "Size (KB)",
                "Files Found",
                "Nodes Extracted",
                "Valid Nodes",
                "Extraction Success",
                "Extraction Failed",
                "Success Rate (%)",
                "Validity Rate (%)",
                "Quality Score"
            ])
            
            for repo_key in sorted(
                self.repo_stats.keys(),
                key=lambda x: self.get_repo_score(x),
                reverse=True
            ):
                stats = self.repo_stats[repo_key]
                score = self.get_repo_score(repo_key)
                
                success_rate = 0
                if stats["extraction_success"] + stats["extraction_failed"] > 0:
                    success_rate = round(
                        stats["extraction_success"] / (stats["extraction_success"] + stats["extraction_failed"]) * 100,
                        1
                    )
                
                validity_rate = 0
                if stats["nodes_extracted"] > 0:
                    validity_rate = round(
                        stats["nodes_valid"] / stats["nodes_extracted"] * 100,
                        1
                    )
                
                writer.writerow([
                    stats["repo"],
                    stats["owner"],
                    stats["stars"],
                    stats["forks"],
                    stats["size"],
                    stats["files_found"],
                    stats["nodes_extracted"],
                    stats["nodes_valid"],
                    stats["extraction_success"],
                    stats["extraction_failed"],
                    success_rate,
                    validity_rate,
                    score
                ])
        
        logger.info(f"✓ Saved {filepath}")
    
    def export_html(self, filepath):
        """Export quality stats as HTML report"""
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Node Source Quality Report</title>
    <style>
        * { margin: 0; padding: 0; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 { 
            color: #333; 
            margin-bottom: 10px; 
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }
        h2 {
            color: #333;
            margin-top: 30px;
            margin-bottom: 15px;
            border-bottom: 2px solid #ddd;
            padding-bottom: 8px;
        }
        .header-info { 
            color: #666; 
            margin-bottom: 20px; 
            font-size: 14px;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-top: 20px;
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 12px; 
            text-align: left; 
        }
        th { 
            background-color: #4CAF50; 
            color: white;
            font-weight: 600;
        }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f0f0f0; }
        .score-high { 
            color: white; 
            background-color: #4CAF50; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: bold;
        }
        .score-medium { 
            color: white; 
            background-color: #FF9800; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: bold;
        }
        .score-low { 
            color: white; 
            background-color: #f44336; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-weight: bold;
        }
        .summary { 
            margin-top: 30px; 
            padding: 20px; 
            background-color: #e8f5e9; 
            border-left: 4px solid #4CAF50; 
            border-radius: 4px;
        }
        .summary h2 { color: #2e7d32; margin-top: 0; }
        .summary p { color: #555; margin: 8px 0; }
        .protocol-table { margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Node Source Quality Report</h1>
        <div class="header-info">
            <p>Generated: """ + time.strftime("%Y-%m-%d %H:%M:%S") + """</p>
        </div>
        
        <h2>Repository Quality Metrics</h2>
        <table>
            <thead>
                <tr>
                    <th>Repository</th>
                    <th>Stars</th>
                    <th>Forks</th>
                    <th>Files</th>
                    <th>Extracted</th>
                    <th>Valid</th>
                    <th>Success Rate</th>
                    <th>Validity Rate</th>
                    <th>Quality Score</th>
                </tr>
            </thead>
            <tbody>
"""
        
        total_repos = 0
        total_valid_nodes = 0
        
        for repo_key in sorted(
            self.repo_stats.keys(),
            key=lambda x: self.get_repo_score(x),
            reverse=True
        ):
            stats = self.repo_stats[repo_key]
            score = self.get_repo_score(repo_key)
            total_repos += 1
            total_valid_nodes += stats["nodes_valid"]
            
            if score >= 70:
                score_class = "score-high"
            elif score >= 40:
                score_class = "score-medium"
            else:
                score_class = "score-low"
            
            success_rate = 0
            if stats["extraction_success"] + stats["extraction_failed"] > 0:
                success_rate = round(
                    stats["extraction_success"] / (stats["extraction_success"] + stats["extraction_failed"]) * 100,
                    1
                )
            
            validity_rate = 0
            if stats["nodes_extracted"] > 0:
                validity_rate = round(
                    stats["nodes_valid"] / stats["nodes_extracted"] * 100,
                    1
                )
            
            html += f"""                <tr>
                    <td><strong>{stats['repo']}</strong><br><small>by {stats['owner']}</small></td>
                    <td>{stats['stars']}</td>
                    <td>{stats['forks']}</td>
                    <td>{stats['files_found']}</td>
                    <td>{stats['nodes_extracted']}</td>
                    <td>{stats['nodes_valid']}</td>
                    <td>{success_rate}%</td>
                    <td>{validity_rate}%</td>
                    <td><div class="{score_class}">{score}</div></td>
                </tr>
"""
        
        html += """            </tbody>
        </table>
"""
        
        # Protocol stats
        html += """        <h2>Protocol Validation Statistics</h2>
        <table class="protocol-table">
            <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Total Validated</th>
                    <th>Valid</th>
                    <th>Failed</th>
                    <th>Success Rate</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for proto in sorted(self.protocol_stats.keys()):
            stats = self.protocol_stats[proto]
            if stats["total"] > 0:
                success_rate = round(stats["valid"] / stats["total"] * 100, 1)
            else:
                success_rate = 0
            
            html += f"""                <tr>
                    <td><strong>{proto.upper()}</strong></td>
                    <td>{stats['total']}</td>
                    <td>{stats['valid']}</td>
                    <td>{stats['failed']}</td>
                    <td>{success_rate}%</td>
                </tr>
"""
        
        html += """            </tbody>
        </table>
        
        <div class="summary">
            <h2>📈 Summary</h2>
"""
        html += f"            <p><strong>Total Repositories:</strong> {total_repos}</p>\n"
        html += f"            <p><strong>Total Valid Nodes:</strong> {total_valid_nodes}</p>\n"
        html += f"            <p><strong>Protocol Validation Enabled:</strong> {ENABLE_PROTOCOL_VALIDATION}</p>\n"
        html += f"            <p><strong>Generated At:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>\n"
        
        html += """        </div>
    </div>
</body>
</html>
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        
        logger.info(f"✓ Saved {filepath}")

quality_tracker = SourceQuality()

# =========================
# HELPERS
# =========================

def safe_request(url, timeout=15):
    req = urllib.request.Request(url, headers=HEADERS)
    return urllib.request.urlopen(req, timeout=timeout)

def is_probably_subscription_file(name):
    name_lower = name.lower()

    if any(k in name_lower for k in POSSIBLE_KEYWORDS):
        return True

    if any(name_lower.endswith(ext) for ext in VALID_EXTENSIONS):
        return True

    return False

# =========================
# PROTOCOL VALIDATION
# =========================

def get_protocol_type(node):
    """Extract protocol type from node string"""
    try:
        return node.split("://")[0].lower()
    except:
        return None

def validate_ss_protocol(server, port):
    """Validate Shadowsocks protocol"""
    try:
        sock = socket.create_connection((server, port), timeout=TIMEOUT_SECONDS)
        # Send minimal probe for SS
        sock.send(b"\x03\x01\x00")
        sock.settimeout(2)
        response = sock.recv(1024)
        sock.close()
        return response and len(response) > 0
    except Exception as e:
        logger.debug(f"SS validation failed: {type(e).__name__}")
        return False

def validate_trojan_protocol(server, port):
    """Validate Trojan protocol"""
    try:
        sock = socket.create_connection((server, port), timeout=TIMEOUT_SECONDS)
        # Trojan CONNECT command with hostname
        cmd = b"\x00" + b"\x0dhello.trojan.io" + b"\x00\x50"  # Port 80
        sock.send(cmd)
        sock.settimeout(2)
        response = sock.recv(1024)
        sock.close()
        return response and len(response) > 0
    except Exception as e:
        logger.debug(f"Trojan validation failed: {type(e).__name__}")
        return False

def validate_socks5_protocol(server, port):
    """Validate SOCKS5 protocol"""
    try:
        sock = socket.create_connection((server, port), timeout=TIMEOUT_SECONDS)
        # SOCKS5 greeting
        sock.send(b"\x05\x01\x00")
        sock.settimeout(2)
        response = sock.recv(1024)
        sock.close()
        # Response should be: \x05 (version) \x00 (no auth)
        return response and len(response) >= 2 and response[0] == 0x05
    except Exception as e:
        logger.debug(f"SOCKS5 validation failed: {type(e).__name__}")
        return False

def validate_vmess_protocol(server, port):
    """Validate VMess protocol (simple port check)"""
    try:
        sock = socket.create_connection((server, port), timeout=TIMEOUT_SECONDS)
        sock.send(b"\x00" * 16)  # Minimal probe
        sock.settimeout(2)
        response = sock.recv(1024)
        sock.close()
        return True  # VMess is hard to validate without full handshake
    except Exception as e:
        logger.debug(f"VMess validation failed: {type(e).__name__}")
        return False

def validate_vless_protocol(server, port):
    """Validate VLESS protocol (simple port check)"""
    try:
        sock = socket.create_connection((server, port), timeout=TIMEOUT_SECONDS)
        sock.send(b"\x00" * 16)  # Minimal probe
        sock.settimeout(2)
        sock.recv(1024)
        sock.close()
        return True  # VLESS is hard to validate without full handshake
    except Exception as e:
        logger.debug(f"VLESS validation failed: {type(e).__name__}")
        return False

def enhanced_protocol_check(node):
    """Enhanced protocol validation with proper handshakes"""
    
    if not ENABLE_PROTOCOL_VALIDATION:
        return tcp_check(node)
    
    server, port = parse_server_port(node)
    
    if not server or not port:
        return None
    
    protocol = get_protocol_type(node)
    
    try:
        # Route to appropriate validator
        if protocol == "ss":
            result = validate_ss_protocol(server, port)
            quality_tracker.record_protocol_validation("ss", result, "connection" if not result else None)
        elif protocol == "trojan":
            result = validate_trojan_protocol(server, port)
            quality_tracker.record_protocol_validation("trojan", result, "handshake" if not result else None)
        elif protocol == "vmess":
            result = validate_vmess_protocol(server, port)
            quality_tracker.record_protocol_validation("vmess", result, "connection" if not result else None)
        elif protocol == "vless":
            result = validate_vless_protocol(server, port)
            quality_tracker.record_protocol_validation("vless", result, "connection" if not result else None)
        else:
            # Fallback to TCP check
            result = tcp_check(node)
            quality_tracker.record_protocol_validation(protocol, result is not None, "unknown" if result is None else None)
        
        return node if result else None
    
    except Exception as e:
        logger.debug(f"Enhanced validation error for {protocol}: {type(e).__name__}")
        quality_tracker.record_protocol_validation(protocol, False, str(type(e).__name__))
        return None

# =========================
# SEARCH REPOSITORIES
# =========================

def search_repositories():
    repos = []

    logger.info("1. Searching repositories...")

    for keyword in SEARCH_KEYWORDS:

        encoded = urllib.parse.quote(keyword)

        url = (
            f"https://api.github.com/search/repositories"
            f"?q={encoded}"
            f"&sort=updated"
            f"&order=desc"
            f"&per_page={MAX_REPOS_PER_KEYWORD}"
        )

        try:
            with safe_request(url) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            items = data.get("items", [])

            logger.info(
                f"Keyword '{keyword}' -> {len(items)} repos"
            )

            for item in items:
                if item.get("size",0) > 50000:
                    continue
                
                owner = item["owner"]["login"]
                repo = item["name"]
                
                repos.append({
                    "owner": owner,
                    "repo": repo,
                    "branch": item.get("default_branch", "main"),
                    "stars": item.get("stargazers_count", 0),
                    "forks": item.get("forks_count", 0),
                    "size": item.get("size", 0),
                })
                
                # Register in quality tracker
                quality_tracker.register_repo(
                    owner,
                    repo,
                    stars=item.get("stargazers_count", 0),
                    forks=item.get("forks_count", 0),
                    size=item.get("size", 0),
                )

        except Exception as e:
            logger.error(
                f"Search failed for '{keyword}': {type(e).__name__}"
            )

    # dedup repos
    seen = set()
    unique = []

    for r in repos:
        key = f"{r['owner']}/{r['repo']}"

        if key not in seen:
            seen.add(key)
            unique.append(r)

    logger.info(f"Unique repositories: {len(unique)}")

    return unique

# =========================
# RECURSIVE CONTENT SCAN
# =========================

def get_repo_files(owner, repo, branch):

    found_files = []
    repo_key = f"{owner}/{repo}"

    def walk(path="",depth=0):
        if depth > 2:
             return

        api = (
            f"https://api.github.com/repos/"
            f"{owner}/{repo}/contents/{path}"
            f"?ref={branch}"
        )

        try:
            with safe_request(api) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if isinstance(data, dict):
                return

            for item in data:

                item_type = item.get("type")
                item_name = item.get("name", "")
                item_path = item.get("path", "")

                if item_type == "dir":

                    # avoid huge useless dirs
                    skip_dirs = [
                        ".git",
                        "node_modules",
                        "vendor",
                        "dist",
                        "build",
                        "__pycache__",
                    ]

                    if any(s in item_path.lower() for s in skip_dirs):
                        continue

                    walk(item_path,depth+1)

                elif item_type == "file":

                    if is_probably_subscription_file(item_name):

                        download_url = item.get("download_url")

                        if download_url:
                            found_files.append(download_url)
                            quality_tracker.register_url(download_url, repo_key)
                            quality_tracker.record_file_found(repo_key)

        except Exception:
            pass

    walk()

    return found_files

# =========================
# PARSERS
# =========================

def extract_standard_links(content):

    pattern = (
        r"(vmess|vless|trojan|ss):\/\/"
        r"[A-Za-z0-9+\/=:@?&%._#,-]+"
    )

    return re.findall(pattern, content)

def extract_links_full(content):

    pattern = (
        r"(?:vmess|vless|trojan|ss):\/\/"
        r"[A-Za-z0-9+\/=:@?&%._#,-]+"
    )

    return re.findall(pattern, content)

# =========================
# CLASH YAML PARSER
# =========================

def parse_clash_yaml(content):

    nodes = []

    try:
        data = yaml.safe_load(content)

        if not isinstance(data, dict):
            return nodes

        proxies = data.get("proxies", [])

        for proxy in proxies:

            if not isinstance(proxy, dict):
                continue

            ptype = str(proxy.get("type", "")).lower()

            server = proxy.get("server")
            port = proxy.get("port")

            if not server or not port:
                continue

            name = urllib.parse.quote(
                str(proxy.get("name", "Node"))
            )

            # SS
            if ptype == "ss":

                cipher = proxy.get("cipher")
                password = proxy.get("password")

                if cipher and password:

                    userinfo = base64.b64encode(
                        f"{cipher}:{password}".encode()
                    ).decode()

                    nodes.append(
                        f"ss://{userinfo}@{server}:{port}#{name}"
                    )

            # VMESS
            elif ptype == "vmess":

                uuid = proxy.get("uuid")

                if uuid:

                    vmess = {
                        "v": "2",
                        "ps": name,
                        "add": server,
                        "port": str(port),
                        "id": uuid,
                        "aid": str(proxy.get("alterId", 0)),
                        "scy": proxy.get("cipher", "auto"),
                        "net": proxy.get("network", "tcp"),
                        "type": "none",
                        "host": proxy.get("host", ""),
                        "path": proxy.get("path", ""),
                        "tls": "tls" if proxy.get("tls") else ""
                    }

                    encoded = base64.b64encode(
                        json.dumps(vmess).encode()
                    ).decode()

                    nodes.append(
                        f"vmess://{encoded}"
                    )

            # VLESS
            elif ptype == "vless":

                uuid = proxy.get("uuid")

                if uuid:

                    nodes.append(
                        f"vless://{uuid}@{server}:{port}"
                        f"?encryption=none#{name}"
                    )

            # TROJAN
            elif ptype == "trojan":

                password = proxy.get("password")

                if password:

                    nodes.append(
                        f"trojan://{password}@{server}:{port}#{name}"
                    )

    except Exception as e:
        logger.debug(f"YAML parse failed: {e}")

    return nodes

# =========================
# BASE64 DECODER
# =========================

def try_base64_decode(content):

    try:

        padded = content + "=" * (
            (4 - len(content) % 4) % 4
        )

        decoded = base64.b64decode(
            padded
        ).decode("utf-8", errors="ignore")

        return decoded

    except Exception:
        return content

# =========================
# EXTRACT FROM URL
# =========================

def extract_from_url(url):

    nodes = []

    try:

        with safe_request(url, timeout=10) as resp:

            content = resp.read().decode(
                "utf-8",
                errors="ignore"
            )

        if not content.strip():
            quality_tracker.record_extraction(url, 0, success=False)
            return nodes

        # YAML
        if (
            "proxies:" in content
            or "proxy-groups:" in content
        ):
            nodes.extend(parse_clash_yaml(content))

        # direct links
        direct = extract_links_full(content)

        if direct:
            nodes.extend(direct)

        # base64 subscriptions
        if not direct:

            decoded = try_base64_decode(content)

            decoded_links = extract_links_full(decoded)

            if decoded_links:
                nodes.extend(decoded_links)
        
        quality_tracker.record_extraction(url, len(nodes), success=True)

    except Exception as e:
        logger.debug(
            f"Extract failed: {type(e).__name__}"
        )
        quality_tracker.record_extraction(url, 0, success=False)

    return nodes

# =========================
# NODE SIGNATURE
# =========================

def node_signature(node):

    return hashlib.md5(
        node.encode("utf-8", errors="ignore")
    ).hexdigest()

# =========================
# SERVER/PORT PARSER
# =========================

def parse_server_port(node):

    try:

        # VMESS
        if node.startswith("vmess://"):

            raw = node.split("vmess://", 1)[1]

            padded = raw + "=" * (
                (4 - len(raw) % 4) % 4
            )

            cfg = json.loads(
                base64.b64decode(padded).decode(
                    "utf-8",
                    errors="ignore"
                )
            )

            return (
                cfg.get("add"),
                int(cfg.get("port"))
            )

        # OTHER TYPES
        body = node.split("://", 1)[1]

        body = body.split("#")[0]

        if "@" in body:
            body = body.split("@", 1)[1]

        body = body.split("?")[0]

        server, port = body.rsplit(":", 1)

        return server, int(port)

    except Exception:
        return None, None

# =========================
# TCP VALIDATION
# =========================

def tcp_check(node):

    server, port = parse_server_port(node)

    if not server or not port:
        return None

    try:

        sock = socket.create_connection(
            (server, port),
            timeout=TIMEOUT_SECONDS
        )

        sock.close()

        return node

    except (
        socket.timeout,
        socket.gaierror,
        ConnectionRefusedError,
        OSError
    ):
        return None

# =========================
# MAIN
# =========================

def main():

    start = time.time()

    # 1 search repos
    repos = search_repositories()

    # 2 recursive file scan
    logger.info(
        "2. Scanning repository contents..."
    )

    urls = []
    repo_map = {}

    with ThreadPoolExecutor(
        max_workers=25
    ) as executor:

        futures = {

            executor.submit(
                get_repo_files,
                r["owner"],
                r["repo"],
                r["branch"]
            ): r

            for r in repos
        }

        for future in as_completed(futures):

            try:

                files = future.result()
                r = futures[future]
                repo_key = f"{r['owner']}/{r['repo']}"

                urls.extend(files)
                for f in files:
                    repo_map[f] = repo_key

            except Exception:
                pass

    urls = list(set(urls))
    MAX_FILES=800
    if len(urls) > MAX_FILES:

        logger.info(f"File cap applied: "f"{len(urls)} -> {MAX_FILES}")
        urls = urls[:MAX_FILES]
        logger.info(f"Potential files found: {len(urls)}")

    # 3 extract nodes
    logger.info(
        "3. Extracting subscriptions..."
    )

    raw_nodes = []
    nodes_by_url = {}

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {

            executor.submit(
                extract_from_url,
                url
            ): url

            for url in urls
        }

        for future in as_completed(futures):

            try:

                result = future.result()
                url = [k for k, v in futures.items() if v == future][0] if future in futures else None

                if result:
                    raw_nodes.extend(result)
                    if url:
                        nodes_by_url[url] = result

            except Exception:
                pass

    logger.info(
        f"Raw extracted nodes: {len(raw_nodes)}"
    )

    # 4 dedup
    logger.info(
        "4. Deduplicating..."
    )

    unique_nodes = []
    seen = set()

    for node in raw_nodes:

        sig = node_signature(node)

        if sig not in seen:

            seen.add(sig)

            unique_nodes.append(node)

    logger.info(
        f"Unique nodes: {len(unique_nodes)}"
    )

    # save nodeALL
    logger.info(
        "5. Writing nodeALL.txt..."
    )

    merged_all = "\n".join(
        unique_nodes
    )

    encoded_all = base64.b64encode(
        merged_all.encode("utf-8")
    ).decode()

    with open(
        OUTPUT_DIR / "nodeALL.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(encoded_all)

    # 5 validation
    live_nodes = []

    if ENABLE_TCP_CHECK:

        logger.info(
            "6. Enhanced Protocol Validation..." if ENABLE_PROTOCOL_VALIDATION else "6. TCP Validation..."
        )

        validator_func = enhanced_protocol_check if ENABLE_PROTOCOL_VALIDATION else tcp_check

        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as executor:

            futures = {

                executor.submit(
                    validator_func,
                    node
                ): node

                for node in unique_nodes[:3000]
            }

            checked = 0

            total = len(unique_nodes)

            for future in as_completed(
                futures
            ):

                checked += 1

                try:

                    res = future.result()

                    if res:
                        live_nodes.append(
                            res
                        )
                        # Track valid nodes by source
                        for url, nodes in nodes_by_url.items():
                            if res in nodes:
                                repo_key = quality_tracker.url_to_repo.get(url)
                                if repo_key:
                                    quality_tracker.record_node_validation(res, repo_key)

                except Exception:
                    pass

                if checked % 500 == 0:

                    logger.info(
                        f"Validated "
                        f"{checked}/{total}"
                    )

    else:

        live_nodes = unique_nodes

    logger.info(
        f"Live nodes: "
        f"{len(live_nodes)} / "
        f"{len(unique_nodes)}"
    )

    # save nodes.txt
    logger.info(
        "7. Writing nodes.txt..."
    )

    merged_live = "\n".join(
        live_nodes
    )

    encoded_live = base64.b64encode(
        merged_live.encode("utf-8")
    ).decode()

    with open(
        OUTPUT_DIR / "nodes.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(encoded_live)

    # save quality reports
    logger.info(
        "8. Generating source quality reports..."
    )
    
    quality_tracker.export_json(OUTPUT_DIR / "source_quality.json")
    quality_tracker.export_csv(OUTPUT_DIR / "source_quality.csv")
    quality_tracker.export_html(OUTPUT_DIR / "source_quality.html")

    elapsed = round(
        time.time() - start,
        2
    )

    logger.info(
        "========================"
    )

    logger.info(
        "DONE"
    )

    logger.info(
        f"Repositories: {len(repos)}"
    )

    logger.info(
        f"Files: {len(urls)}"
    )

    logger.info(
        f"Raw nodes: {len(raw_nodes)}"
    )

    logger.info(
        f"Unique nodes: "
        f"{len(unique_nodes)}"
    )

    logger.info(
        f"Validated nodes: "
        f"{len(live_nodes)}"
    )

    logger.info(
        f"Elapsed: {elapsed}s"
    )

if __name__ == "__main__":
    main()
