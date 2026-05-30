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

MAX_REPOS_PER_KEYWORD = 20
MAX_WORKERS = 80
TIMEOUT_SECONDS = 5
ENABLE_TCP_CHECK = True

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
                repos.append({
                    "owner": item["owner"]["login"],
                    "repo": item["name"],
                    "branch": item.get("default_branch", "main")
                })

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

    def walk(path=""):

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

                    walk(item_path)

                elif item_type == "file":

                    if is_probably_subscription_file(item_name):

                        download_url = item.get("download_url")

                        if download_url:
                            found_files.append(download_url)

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

    except Exception as e:
        logger.debug(
            f"Extract failed: {type(e).__name__}"
        )

    return nodes

# =========================
# NODE SIGNATURE
# =========================

def node_signature(node):

    return hashlib.md5(
        node.encode("utf-8", errors="ignore")
    ).hexdigest()

# =========================
# SERVER/PART PARSER
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
# PART 2/2
# =========================

# TCP VALIDATION

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

                urls.extend(files)

            except Exception:
                pass

    urls = list(set(urls))

    logger.info(
        f"Potential files found: {len(urls)}"
    )

    # 3 extract nodes
    logger.info(
        "3. Extracting subscriptions..."
    )

    raw_nodes = []

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

                if result:
                    raw_nodes.extend(result)

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
            "6. TCP validation..."
        )

        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as executor:

            futures = {

                executor.submit(
                    tcp_check,
                    node
                ): node

                for node in unique_nodes
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
    
    
