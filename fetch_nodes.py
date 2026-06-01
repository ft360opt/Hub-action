import os
import re
import json
import base64
import socket
import logging
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# External Libraries
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import yaml

# =========================
# CONFIGURATION
# =========================
SEARCH_KEYWORDS = [
    "v2ray share", "clash subscribe", "free ssr", "trojan subscribe", 
    "warp config", "china nodes", "订阅", "节点", "梯子", "翻墙"
]
MAX_REPOS_PER_KEYWORD = 5
MAX_WORKERS = 40
TIMEOUT_SECONDS = 4

OUTPUT_DIR = Path("data")
OUTPUT_DIR.mkdir(exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Configure a robust HTTP Session with automated retries
session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retries))

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
if GITHUB_TOKEN:
    session.headers.update({"Authorization": f"token {GITHUB_TOKEN}"})
session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

# =========================
# QUALITY TRACKER
# =========================
class RepoTracker:
    def __init__(self):
        self.stats = {}
    
    def init_repo(self, repo_full_name, stars, forks):
        if repo_full_name not in self.stats:
            self.stats[repo_full_name] = {
                "repository": repo_full_name,
                "stars": stars,
                "forks": forks,
                "extracted_nodes": 0,
                "valid_nodes": 0,
                "quality_score": 0.0
            }

    def add_counts(self, repo_full_name, extracted=0, valid=0):
        if repo_full_name in self.stats:
            self.stats[repo_full_name]["extracted_nodes"] += extracted
            self.stats[repo_full_name]["valid_nodes"] += valid

    def calculate_and_save(self, path):
        output_list = []
        for name, data in self.stats.items():
            star_score = min(data["stars"] / 50 * 40, 40)
            fork_score = min(data["forks"] / 20 * 20, 20)
            node_score = 40 if data["valid_nodes"] > 0 else 0
            data["quality_score"] = round(star_score + fork_score + node_score, 2)
            output_list.append(data)
            
        output_list.sort(key=lambda x: x["quality_score"], reverse=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"repositories": output_list, "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}, f, indent=2)

tracker = RepoTracker()

# =========================
# ADVANCED PARSING LAYER
# =========================
def parse_clash_yaml(yaml_content):
    """Safely extracts nodes from a Clash YAML structure and formats them."""
    nodes = []
    try:
        data = yaml.safe_load(yaml_content)
        if not data or not isinstance(data, dict):
            return nodes
        
        proxies = data.get("proxies", [])
        if not isinstance(proxies, list):
            return nodes

        for p in proxies:
            if not isinstance(p, dict):
                continue
            ptype = p.get("type", "").lower()
            server = p.get("server")
            port = p.get("port")
            name = p.get("name", "clash-node")

            if not server or not port:
                continue

            # Map YAML dictionaries back into shareable application protocol links
            if ptype == "ss":
                cipher = p.get("cipher", "")
                password = p.get("password", "")
                userpass = base64.b64encode(f"{cipher}:{password}".encode()).decode()
                nodes.append(f"ss://{userpass}@{server}:{port}#{name}")
            elif ptype == "ssr":
                # Basic SSR string reconstruction
                nodes.append(f"ssr://{server}:{port}::::")
            elif ptype == "vmess":
                vmess_meta = {
                    "v": "2", "ps": name, "add": server, "port": str(port),
                    "id": p.get("uuid", ""), "aid": str(p.get("alterId", 0)),
                    "scy": "auto", "net": p.get("network", "tcp"),
                    "type": "none", "host": "", "path": "", "tls": "tls" if p.get("tls") else ""
                }
                v_str = base64.b64encode(json.dumps(vmess_meta).encode()).decode()
                nodes.append(f"vmess://{v_str}")
            elif ptype in ["vless", "trojan", "tuic", "hysteria", "hysteria2"]:
                uuid_or_pass = p.get("uuid") or p.get("password") or ""
                nodes.append(f"{ptype}://{uuid_or_pass}@{server}:{port}#{name}")
    except:
        pass # If YAML parsing crashes, fallback logic handles raw regex scan
    return nodes

def extract_nodes_from_text(text):
    protocols = r'(vmess|vless|ss|ssr|trojan|tuic|hysteria2|hysteria):\/\/[^\s"\':<>]+'
    return [n + "://" + n for n in re.findall(r'(~?\w+):\/\/([^\s"\'<>]+)', text)]

def decode_and_extract(raw_bytes, filename=""):
    """Orchestrates parsing based on file layout rules."""
    text = raw_bytes.decode('utf-8', errors='ignore')
    
    # If the asset file points to YAML, target the structured parser first
    if filename.endswith((".yaml", ".yml")):
        yaml_nodes = parse_clash_yaml(text)
        if yaml_nodes:
            return yaml_nodes

    # Try fallback to standard raw text link scraping
    nodes = extract_nodes_from_text(text)
    if nodes:
        return nodes
    
    # Try Base64 decoding fallback
    try:
        padded = raw_bytes + b'=' * (-len(raw_bytes) % 4)
        decoded_text = base64.b64decode(padded).decode('utf-8', errors='ignore')
        if filename.endswith((".yaml", ".yml")):
            yaml_nodes = parse_clash_yaml(decoded_text)
            if yaml_nodes:
                return yaml_nodes
        return extract_nodes_from_text(decoded_text)
    except:
        pass
    return []

# =========================
# NETWORK VALIDATION LAYER
# =========================
def parse_target_host_port(node_str):
    try:
        payload = node_str.split("://")[1]
        payload = payload.split("#")[0]
        
        if "vmess://" in node_str:
            try:
                decoded_vmess = json.loads(base64.b64decode(payload + '=' * (-len(payload) % 4)).decode('utf-8'))
                return decoded_vmess.get('add'), int(decoded_vmess.get('port', 0))
            except:
                pass

        if "@" in payload:
            payload = payload.split("@")[1]
            
        host_port = payload.split("?")[0]
        if ":" in host_port:
            parts = host_port.split(":")
            return parts[0], int(parts[1])
    except:
        pass
    return None, None

def test_tcp(node_str):
    host, port = parse_target_host_port(node_str)
    if not host or not port:
        return node_str, False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SECONDS)
        sock.connect((host, port))
        sock.close()
        return node_str, True
    except:
        return node_str, False

# =========================
# MAIN EXECUTIVE LOOP
# =========================
def main():
    logger.info("Starting upgraded node generation process...")
    unique_raw_nodes = set()
    processed_repos = set()
    current_year = time.strftime("%Y")

    for keyword in SEARCH_KEYWORDS:
        #query = urllib.parse.quote(f"{keyword} pushed:>{current_year}-01-01 sort:updated")
        #url = f"https://github.com{query}&per_page={MAX_REPOS_PER_KEYWORD}"
        url = "https://github.com"
        params = {
            "q": f"{keyword} pushed:>{current_year}-01-01 sort:updated",
            "per_page": MAX_REPOS_PER_KEYWORD
        }
        
        try:
            #res = session.get(url, timeout=10)
            res = session.get(url, params=params, timeout=10)
            if res.status_code != 200: continue
            data = res.json()
        except Exception as e:
            logger.error(f"Failed to query keyword '{keyword}': {e}")
            continue

        for item in data.get("items", []):
            repo_name = item["full_name"]
            if repo_name in processed_repos: continue
            processed_repos.add(repo_name)

            tracker.init_repo(repo_name, item["stargazers_count"], item["forks_count"])
            logger.info(f"Targeting repository: {repo_name}")

            try:
                branch = item['default_branch']
                tree_res = session.get(f"https://github.com{repo_name}/branches/{branch}", timeout=10)
                if tree_res.status_code != 200: continue
                sha = tree_res.json()["commit"]["commit"]["tree"]["sha"]

                files_res = session.get(f"https://github.com{repo_name}/git/trees/{sha}?recursive=1", timeout=10)
                if files_res.status_code != 200: continue
                files_data = files_res.json()
            except Exception as e:
                logger.error(f"Error fetching metadata for {repo_name}: {e}")
                continue

            repo_raw_nodes = []
            for file_obj in files_data.get("tree", []):
                path = file_obj.get("path", "")
                if any(path.lower().endswith(ext) for ext in [".txt", ".yaml", ".yml", ".json", "sub", "subscribe"]):
                    raw_url = f"https://githubusercontent.com{repo_name}/{branch}/{path}"
                    try:
                        content_res = session.get(raw_url, timeout=7)
                        if content_res.status_code == 200:
                            extracted = decode_and_extract(content_res.content, path)
                            repo_raw_nodes.extend(extracted)
                    except:
                        continue

            if repo_raw_nodes:
                repo_raw_nodes = list(set(repo_raw_nodes))
                tracker.add_counts(repo_name, extracted=len(repo_raw_nodes))
                unique_raw_nodes.update(repo_raw_nodes)
                logger.info(f" -> Found {len(repo_raw_nodes)} raw nodes.")

    raw_node_list = list(unique_raw_nodes)
    logger.info(f"Total unique raw nodes found: {len(raw_node_list)}. Validating TCP connections...")
    valid_nodes_list = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_tcp, node): node for node in raw_node_list}
        for future in as_completed(futures):
            node_str, is_valid = future.result()
            if is_valid:
                valid_nodes_list.append(node_str)
                for repo_name in processed_repos:
                    tracker.add_counts(repo_name, valid=1)
                    # Output unverified items as plaintext lines into data/nodeALL.txt
                    with open(OUTPUT_DIR / "nodeALL.txt", "w", encoding="utf-8") as f:
                        f.write("\n".join(raw_node_list))
                        # Base64-encode verified items into data/nodes.txt
                        valid_payload_string = "\n".join(valid_nodes_list)
                        base64_encoded_bytes = base64.b64encode(valid_payload_string.encode('utf-8'))
                        with open(OUTPUT_DIR / "nodes.txt", "wb") as f:
                            f.write(base64_encoded_bytes)
                            tracker.calculate_and_save(OUTPUT_DIR / "repository_quality.json")
                            logger.info("Processing complete! Data output written to 'data/' folder.")
                            
if __name__ == "__main__":
    main()
