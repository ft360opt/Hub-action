import os
import re
import json
import base64
import socket
import logging
import urllib.request
import urllib.parse
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

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

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
HEADERS = {"User-Agent": "Mozilla/5.0"}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"

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
            # Quality Score formula: Stars (max 40) + Forks (max 20) + Valid Node Output Weight (max 40)
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
# HELPER FUNCTIONS
# =========================
def github_api_request(url):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        logger.error(f"GitHub API Error for {url}: {e}")
        return None

def fetch_raw_content(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=7) as response:
            return response.read()
    except:
        return b""

def extract_nodes_from_text(text):
    # Regex to capture standard proxies: vmproxy://, vless://, ss://, ssr://, trojan://, tuic://, hysteresis://
    protocols = r'(vmess|vless|ss|ssr|trojan|tuic|hysteria2|hysteria):\/\/[^\s"\':<>]+'
    return re.findall(protocols, text)

def decode_and_extract(raw_bytes):
    # Try direct parsing
    text = raw_bytes.decode('utf-8', errors='ignore')
    nodes = extract_nodes_from_text(text)
    if nodes:
        return [n[0] + "://" + n[1] for n in re.findall(r'(~?\w+):\/\/([^\s"\'<>]+)', text)]
    
    # Try Base64 string decoding (common for subscription URLs)
    try:
        padded = raw_bytes + b'=' * (-len(raw_bytes) % 4)
        decoded_text = base64.b64decode(padded).decode('utf-8', errors='ignore')
        nodes = [n[0] + "://" + n[1] for n in re.findall(r'(~?\w+):\/\/([^\s"\'<>]+)', decoded_text)]
        if nodes:
            return nodes
    except:
        pass
    return []

def parse_target_host_port(node_str):
    try:
        # Strip protocol prefix
        payload = node_str.split("://")[1]
        # Clean up remarks suffix matching tags (#...)
        payload = payload.split("#")[0]
        
        # Handle Base64 encoded protocols inside URL parameters (like vmess)
        if "vmess://" in node_str:
            try:
                decoded_vmess = json.loads(base64.b64decode(payload + '=' * (-len(payload) % 4)).decode('utf-8'))
                return decoded_vmess.get('add'), int(decoded_vmess.get('port', 0))
            except:
                pass

        # Handle standard configurations (user:pass@host:port)
        if "@" in payload:
            payload = payload.split("@")[1]
            
        host_port = payload.split("?")[0] # strip config parameters
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
# MAIN FLOW EXECUTIVE
# =========================
def main():
    logger.info("Starting node generation process...")
    unique_raw_nodes = set()
    processed_repos = set()

    for keyword in SEARCH_KEYWORDS:
        query = urllib.parse.quote(f"{keyword} pushed:>2026-01-01 sort:updated")
        url = f"https://github.com{query}&per_page={MAX_REPOS_PER_KEYWORD}"
        
        data = github_api_request(url)
        if not data or "items" not in data:
            continue

        for item in data["items"]:
            repo_name = item["full_name"]
            if repo_name in processed_repos:
                continue
            processed_repos.add(repo_name)

            tracker.init_repo(repo_name, item["stargazers_count"], item["forks_count"])
            logger.info(f"Targeting repository: {repo_name}")

            # Grab the repository's file tree schema 
            tree_url = f"https://github.com{repo_name}/branches/{item['default_branch']}"
            branch_data = github_api_request(tree_url)
            if not branch_data:
                continue
                
            sha = branch_data["commit"]["commit"]["tree"]["sha"]
            files_url = f"https://github.com{repo_name}/git/trees/{sha}?recursive=1"
            files_data = github_api_request(files_url)
            if not files_data or "tree" not in files_data:
                continue

            repo_raw_nodes = []
            for file_obj in files_data["tree"]:
                path = file_obj.get("path", "")
                # Prioritize typical text storage configurations
                if any(path.endswith(ext) for ext in [".txt", ".yaml", ".yml", ".json", "sub", "subscribe"]):
                    raw_url = f"https://githubusercontent.com {repo_name}/{item['default_branch']}/{path}".replace(" ", "")
                    content = fetch_raw_content(raw_url)
                    if content:
                        extracted = decode_and_extract(content)
                        repo_raw_nodes.extend(extracted)

            if repo_raw_nodes:
                repo_raw_nodes = list(set(repo_raw_nodes))
                tracker.add_counts(repo_name, extracted=len(repo_raw_nodes))
                unique_raw_nodes.update(repo_raw_nodes)
                logger.info(f" -> Found {len(repo_raw_nodes)} raw nodes.")

    # Process TCP Validations via Concurrency
    raw_node_list = list(unique_raw_nodes)
    logger.info(f"Total unique raw nodes found: {len(raw_node_list)}. Validating TCP connections...")
    
    valid_nodes_list = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_tcp, node): node for node in raw_node_list}
        for future in as_completed(futures):
            node_str, is_valid = future.result()
            if is_valid:
                valid_nodes_list.append(node_str)
                # Reverse lookup tracking map to assign point metric weights
                for repo_name in processed_repos:
                    # If this valid node originated from a target repository, score it
                    tracker.add_counts(repo_name, valid=1)

    # Save outputs
    with open(OUTPUT_DIR / "raw_nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(raw_node_list))
        
    with open(OUTPUT_DIR / "validated_nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(valid_nodes_list))

    tracker.calculate_and_save(OUTPUT_DIR / "repository_quality.json")
    logger.info("Processing complete! Data output written to 'output/' folder.")

if __name__ == "__main__":
    main()
