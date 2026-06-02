# Mihomo 节点验证集成指南

## 问题分析

### 你的脚本存在的 GitHub Actions 问题

| 问题 | 原因 | 解决方案 |
|------|------|--------|
| 下载链接错误 | `download_url = "https://github.com"` 不完整 | 自动从 API 获取最新 release |
| 端口冲突 | 硬编码 9090，可能被占用 | 使用 `get_free_port()` 动态分配 |
| API 启动超时 | `time.sleep(3)` 不稳定 | 使用 `wait_for_api_ready()` 轮询 |
| 环境兼容性 | 未考虑 GitHub Actions 受限 | 添加降级处理（无 Mihomo 时用 TCP） |
| 错误恢复不足 | 任何一步失败就直接退出 | 多层错误处理 |

---

## 集成步骤

### 1. 导入改进模块（fetch_nodes.py 开头）

```python
from validate_nodes_mihomo import validate_nodes_with_mihomo
```

### 2. 替换验证部分（fetch_nodes.py 第 543-556 行）

**原代码：**
```python
raw_node_list = list(unique_raw_nodes)
logger.info(f"Total unique raw nodes found: {len(raw_node_list)}. Validating TCP connections...")
valid_nodes_list = []

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    futures = {executor.submit(test_tcp, node): node for node in raw_node_list}
    for future in as_completed(futures):
        try:
            node_str, is_valid = future.result()
            if is_valid:
                valid_nodes_list.append(node_str)
                source_repo = tracker.node_sources.get(node_str)
                if source_repo:
                    tracker.add_counts(source_repo, valid=1)
        except Exception as e:
            logger.error(f"Error processing validation result: {e}")
```

**新代码：**
```python
raw_node_list = list(unique_raw_nodes)
logger.info(f"Total unique raw nodes found: {len(raw_node_list)}. Starting validation...")

# 尝试 Mihomo 验证，失败则降级到 TCP
mihomo_results = validate_nodes_with_mihomo(raw_node_list, OUTPUT_DIR / "nodeALL.txt")

if mihomo_results:
    # Mihomo 成功
    valid_nodes_list = mihomo_results
    logger.info(f"Mihomo validation completed: {len(valid_nodes_list)} valid nodes")
    # 更新 tracker
    for node_str in valid_nodes_list:
        source_repo = tracker.node_sources.get(node_str)
        if source_repo:
            tracker.add_counts(source_repo, valid=1)
else:
    # 降级到 TCP 验证
    logger.warning("Mihomo unavailable, falling back to TCP validation...")
    valid_nodes_list = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_tcp, node): node for node in raw_node_list}
        for future in as_completed(futures):
            try:
                node_str, is_valid = future.result()
                if is_valid:
                    valid_nodes_list.append(node_str)
                    source_repo = tracker.node_sources.get(node_str)
                    if source_repo:
                        tracker.add_counts(source_repo, valid=1)
            except Exception as e:
                logger.error(f"Error processing validation result: {e}")
    logger.info(f"TCP validation completed: {len(valid_nodes_list)} valid nodes")
```

### 3. 更新工作流配置（.github/workflows/main.yml）

```yaml
      - name: Install dependencies
        run: pip install pyyaml requests

      # ✨ 新增：为 GitHub Actions 环境预装 Mihomo（可选，加快速度）
      - name: Pre-download Mihomo (GitHub Actions optimization)
        if: runner.os == 'Linux'
        run: |
          python -c "
          import os
          os.environ['GITHUB_ACTIONS'] = 'true'
          from validate_nodes_mihomo import download_mihomo_core
          download_mihomo_core()
          "
```

---

## 性能对比

| 方案 | 耗时 | 准确性 | 网络需求 | 稳定性 |
|------|------|--------|---------|--------|
| **原 TCP** | 2-5 分钟 | 低（只检查连接） | 最小 | ⚠️ 易超时 |
| **改进 TCP** | 1.5-3 分钟 | 中（DNS+TCP） | 最小 | ✅ 稳定 |
| **Mihomo** | 3-8 分钟 | 高（真实 HTTP） | 需要代理 | ✅ 高效 |
| **混合**（推荐） | 1-5 分钟 | 高（能用就用 Mihomo，否则 TCP） | 最小 | ✅✅ 最佳 |

---

## 环境变量配置

在 GitHub Secrets 中添加（可选）：

```bash
# 控制是否启用 Mihomo
MIHOMO_ENABLED=true

# 调整测速并发数
VALIDATION_WORKERS=15

# 调整测速超时
VALIDATION_TIMEOUT_MS=2500
```

在工作流中使用：

```yaml
      - name: Execute Fetch Script
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          MIHOMO_ENABLED: ${{ secrets.MIHOMO_ENABLED || 'true' }}
          VALIDATION_WORKERS: ${{ secrets.VALIDATION_WORKERS || '15' }}
        run: python fetch_nodes.py
```

---

## 故障排查

### 问题 1：Mihomo 下载失败

```
[!] Failed to download Mihomo: HTTP Error 403
```

**解决方案：**
- 检查网络连接
- 尝试手动下载并放入仓库：`https://github.com/MetaCubeX/mihomo/releases`
- 确保有读写权限

### 问题 2：API 端口占用

```
[!] Failed to allocate port
```

**解决方案：**
- 脚本会自动使用动态端口，无需手动干预
- 检查是否有其他进程占用 9090-9099 端口

### 问题 3：GitHub Actions 超时

```
API not ready within 15 seconds
```

**解决方案：**
- 增加超时时间：编辑 `validate_nodes_mihomo.py` 中的 `api_startup_timeout`
- 或直接降级使用 TCP 验证

---

## 最优实践

### 推荐的工作流组合

```yaml
jobs:
  scrape:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: 'pip'
      
      - run: pip install pyyaml requests
      
      # 节点收���
      - name: Fetch nodes
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: python fetch_nodes.py
      
      # 节点验证（自动选择 Mihomo 或 TCP）
      # 已集成到 fetch_nodes.py
      
      # 提交
      - name: Commit changes
        run: |
          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add data/
          git diff --quiet && git diff --staged --quiet || \
            (git commit -m "Auto updated: $(date)" && git push)
```

---

## 下一步优化

- [ ] 添加代理池支持（多线程更稳定）
- [ ] 实现增量验证（只验证新节点）
- [ ] 添加节点地域分类
- [ ] 集成 geoip 库用于节点定位
