# Proxy Rename

Proxy Rename 是一个基于 Python 与 Xray-core 的代理节点批量测试工具。它可以从订阅 URL 获取节点（支持 VMess / VLESS / Shadowsocks / Trojan / Hysteria2），通过本地 Xray 代理逐一测试出口 IP 与地理信息，自动重命名节点并生成可直接导入的 base64 订阅。

---

## 主要特性

- **异步高性能**：使用 httpx + asyncio 实现并行处理，大幅提升订阅拉取和节点测试速度（23 节点约 2-3 分钟）
- **定时订阅**：后台定时拉取与检测订阅（每 X 小时），并保存结果。
- **即时 API**：提供 Webhook 接口（/process）按需触发检测，/sub 返回最新 base64 订阅。
- **自定义节点名称**：支持 `--prefix` 参数，为节点添加自定义前缀（如：ICY-CN-北京-001）
- **支持多协议**：VMess、VLESS、SS、Trojan、Hysteria2
- **并发控制与限流优化**：可配置并发线程数（默认 4），兼容 ip-api.com 的免费限流策略。
- **Docker 支持**：可通过 Docker Compose 一键部署。
- **本地持久化**：结果保存为 JSON 与 base64 文本，便于审计与导入。

## 先决条件

- Docker >= 20.10, Docker Compose >= v2.0（或在目标环境直接安装 Python 运行）。
- Xray-core 二进制在容器内可用，或通过 `--xray_path` 指定路径。
- Python >= 3.12
- 若通过 socks5 代理进行测试，httpx 已内置 socks 支持。
- 订阅文件（可选）：每行一个订阅 URL，例如 `subs.txt`。

## 快速启动（Docker Compose）

### 方法 1：从 GitHub 克隆（推荐）

```bash
# 1. 克隆仓库
git clone https://github.com/xynet81/proxy_rename.git
cd proxy_rename

# 2. 准备订阅文件
echo "你的订阅链接1" > subs.txt
echo "你的订阅链接2" >> subs.txt

# 3. 构建并启动
docker-compose up -d --build

# 4. 查看日志
docker-compose logs -f proxy-tester
```

### 方法 2：直接下载 ZIP 文件

```bash
# 1. 下载项目
wget https://github.com/xynet81/proxy_rename/archive/refs/heads/main.zip
unzip main.zip
cd proxy_rename-main

# 2. 准备订阅文件
echo "你的订阅链接" > subs.txt

# 3. 构建并启动
docker-compose up -d --build
```

### 方法 3：下载单个文件

```bash
# 创建项目目录
mkdir proxy_rename && cd proxy_rename

# 下载必要文件
wget https://raw.githubusercontent.com/xynet81/proxy_rename/main/dockerfile
wget https://raw.githubusercontent.com/xynet81/proxy_rename/main/docker-compose.yml
wget https://raw.githubusercontent.com/xynet81/proxy_rename/main/proxy_test_exit_ip.py

# 准备订阅文件
echo "你的订阅链接" > subs.txt

# 构建并启动
docker-compose up -d --build
```

### 自定义镜像名称

编辑 `docker-compose.yml` 第 6 行，修改 `image` 字段：

```yaml
services:
  proxy-tester:
    image: your-registry/sub-store:v1.0.0  # 修改这里
    # ... 其他配置
```

### Docker Compose 配置说明

```yaml
services:
  proxy-tester:
    image: sub-store:latest           # 镜像名称（可自定义）
    container_name: proxy-rename       # 容器名称
    volumes:
      - ./app:/app                   # 挂载整个 /app 目录
    environment:
      - API_KEY=xynet                # API 密钥
    ports:
      - "5005:5005"                 # 端口映射
    command: >                         # 启动命令
      python proxy_test_exit_ip.py
      --sub_urls /app/subs.txt        # 订阅文件路径
      --interval_hours 24              # 定时间隔（小时）
      --mode webhook                  # 运行模式
      --port 5005                     # 服务端口
      --max_workers 4                  # 并发数（默认 4）
      --prefix ICY-                    # 节点名称前缀（可选）
```

### 常用命令

```bash
# 构建镜像
docker-compose build

# 启动服务（后台）
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose stop

# 停止并删除容器
docker-compose down

# 重新构建并启动
docker-compose up -d --build

# 查看容器状态
docker-compose ps

# 进入容器
docker-compose exec proxy-tester bash
```

## 使用说明

### 定时任务
- 启动后会立即运行一次检测，随后按 `--interval_hours` 间隔定时执行。
- 输出目录（容器内 `/app/output`）保存：
  - `results_YYYYMMDD_HHMMSS.json`：详细测试结果
  - `new_sub_YYYYMMDD_HHMMSS.txt`：base64 编码的新订阅

### API（Webhook）
- 健康检查：GET /health

    ```bash
    curl http://<host>:5005/health
    ```

- 获取订阅：GET /subscribe（支持 Accept: text/plain 返回纯 base64）

- 按需处理：POST /process

Headers:
- Content-Type: application/json
- X-API-Key: <your-key>

Body 示例：

    ```json
    {
      "sub_urls": ["https://example.com/sub"],
      "max_workers": 2,
      "include_details": false
    }
    ```

返回示例：

    ```json
    {"new_sub_b64": "...", "success_count": 12, "total_nodes": 20}
    ```

## 常见问题与排查建议

- 容器立即退出（Exited:0）：检查 `subs.txt` 是否存在且非空；查看容器日志确认 argparse 参数是否传递正确。
- argparse 错误：确认 compose 或运行命令使用的参数名称与脚本中定义一致（支持 `--sub_urls`，也可以改为接收 `--sub_url`）。
- ip-api 限流（429）：将 `--max_workers` 调小，或更换 API。脚本已包含限流/重试优化建议。
- Xray 无法启动：确认 Xray 可执行文件在容器中存在并具有执行权限，或通过 `--xray_path` 指定正确路径。
- requests socks5 问题：安装 `requests[socks]` 或 `pysocks`。

若需进入容器调试：

```bash
docker compose exec proxy-tester bash
python proxy_test_exit_ip.py --help
```

## 贡献 & 许可证

欢迎 Fork、Issue 与 PR。项目采用 MIT License，欢迎在遵守许可的前提下使用与改进。请在提交 PR 前运行基本测试并更新 README。

---

感谢使用 Proxy Rename。如需定制协议支持或集成帮助，请在仓库中提交 Issue。