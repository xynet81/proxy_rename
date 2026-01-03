# Sing-box 实施计划

## 概述

将项目从 Xray-core 迁移到 sing-box，以获得对 Hysteria2 协议的原生支持。

## 实施步骤

### 步骤 1: 更新 Dockerfile

**文件**: [`dockerfile`](../dockerfile:1)

**修改内容**:
```dockerfile
# 下载并安装 sing-box（最新版本）
RUN wget https://github.com/SagerNet/sing-box/releases/download/v1.10.0/sing-box-1.10.0-linux-amd64.tar.gz \
    && tar -xzf sing-box-1.10.0-linux-amd64.tar.gz \
    && mv sing-box-1.10.0-linux-amd64/sing-box /usr/local/bin/ \
    && chmod +x /usr/local/bin/sing-box \
    && rm -rf sing-box-1.10.0-linux-amd64.tar.gz sing-box-1.10.0-linux-amd64

# 验证安装
RUN sing-box version
```

### 步骤 2: 修改 Python 脚本

**文件**: [`proxy_test_exit_ip.py`](../proxy_test_exit_ip.py:1)

#### 2.1 重命名函数

- `parse_proxy_uri_to_xray_config()` → `parse_proxy_uri_to_singbox_config()`
- `start_xray_and_test()` → `start_singbox_and_test()`

#### 2.2 修改配置生成逻辑

**VMess 配置格式**:
```json
{
  "type": "vmess",
  "tag": "proxy",
  "server": "example.com",
  "server_port": 443,
  "uuid": "uuid",
  "security": "auto",
  "alter_id": 0,
  "tls": {
    "enabled": true,
    "server_name": "example.com"
  },
  "transport": {
    "type": "ws",
    "path": "/path"
  }
}
```

**VLESS 配置格式**:
```json
{
  "type": "vless",
  "tag": "proxy",
  "server": "example.com",
  "server_port": 443,
  "uuid": "uuid",
  "flow": "",
  "network": "tcp",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "reality": {
      "enabled": true,
      "public_key": "key",
      "short_id": "id"
    }
  },
  "transport": {
    "type": "ws",
    "path": "/path"
  }
}
```

**Shadowsocks 配置格式**:
```json
{
  "type": "shadowsocks",
  "tag": "proxy",
  "server": "example.com",
  "server_port": 8388,
  "method": "aes-256-gcm",
  "password": "password"
}
```

**Trojan 配置格式**:
```json
{
  "type": "trojan",
  "tag": "proxy",
  "server": "example.com",
  "server_port": 443,
  "password": "password",
  "tls": {
    "enabled": true,
    "server_name": "example.com"
  },
  "transport": {
    "type": "ws",
    "path": "/path"
  }
}
```

**Hysteria2 配置格式**:
```json
{
  "type": "hysteria2",
  "tag": "proxy",
  "server": "example.com",
  "server_port": 443,
  "password": "password",
  "tls": {
    "enabled": true,
    "server_name": "example.com",
    "insecure": false
  },
  "obfs": {
    "type": "salamander",
    "password": "obfs-password"
  }
}
```

#### 2.3 修改启动命令

**原命令**:
```python
subprocess.Popen([xray_path, 'run', '-c', config_file], ...)
```

**新命令**:
```python
subprocess.Popen([singbox_path, 'run', '-c', config_file], ...)
```

#### 2.4 更新命令行参数

```python
parser.add_argument('--xray_path', type=str,
                    default='sing-box', help="Sing-box 二进制路径")
```

### 步骤 3: 添加 CLI 模式支持

**新增函数**: `cli_mode()`

```python
async def cli_mode(sub_urls: List[str], max_workers: int = 4, singbox_path: str = 'sing-box', prefix: str = ''):
    """CLI 模式：运行测试并保存结果"""
    uris = await fetch_subscriptions(sub_urls)
    if not uris:
        logging.error("无有效节点")
        return
    
    results, new_sub_b64, total, success = await process_batch(
        uris, max_workers, singbox_path, False, prefix)
    
    # 保存结果
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    os.makedirs('results', exist_ok=True)
    
    with open(f'results/results_{timestamp}.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    with open(f'results/new_sub_{timestamp}.txt', 'w', encoding='utf-8') as f:
        f.write(new_sub_b64)
    
    # 创建最新订阅链接
    with open('results/latest_subscription.txt', 'w', encoding='utf-8') as f:
        f.write(new_sub_b64)
    
    logging.info(f"测试完成: {success}/{total} 成功")
    logging.info(f"结果保存到: results/results_{timestamp}.json")
    logging.info(f"订阅保存到: results/new_sub_{timestamp}.txt")
```

**添加命令行参数**:
```python
parser.add_argument('--mode', choices=['webhook', 'cli'], default='webhook', 
                    help="运行模式: webhook (API + 定时) 或 cli (命令行)")
parser.add_argument('--sub_urls_env', type=str,
                    help="从环境变量读取订阅链接")
```

### 步骤 4: 创建 GitHub Actions Workflow

**文件**: `.github/workflows/proxy-test.yml`

```yaml
name: Proxy Node Test

on:
  schedule:
    - cron: '0 */6 * * *'  # 每6小时
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      
      - name: Install Sing-box
        run: |
          wget https://github.com/SagerNet/sing-box/releases/download/v1.10.0/sing-box-1.10.0-linux-amd64.tar.gz
          tar -xzf sing-box-1.10.0-linux-amd64.tar.gz
          mv sing-box-1.10.0-linux-amd64/sing-box /usr/local/bin/
          chmod +x /usr/local/bin/sing-box
          sing-box version
      
      - name: Install dependencies
        run: |
          pip install httpx[socks] schedule flask
      
      - name: Run proxy test
        env:
          SUBSCRIPTION_URLS: ${{ secrets.SUBSCRIPTION_URLS }}
        run: |
          python proxy_test_exit_ip.py --mode cli --sub_urls_env SUBSCRIPTION_URLS
      
      - name: Commit results
        run: |
          git config --local user.email "github-actions[bot]@users.noreply.github.com"
          git config --local user.name "github-actions[bot]"
          git add results/
          git commit -m "Update test results" || exit 0
          git push
```

### 步骤 5: 更新文档

**文件**: `README.md`

**添加内容**:
```markdown
## 支持的协议

- ✅ VMess
- ✅ VLESS
- ✅ Shadowsocks (ss)
- ✅ Trojan
- ✅ Hysteria2

## 核心组件

本项目使用 **Sing-box** 作为代理核心，支持所有主流代理协议。

### 使用方法

#### Docker 部署

```bash
docker build -t proxy-test .
docker run -p 5000:5000 -e API_KEY=your-key proxy-test
```

#### GitHub Actions 部署

1. Fork 本仓库
2. 在 Settings > Secrets 中添加 `SUBSCRIPTION_URLS`
3. 推送代码，自动触发测试
4. 或手动触发 workflow
```

## 配置 GitHub Secrets

在仓库 Settings > Secrets and variables > Actions 中添加：

- `SUBSCRIPTION_URLS`: 订阅链接，多个用逗号分隔

## 文件清单

需要修改的文件：

```
dockerfile                              # 更新：安装 sing-box
proxy_test_exit_ip.py                   # 修改：配置生成逻辑 + CLI 模式
.github/workflows/proxy-test.yml         # 新增：GitHub Actions 配置
README.md                               # 更新：使用说明
results/                                # 新增：测试结果目录（自动创建）
```

## 参考资料

- Sing-box 官方文档: https://sing-box.sagernet.org/
- Sing-box GitHub: https://github.com/SagerNet/sing-box
- Sing-box 配置示例: https://sing-box.sagernet.org/configuration/
