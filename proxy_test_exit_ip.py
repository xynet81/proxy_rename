import json
import base64
import urllib.parse
import subprocess
import tempfile
import os
import time
import argparse
import threading
import schedule
import logging
import asyncio
from flask import Flask, request, jsonify, Response
from typing import List, Dict, Optional, Tuple
import httpx

# 常量定义
SUPPORTED_PROTOCOLS = ('vmess', 'vless', 'ss', 'trojan', 'hysteria2')
PROTOCOL_PREFIXES = tuple(f'{p}://' for p in SUPPORTED_PROTOCOLS)
FILTERED_PORT = 53

# 辅助函数
def decode_base64_padded(content: str) -> str:
    """解码 base64 内容，自动补全 padding"""
    padding = '=' * (4 - len(content) % 4) if len(content) % 4 else ''
    return base64.b64decode(content + padding).decode('utf-8')

def is_valid_uri(uri: str) -> bool:
    """检查是否为有效的代理 URI"""
    return any(uri.startswith(prefix) for prefix in PROTOCOL_PREFIXES)

def filter_valid_uris(uris: List[str]) -> List[str]:
    """过滤出有效的代理 URI"""
    return [u for u in uris if is_valid_uri(u)]

# 配置日志
os.makedirs('/app/output', exist_ok=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler('/app/output/webhook.log'), logging.StreamHandler()])

# 全局变量：存储最新新订阅
latest_new_sub_b64 = ''
latest_results = []

# 全局锁，避免端口冲突
port_lock = threading.Lock()
next_port = 10801


def get_free_port() -> int:
    """获取可用端口。"""
    global next_port
    with port_lock:
        port = next_port
        next_port += 1
        if next_port > 10900:
            next_port = 10801
        return port


async def fetch_subscriptions(sub_urls: List[str]) -> List[str]:
    """异步并行从多个订阅 URL 获取并解码 URI 列表（去重）。"""
    async def fetch_single(url: str, client: httpx.AsyncClient) -> set:
        """异步获取单个订阅 URL"""
        try:
            response = await client.get(url, timeout=10)
            response.raise_for_status()
            content = response.text.strip()
            
            # 尝试 base64 解码
            try:
                decoded = decode_base64_padded(content)
                lines = decoded.split('\n')
            except (ValueError, UnicodeDecodeError, base64.binascii.Error):
                # 非 base64，直接按行处理
                lines = content.split('\n')
            
            uris = filter_valid_uris([line.strip() for line in lines if line.strip()])
            logging.info(f"从 {url} 获取 {len(uris)} 个节点")
            return set(uris)
        except httpx.HTTPError as e:
            logging.error(f"订阅 {url} 获取失败: {e}")
            return set()
    
    all_uris = set()
    async with httpx.AsyncClient() as client:
        tasks = [fetch_single(url, client) for url in sub_urls]
        results = await asyncio.gather(*tasks)
        for result in results:
            all_uris.update(result)
    
    uris_list = list(all_uris)
    logging.info(f"总有效节点: {len(uris_list)}")
    return uris_list


async def get_ip_geo(ip: str, client: httpx.AsyncClient, max_retries: int = 3) -> Optional[Dict[str, str]]:
    """
    异步查询 IP 的地理信息（带限流重试）。
    """
    if not ip or ip.startswith('127.') or ip.startswith('::1'):
        return None

    url = f"http://ip-api.com/json/{ip}?fields=status,countryCode,region"
    for attempt in range(max_retries):
        try:
            response = await client.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'countryCode': data.get('countryCode', '未知'),
                    'region': data.get('region', '未知')
                }
            elif data.get('status') == 'fail' and 'rate limit' in data.get('message', ''):
                wait_time = 60 * (attempt + 1)
                logging.warning(
                    f"ip-api 限流，等待 {wait_time}s (尝试 {attempt+1}/{max_retries})")
                await asyncio.sleep(wait_time)
                continue
            return None
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                wait_time = 60 * (attempt + 1)
                logging.warning(
                    f"ip-api 429 限流，等待 {wait_time}s (尝试 {attempt+1}/{max_retries})")
                await asyncio.sleep(wait_time)
                continue
            raise
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # 指数退避
                continue
            return None

    return None


def modify_uri_name(uri: str, new_name: str) -> str:
    """修改 URI 名称（VMess 修改 ps，其他追加 #name）。"""
    protocol = uri.split('://')[0]
    if protocol == 'vmess':
        try:
            encoded_part = uri.split('://')[1].split('#')[0]
            decoded = decode_base64_padded(encoded_part)
            config = json.loads(decoded)
            config['ps'] = new_name
            new_encoded = base64.b64encode(json.dumps(
                config).encode('utf-8')).decode('utf-8').rstrip('=')
            return f"vmess://{new_encoded}" + (f"#{new_name}" if '#' in uri else '')
        except (ValueError, json.JSONDecodeError, KeyError):
            pass
    
    # 其他协议：替换或追加 #name
    if '#' not in uri:
        return uri + f"#{new_name}"
    return uri.rsplit('#', 1)[0] + f"#{new_name}"


def extract_port_from_uri(uri: str) -> Optional[int]:
    """从 URI 中提取端口号"""
    try:
        if not is_valid_uri(uri):
            return None
            
        protocol = uri.split('://')[0]
        encoded_part = uri.split('://')[1].split('#')[0]
        
        if protocol == 'vmess':
            try:
                decoded = decode_base64_padded(encoded_part)
                config = json.loads(decoded)
                return int(config['port'])
            except (ValueError, json.JSONDecodeError, KeyError):
                return None
        
        # vless, ss, trojan, hysteria2 使用 urlparse
        parsed = urllib.parse.urlparse(f"{protocol}://{encoded_part}")
        return parsed.port
    except (ValueError, AttributeError):
        return None


def parse_proxy_uri_to_xray_config(uri: str) -> Optional[Dict]:
    """解析 URI 到 Xray JSON 配置。"""
    if not is_valid_uri(uri):
        return None

    protocol = uri.split('://')[0]
    encoded_part = uri.split('://')[1].split('#')[0]

    try:
        outbound = {'protocol': protocol.upper()}
        if protocol == 'vmess':
            decoded = decode_base64_padded(encoded_part)
            config = json.loads(decoded)
            outbound['settings'] = {'vnext': [{'address': config['add'], 'port': int(config['port']), 'users': [
                {'id': config['id'], 'alterId': config.get('aid', 0), 'security': config.get('scy', 'auto')}]}]}
            outbound['streamSettings'] = {'network': config.get('net', 'tcp'), 'security': config.get('tls', '')}
            if config.get('tls') == 'tls':
                outbound['streamSettings']['tlsSettings'] = {'serverName': config.get('host', config['add'])}
                
        elif protocol == 'vless':
            parsed = urllib.parse.urlparse(f"{protocol}://{encoded_part}")
            params = urllib.parse.parse_qs(parsed.query)
            outbound['settings'] = {'vnext': [{'address': parsed.hostname, 'port': int(parsed.port),
                'users': [{'id': parsed.username, 'encryption': params.get('encryption', ['none'])[0]}]}]}
            
            # 处理传输层配置
            network = params.get('type', ['tcp'])[0]
            security = params.get('security', ['none'])[0]
            stream_settings = {'network': network, 'security': security}
            
            # TLS配置
            if security == 'tls':
                stream_settings['tlsSettings'] = {'serverName': params.get('sni', [parsed.hostname])[0]}
                if params.get('fp'):
                    stream_settings['tlsSettings']['fingerprint'] = params['fp'][0]
                if params.get('allowInsecure'):
                    stream_settings['tlsSettings']['allowInsecure'] = params['allowInsecure'][0] == '1'
            
            # Reality配置
            elif security == 'reality':
                stream_settings['realitySettings'] = {
                    'serverName': params.get('sni', [parsed.hostname])[0],
                    'publicKey': params.get('pbk', [''])[0],
                    'shortId': params.get('sid', [''])[0],
                    'serverNames': [params.get('servername', [params.get('sni', [parsed.hostname])[0]])[0]],
                    'spiderX': params.get('spx', ['/'])[0],
                    'fingerprint': params.get('fp', ['chrome'])[0]
                }
            
            # WebSocket配置
            if network == 'ws':
                stream_settings['wsSettings'] = {
                    'path': urllib.parse.unquote(params.get('path', ['/'])[0])
                }
                if params.get('host'):
                    stream_settings['wsSettings']['headers'] = {'Host': params['host'][0]}
            
            # gRPC配置
            elif network == 'grpc':
                stream_settings['grpcSettings'] = {
                    'serviceName': params.get('serviceName', [''])[0],
                    'multiMode': params.get('mode', ['auto'])[0] == 'multi'
                }
            
            # XHTTP配置
            elif network == 'xhttp':
                stream_settings['xhttpSettings'] = {
                    'path': urllib.parse.unquote(params.get('path', [''])[0]),
                    'mode': params.get('mode', ['auto'])[0]
                }
                if params.get('host'):
                    stream_settings['xhttpSettings']['host'] = params['host'][0]
            
            outbound['streamSettings'] = stream_settings
                
        elif protocol == 'ss':
            parts = encoded_part.split('@')
            if len(parts) < 2:
                return None
            method_pass = parts[0]
            if ':' not in method_pass:
                method_pass = decode_base64_padded(method_pass)
            method, password = method_pass.split(':', 1)
            host, port = parts[1].split(':')
            outbound['settings'] = {'servers': [{'address': host, 'port': int(port), 'method': method, 'password': password}]}
            
        elif protocol == 'trojan':
            parsed = urllib.parse.urlparse(f"{protocol}://{encoded_part}")
            params = urllib.parse.parse_qs(parsed.query)
            outbound['settings'] = {'servers': [{'address': parsed.hostname, 'port': int(parsed.port), 'password': parsed.username}]}
            
            # 处理传输层配置
            network = params.get('type', ['tcp'])[0]
            stream_settings = {'network': network}
            
            # 安全设置
            security = params.get('security', ['none'])[0]
            if security == 'tls':
                stream_settings['security'] = 'tls'
                stream_settings['tlsSettings'] = {'serverName': params.get('sni', [parsed.hostname])[0]}
                if params.get('fp'):
                    stream_settings['tlsSettings']['fingerprint'] = params['fp'][0]
                if params.get('allowInsecure'):
                    stream_settings['tlsSettings']['allowInsecure'] = params['allowInsecure'][0] == '1'
            
            # WebSocket配置
            if network == 'ws':
                stream_settings['wsSettings'] = {
                    'path': params.get('path', ['/'])[0]
                }
                if params.get('host'):
                    stream_settings['wsSettings']['headers'] = {'Host': params['host'][0]}
            
            outbound['streamSettings'] = stream_settings
            
        elif protocol == 'hysteria2':
            parsed = urllib.parse.urlparse(f"{protocol}://{encoded_part}")
            params = urllib.parse.parse_qs(parsed.query)
            
            # 处理IPv6地址 - 去除方括号
            hostname = parsed.hostname
            if hostname and hostname.startswith('[') and hostname.endswith(']'):
                hostname = hostname[1:-1]
            
            outbound['settings'] = {'servers': [{'address': hostname, 'port': int(parsed.port), 'password': parsed.username}]}
            outbound['streamSettings'] = {'network': 'hysteria2', 'security': 'tls'}
            
            # TLS/SNI配置 - Hysteria2必需TLS
            outbound['streamSettings']['tlsSettings'] = {
                'serverName': params.get('sni', [hostname])[0],
                'allowInsecure': params.get('insecure', ['0'])[0] == '1'
            }
            if params.get('fp'):
                outbound['streamSettings']['tlsSettings']['fingerprint'] = params['fp'][0]
            
            # Hysteria2特定配置
            hysteria2_settings = {}
            if 'obfs' in params:
                hysteria2_settings['obfs'] = params['obfs'][0]
                hysteria2_settings['obfs-password'] = params.get('obfs-password', [''])[0]
            
            if hysteria2_settings:
                outbound['streamSettings']['hysteria2Settings'] = hysteria2_settings
        else:
            return None

        local_port = get_free_port()
        config = {
            "inbounds": [{"port": local_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}, "listen": "127.0.0.1"}],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
            "routing": {"rules": [{"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]}]}
        }
        config['outbounds'][0]['tag'] = 'proxy'
        return {'config': config, 'port': local_port, 'uri': uri}
    except (ValueError, json.JSONDecodeError, KeyError, AttributeError) as e:
        logging.error(f"解析 URI 异常 ({uri[:30]}...): {e}")
        return None


async def start_xray_and_test(config_info: Dict, xray_path: str = 'xray', timeout: int = 10) -> Dict[str, any]:
    """启动 Xray 测试出口 IP（超时增到 10s），使用异步查询地理信息。"""
    config = config_info['config']
    port = config_info['port']
    uri = config_info['uri']

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f, indent=2)
        config_file = f.name

    proc = None
    try:
        proc = subprocess.Popen([xray_path, 'run', '-c', config_file],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(2)

        # 使用 httpx 异步查询出口 IP
        async with httpx.AsyncClient(proxy=f'socks5://127.0.0.1:{port}') as client:
            response = await client.get(
                'http://ip-api.com/json?fields=status,query', timeout=timeout)

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    exit_ip = data.get('query', '未知')
                    geo = await get_ip_geo(exit_ip, client)
                    status = '连接成功'
                    reachable = True
                else:
                    exit_ip, geo, status, reachable = '未知', None, 'API 响应失败', False
            else:
                exit_ip, geo, status, reachable = '未知', None, f'HTTP {response.status_code}', False

            return {
                'original_uri': uri,
                'protocol': config['outbounds'][0]['protocol'].lower(),
                'local_port': port,
                'exit_ip': exit_ip,
                'countryCode': geo['countryCode'] if geo else '未知',
                'region': geo['region'] if geo else '未知',
                'status': status,
                'reachable': reachable
            }
    except Exception as e:
        status = f'测试异常: {e}'
        return {
            'original_uri': uri,
            'protocol': config.get('outbounds', [{}])[0].get('protocol', '未知').lower(),
            'local_port': port,
            'exit_ip': '未知',
            'countryCode': '未知',
            'region': '未知',
            'status': status,
            'reachable': False
        }
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        os.unlink(config_file)


async def process_batch(uris: List[str], max_workers: int = 4, xray_path: str = 'xray', include_details: bool = False, prefix: str = '') -> Tuple[List[Dict], str, int, int]:
    """异步处理批量节点（默认并发 4 + 延时），过滤53端口的节点。"""
    results = []
    new_uris = []
    semaphore = asyncio.Semaphore(max_workers)

    async def process_single(uri: str, index: int) -> Dict:
        async with semaphore:
            protocol = uri.split('://')[0] if '://' in uri else '未知'
            uri_preview =  uri
            port = extract_port_from_uri(uri)
            
            # 过滤53端口的节点
            if port == FILTERED_PORT:
                logging.info(f"[{index + 1}/{len(uris)}] 过滤53端口节点 | 协议={protocol} | 端口={port} | URI={uri_preview}")
                return {
                    'original_uri': uri,
                    'protocol': protocol,
                    'status': '已过滤(53端口)',
                    'reachable': False,
                    'new_uri': uri
                }
            
            config_info = parse_proxy_uri_to_xray_config(uri)
            if not config_info:
                logging.warning(f"[{index + 1}/{len(uris)}] URI解析失败 | 协议={protocol} | 端口={port} | URI={uri_preview}")
                return {
                    'original_uri': uri,
                    'protocol': protocol,
                    'status': 'URI 解析失败',
                    'reachable': False,
                    'new_uri': uri
                }

            result = await start_xray_and_test(config_info, xray_path)
            if result['reachable'] and result['countryCode'] != '未知' and result['region'] != '未知':
                new_name = f"{prefix}{result['countryCode']}-{result['region']}-{index + 1:03d}"
                new_uri = modify_uri_name(result['original_uri'], new_name)
                result['new_name'] = new_name
                result['new_uri'] = new_uri
                new_uris.append(new_uri)
                
                # 记录成功节点信息
                logging.info(
                    f"[{index + 1}/{len(uris)}] 测试成功 | 协议={result['protocol']} | 端口={port} | "
                    f"出口IP={result['exit_ip']} | 国家={result['countryCode']}-{result['region']} | "
                    f"新名称={new_name} | 本地端口={result['local_port']} | URI={uri_preview}")
            else:
                result['new_uri'] = result['original_uri']
                new_uris.append(result['original_uri'])
                
                # 记录失败节点信息
                logging.warning(
                    f"[{index + 1}/{len(uris)}] 测试失败 | 协议={result['protocol']} | 端口={port} | "
                    f"状态={result['status']} | 本地端口={result.get('local_port', 'N/A')} | URI={uri_preview}")

            return result

    # 并行处理所有节点
    tasks = [process_single(uri, i) for i, uri in enumerate(uris)]
    
    # 逐个获取结果以支持限流
    for task in asyncio.as_completed(tasks):
        result = await task
        results.append(result)
        # 限流延时：每请求 1.5s
        await asyncio.sleep(1.5)

    # 生成新订阅 base64（仅成功节点）
    successful_new_uris = [r['new_uri'] for r in results if r['reachable']]
    new_sub_content = '\n'.join(successful_new_uris)
    new_sub_b64 = base64.b64encode(new_sub_content.encode('utf-8')).decode('utf-8')

    total_nodes = len(uris)
    success_count = len(successful_new_uris)
    logging.info(f"处理完成: {total_nodes} 个节点，新订阅包含 {success_count} 个成功节点。")

    return results, new_sub_b64, total_nodes, success_count


def scheduled_job(sub_urls: List[str], interval_hours: int, max_workers: int = 4, xray_path: str = 'xray', prefix: str = ''):
    """定时任务：访问订阅、处理、保存本地、更新全局。"""
    async def async_job():
        global latest_new_sub_b64, latest_results
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        output_file = f"/app/output/results_{timestamp}.json"
        sub_output_file = f"/app/output/new_sub_{timestamp}.txt"
        logging.info(f"\n=== 定时任务执行: {timestamp} ===")
        uris = await fetch_subscriptions(sub_urls)
        if uris:
            results, new_sub_b64, total, success = await process_batch(
                uris, max_workers, xray_path, False, prefix)
            # 保存本地
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            with open(sub_output_file, 'w', encoding='utf-8') as f:
                f.write(new_sub_b64)
            # 更新全局（供 /subscribe 使用）
            latest_new_sub_b64 = new_sub_b64
            latest_results = results
            logging.info(f"结果保存: {output_file}, {sub_output_file}")
        else:
            logging.warning("无 URI，跳过处理")

    def job():
        """同步包装器，使用 asyncio.run() 执行异步任务"""
        asyncio.run(async_job())

    # 立即执行一次
    job()

    # 调度
    schedule.every(interval_hours).hours.do(job)

    logging.info(f"定时调度启动: 每 {interval_hours} 小时执行一次。")
    while True:
        schedule.run_pending()
        time.sleep(60)


# Flask Webhook API
app = Flask(__name__)
API_KEY = os.getenv('API_KEY', 'your-secret-key')


@app.route('/process', methods=['POST'])
def webhook_process():
    """Webhook 端点：处理订阅，返回新订阅 JSON。"""
    async def async_webhook_logic():
        try:
            if request.headers.get('X-API-Key') != API_KEY:
                return jsonify({'error': 'Invalid API Key'}), 401

            data = request.json
            if not data or 'sub_urls' not in data:
                return jsonify({'error': 'Missing sub_urls in request body'}), 400

            sub_urls = data['sub_urls']
            max_workers = data.get('max_workers', 4)
            include_details = data.get('include_details', False)

            logging.info(f"Webhook 调用: {len(sub_urls)} 个订阅 URL")

            uris = await fetch_subscriptions(sub_urls)
            if not uris:
                return jsonify({'error': 'No valid URIs found', 'new_sub_b64': ''}), 400

            results, new_sub_b64, total_nodes, success_count = await process_batch(
                uris, max_workers, 'xray', include_details, data.get('prefix', ''))

            response = {
                'new_sub_b64': new_sub_b64,
                'success_count': success_count,
                'total_nodes': total_nodes,
                'success_rate': round((success_count / total_nodes * 100), 2) if total_nodes > 0 else 0
            }
            if include_details:
                response['results'] = results

            # 更新全局
            global latest_new_sub_b64, latest_results
            latest_new_sub_b64 = new_sub_b64
            latest_results = results

            logging.info(f"Webhook 返回: {success_count}/{total_nodes} 成功")
            return jsonify(response)

        except (KeyError, TypeError) as e:
            logging.error(f"Webhook 数据解析异常: {e}")
            return jsonify({'error': f'Invalid request data: {e}'}), 400
        except Exception as e:
            logging.error(f"Webhook 异常: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    return asyncio.run(async_webhook_logic())


@app.route('/sub', methods=['GET'])
def subscribe_endpoint():
    """外部订阅端点：返回最新 new_sub_b64（纯 base64 或 JSON）。"""
    global latest_new_sub_b64
    if not latest_new_sub_b64:
        return jsonify({'error': 'No subscription data available yet. Wait for first scheduled run or webhook call.'}), 404

    # 检查 Accept header
    accept_header = request.headers.get('Accept', '')
    if 'application/base64' in accept_header or 'text/plain' in accept_header:
        # 返回纯 base64（订阅客户端友好）
        return Response(latest_new_sub_b64, mimetype='text/plain')
    else:
        # 返回 JSON
        return  latest_new_sub_b64


@app.route('/health', methods=['GET'])
def health_check():
    """健康检查端点。"""
    return jsonify({'status': 'healthy', 'latest_update': time.strftime('%Y-%m-%d %H:%M:%S')})


# 主函数
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="代理订阅节点定时测试与 Webhook")
    parser.add_argument('--sub_urls', type=str,default='subs.txt',
                         help="订阅链接，逗号分隔 或 文件路径（定时用）")
    parser.add_argument('--prefix', type=str, default='',
                        help="节点名称前缀 (e.g., MyVPN-)")
    parser.add_argument('--interval_hours', type=int,
                        default=1, help="定时间隔（小时）")
    parser.add_argument('--output_dir', type=str,
                        default='/app/output', help="输出目录")
    parser.add_argument('--max_workers', type=int, default=4, help="并发线程数")
    parser.add_argument('--xray_path', type=str,
                        default='xray', help="Xray 二进制路径")
    parser.add_argument(
        '--mode', choices=['webhook'], default='webhook', help="运行模式: webhook (API + 定时)")
    parser.add_argument('--port', type=int, default=5000, help="Webhook 端口")
    parser.add_argument('--api_key', type=str, help="API Key")

    args = parser.parse_args()

    if args.api_key:
        os.environ['API_KEY'] = args.api_key

    if args.mode == 'webhook':
        # 解析 sub_urls（定时用）
        if os.path.isfile(args.sub_urls):
            with open(args.sub_urls, 'r') as f:
                sub_urls_list = [line.strip() for line in f if line.strip()]
        else:
            sub_urls_list = [url.strip()
                             for url in args.sub_urls.split(',') if url.strip()]

        if not sub_urls_list:
            logging.error("无有效订阅链接")
            exit(1)

        # 启动后台定时线程
        scheduler_thread = threading.Thread(target=scheduled_job, args=(
            sub_urls_list, args.interval_hours, args.max_workers, args.xray_path, args.prefix), daemon=True)
        scheduler_thread.start()

        logging.info(
            f"启动 Webhook API 于端口 {args.port} + 后台定时（订阅: {len(sub_urls_list)} 个）")
        app.run(host='0.0.0.0', port=args.port, debug=False)
