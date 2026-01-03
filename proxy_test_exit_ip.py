"""
代理订阅节点测试与重命名工具
支持多种协议：vmess, vless, ss, trojan, hysteria2
"""

import asyncio
import base64
import json
import logging
import os
import subprocess
import tempfile
import threading
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple, Set

import httpx
from flask import Flask, jsonify, request, Response

# ==================== 常量定义 ====================
SUPPORTED_PROTOCOLS = ('vmess', 'vless', 'ss', 'trojan', 'hysteria2')
PROTOCOL_PREFIXES = tuple(f'{p}://' for p in SUPPORTED_PROTOCOLS)

# 端口配置
FILTERED_PORT = 53
PORT_RANGE_START = 10801
PORT_RANGE_END = 10900

# 超时配置
HTTP_TIMEOUT = 10
SINGBOX_STARTUP_DELAY = 2
PROCESS_WAIT_TIMEOUT = 3
IP_API_MAX_RETRIES = 3

# 速率限制
RATE_LIMIT_DELAY = 60
EXPONENTIAL_BACKOFF_BASE = 2

# 路径配置
OUTPUT_DIR = '/app/output'
LOG_FILE = '/app/output/webhook.log'

# API 配置
DEFAULT_API_KEY = 'your-secret-key'

# ==================== 日志配置 ====================
def setup_logging() -> None:
    """配置日志系统"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )

setup_logging()

# ==================== 全局状态管理 ====================
class GlobalState:
    """全局状态管理类，避免使用全局变量"""
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.latest_new_sub_b64 = ''
                    cls._instance.latest_results = []
        return cls._instance
    
    @property
    def latest_new_sub_b64(self) -> str:
        return self._latest_new_sub_b64
    
    @latest_new_sub_b64.setter
    def latest_new_sub_b64(self, value: str) -> None:
        self._latest_new_sub_b64 = value
    
    @property
    def latest_results(self) -> List[Dict]:
        return self._latest_results
    
    @latest_results.setter
    def latest_results(self, value: List[Dict]) -> None:
        self._latest_results = value

# 全局状态实例
global_state = GlobalState()

# ==================== 端口管理 ====================
class PortManager:
    """端口管理器，线程安全的端口分配"""
    def __init__(self, start: int = PORT_RANGE_START, end: int = PORT_RANGE_END):
        self.start = start
        self.end = end
        self.next_port = start
        self.lock = threading.Lock()
    
    def get_free_port(self) -> int:
        """获取可用端口"""
        with self.lock:
            port = self.next_port
            self.next_port += 1
            if self.next_port > self.end:
                self.next_port = self.start
            return port

port_manager = PortManager()

# ==================== 工具函数 ====================
def decode_base64_padded(content: str) -> str:
    """解码 base64 内容，自动补全 padding
    
    Args:
        content: base64 编码的字符串
        
    Returns:
        解码后的 UTF-8 字符串
    """
    padding = '=' * (4 - len(content) % 4) if len(content) % 4 else ''
    return base64.b64decode(content + padding).decode('utf-8')


def is_valid_uri(uri: str) -> bool:
    """检查是否为有效的代理 URI
    
    Args:
        uri: 待检查的 URI 字符串
        
    Returns:
        是否为有效 URI
    """
    return any(uri.startswith(prefix) for prefix in PROTOCOL_PREFIXES)


def filter_valid_uris(uris: List[str]) -> List[str]:
    """过滤出有效的代理 URI
    
    Args:
        uris: URI 列表
        
    Returns:
        有效的 URI 列表
    """
    return [u for u in uris if is_valid_uri(u)]


def parse_uri(uri: str) -> Tuple[Optional[str], Optional[str]]:
    """解析 URI，返回协议和编码部分
    
    Args:
        uri: 完整的 URI 字符串
        
    Returns:
        (协议, 编码部分) 或 (None, None) 如果解析失败
    """
    if '://' not in uri:
        return None, None
    
    protocol, rest = uri.split('://', 1)
    encoded_part = rest.split('#')[0] if '#' in rest else rest
    return protocol, encoded_part


def extract_port_from_uri(uri: str) -> Optional[int]:
    """从 URI 中提取端口号
    
    Args:
        uri: 完整的 URI 字符串
        
    Returns:
        端口号或 None
    """
    try:
        if not is_valid_uri(uri):
            return None
        
        protocol, encoded_part = parse_uri(uri)
        if not protocol or not encoded_part:
            return None
        
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


# ==================== 配置构建器 ====================
class TLSConfigBuilder:
    """TLS 配置构建器"""
    
    @staticmethod
    def build_tls_config(params: Dict, hostname: str, security: str = 'tls') -> Optional[Dict]:
        """构建 TLS 配置
        
        Args:
            params: URL 查询参数
            hostname: 主机名
            security: 安全类型 (tls/reality)
            
        Returns:
            TLS 配置字典或 None
        """
        if security == 'none':
            return None
        
        tls_config = {
            'enabled': True,
            'server_name': params.get('sni', [hostname])[0]
        }
        
        if security == 'reality':
            tls_config['reality'] = {
                'enabled': True,
                'public_key': params.get('pbk', [''])[0],
                'short_id': params.get('sid', [''])[0]
            }
            tls_config['utls'] = {'fingerprint': params.get('fp', ['chrome'])[0]}
        else:
            # TLS
            if params.get('fp'):
                tls_config['utls'] = {'fingerprint': params['fp'][0]}
            if params.get('allowInsecure'):
                tls_config['insecure'] = params['allowInsecure'][0] == '1'
        
        return tls_config


class TransportConfigBuilder:
    """传输层配置构建器"""
    
    @staticmethod
    def build_ws_config(params: Dict) -> Dict:
        """构建 WebSocket 配置"""
        config = {
            'type': 'ws',
            'path': urllib.parse.unquote(params.get('path', ['/'])[0])
        }
        if params.get('host'):
            config['headers'] = {'Host': params['host'][0]}
        return config
    
    @staticmethod
    def build_grpc_config(params: Dict) -> Dict:
        """构建 gRPC 配置"""
        return {
            'type': 'grpc',
            'service_name': params.get('serviceName', [''])[0]
        }
    
    @staticmethod
    def build_xhttp_config(params: Dict) -> Dict:
        """构建 XHTTP 配置"""
        config = {
            'type': 'xhttp',
            'path': urllib.parse.unquote(params.get('path', [''])[0])
        }
        if params.get('host'):
            config['host'] = params['host'][0]
        return config
    
    @classmethod
    def build_transport_config(cls, network: str, params: Dict) -> Optional[Dict]:
        """根据网络类型构建传输层配置
        
        Args:
            network: 网络类型 (ws/grpc/xhttp)
            params: URL 查询参数
            
        Returns:
            传输层配置字典或 None
        """
        builders = {
            'ws': cls.build_ws_config,
            'grpc': cls.build_grpc_config,
            'xhttp': cls.build_xhttp_config
        }
        builder = builders.get(network)
        return builder(params) if builder else None


def parse_proxy_uri_to_singbox_config(uri: str) -> Optional[Dict]:
    """解析 URI 到 Sing-box JSON 配置
    
    Args:
        uri: 代理 URI 字符串
        
    Returns:
        配置信息字典，包含 config, port, uri
    """
    if not is_valid_uri(uri):
        return None
    
    protocol, encoded_part = parse_uri(uri)
    if not protocol or not encoded_part:
        return None
    
    try:
        outbound = {'type': protocol}
        
        if protocol == 'vmess':
            decoded = decode_base64_padded(encoded_part)
            config = json.loads(decoded)
            outbound.update({
                'tag': 'proxy',
                'server': config['add'],
                'server_port': int(config['port']),
                'uuid': config['id'],
                'security': config.get('scy', 'auto'),
                'alter_id': config.get('aid', 0)
            })
            
            if config.get('tls') == 'tls':
                outbound['tls'] = {
                    'enabled': True,
                    'server_name': config.get('host', config['add'])
                }
            
            if config.get('net') == 'ws':
                outbound['transport'] = {
                    'type': 'ws',
                    'path': config.get('path', '/'),
                    'headers': {'Host': config.get('host', config['add'])}
                }
        
        elif protocol in ('vless', 'trojan'):
            parsed = urllib.parse.urlparse(f"{protocol}://{encoded_part}")
            params = urllib.parse.parse_qs(parsed.query)
            
            if protocol == 'vless':
                outbound.update({
                    'tag': 'proxy',
                    'server': parsed.hostname,
                    'server_port': int(parsed.port),
                    'uuid': parsed.username,
                    'flow': params.get('flow', [''])[0]
                })
            else:  # trojan
                outbound.update({
                    'tag': 'proxy',
                    'server': parsed.hostname,
                    'server_port': int(parsed.port),
                    'password': parsed.username
                })
            
            # TLS/Reality 配置
            security = params.get('security', ['none'])[0]
            tls_config = TLSConfigBuilder.build_tls_config(params, parsed.hostname, security)
            if tls_config:
                outbound['tls'] = tls_config
            
            # 传输层配置
            network = params.get('type', ['tcp'])[0]
            transport_config = TransportConfigBuilder.build_transport_config(network, params)
            if transport_config:
                outbound['transport'] = transport_config
        
        elif protocol == 'ss':
            parts = encoded_part.split('@')
            if len(parts) < 2:
                return None
            
            method_pass = parts[0]
            if ':' not in method_pass:
                method_pass = decode_base64_padded(method_pass)
            
            method, password = method_pass.split(':', 1)
            host, port = parts[1].split(':')
            
            outbound.update({
                'tag': 'proxy',
                'server': host,
                'server_port': int(port),
                'method': method,
                'password': password
            })
        
        elif protocol == 'hysteria2':
            parsed = urllib.parse.urlparse(f"{protocol}://{encoded_part}")
            params = urllib.parse.parse_qs(parsed.query)
            
            # 处理 IPv6 地址 - 去除方括号
            hostname = parsed.hostname
            if hostname and hostname.startswith('[') and hostname.endswith(']'):
                hostname = hostname[1:-1]
            
            outbound.update({
                'tag': 'proxy',
                'server': hostname,
                'server_port': int(parsed.port),
                'password': parsed.username,
                'tls': {
                    'enabled': True,
                    'server_name': params.get('sni', [hostname])[0],
                    'insecure': params.get('insecure', ['0'])[0] == '1'
                }
            })
            
            if params.get('fp'):
                outbound['tls']['utls'] = {'fingerprint': params['fp'][0]}
            
            # Hysteria2 特定配置
            if 'obfs' in params:
                outbound['obfs'] = {
                    'type': params['obfs'][0],
                    'password': params.get('obfs-password', [''])[0]
                }
        else:
            return None
        
        local_port = port_manager.get_free_port()
        config = {
            "log": {"level": "warn"},
            "inbounds": [{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": local_port
            }],
            "outbounds": [outbound, {
                "type": "direct",
                "tag": "direct"
            }],
            "route": {
                "rules": [{
                    "protocol": "dns",
                    "outbound": "direct"
                }],
                "final": "proxy"
            }
        }
        
        return {'config': config, 'port': local_port, 'uri': uri}
    
    except (ValueError, json.JSONDecodeError, KeyError, AttributeError) as e:
        logging.error(f"解析 URI 异常 ({uri[:30]}...): {e}")
        return None


# ==================== URI 名称修改 ====================
def modify_uri_name(uri: str, new_name: str) -> str:
    """修改 URI 名称（VMess 修改 ps，其他追加 #name）
    
    Args:
        uri: 原始 URI
        new_name: 新名称
        
    Returns:
        修改后的 URI
    """
    protocol, encoded_part = parse_uri(uri)
    if not protocol or not encoded_part:
        return uri
    
    if protocol == 'vmess':
        try:
            decoded = decode_base64_padded(encoded_part)
            config = json.loads(decoded)
            config['ps'] = new_name
            new_encoded = base64.b64encode(
                json.dumps(config).encode('utf-8')
            ).decode('utf-8').rstrip('=')
            return f"vmess://{new_encoded}" + (f"#{new_name}" if '#' in uri else '')
        except (ValueError, json.JSONDecodeError, KeyError):
            pass
    
    # 其他协议：替换或追加 #name
    if '#' not in uri:
        return uri + f"#{new_name}"
    return uri.rsplit('#', 1)[0] + f"#{new_name}"


# ==================== 订阅获取 ====================
async def fetch_subscriptions(sub_urls: List[str]) -> List[str]:
    """异步并行从多个订阅 URL 获取并解码 URI 列表（去重）
    
    Args:
        sub_urls: 订阅 URL 列表
        
    Returns:
        去重后的 URI 列表
    """
    async def fetch_single(url: str, client: httpx.AsyncClient) -> Set[str]:
        """异步获取单个订阅 URL"""
        try:
            response = await client.get(url, timeout=HTTP_TIMEOUT)
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


# ==================== IP 地理信息查询 ====================
async def get_ip_geo(ip: str, client: httpx.AsyncClient, max_retries: int = IP_API_MAX_RETRIES) -> Optional[Dict[str, str]]:
    """异步查询 IP 的地理信息（带限流重试）
    
    Args:
        ip: IP 地址
        client: httpx 异步客户端
        max_retries: 最大重试次数
        
    Returns:
        地理信息字典或 None
    """
    if not ip or ip.startswith('127.') or ip.startswith('::1'):
        return None
    
    url = f"http://ip-api.com/json/{ip}?fields=status,countryCode,region"
    
    for attempt in range(max_retries):
        try:
            response = await client.get(url, timeout=HTTP_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'success':
                return {
                    'countryCode': data.get('countryCode', '未知'),
                    'region': data.get('region', '未知')
                }
            
            if data.get('status') == 'fail' and 'rate limit' in data.get('message', '').lower():
                wait_time = RATE_LIMIT_DELAY * (attempt + 1)
                logging.warning(f"ip-api 限流，等待 {wait_time}s (尝试 {attempt+1}/{max_retries})")
                await asyncio.sleep(wait_time)
                continue
            
            return None
        
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                wait_time = RATE_LIMIT_DELAY * (attempt + 1)
                logging.warning(f"ip-api 429 限流，等待 {wait_time}s (尝试 {attempt+1}/{max_retries})")
                await asyncio.sleep(wait_time)
                continue
            raise
        
        except Exception:
            if attempt < max_retries - 1:
                await asyncio.sleep(EXPONENTIAL_BACKOFF_BASE ** attempt)
                continue
            return None
    
    return None


# ==================== Sing-box 测试 ====================
async def start_singbox_and_test(
    config_info: Dict,
    singbox_path: str = 'sing-box',
    timeout: int = HTTP_TIMEOUT
) -> Dict[str, any]:
    """启动 Sing-box 测试出口 IP
    
    Args:
        config_info: 配置信息字典
        singbox_path: sing-box 二进制路径
        timeout: 超时时间
        
    Returns:
        测试结果字典
    """
    config = config_info['config']
    port = config_info['port']
    uri = config_info['uri']
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f, indent=2)
        config_file = f.name
    
    proc = None
    try:
        proc = subprocess.Popen(
            [singbox_path, 'run', '-c', config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        await asyncio.sleep(SINGBOX_STARTUP_DELAY)
        
        # 使用 httpx 异步查询出口 IP
        async with httpx.AsyncClient(proxy=f'socks5://127.0.0.1:{port}') as client:
            response = await client.get(
                'http://ip-api.com/json?fields=status,query',
                timeout=timeout
            )
            
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
                'protocol': config['outbounds'][0]['type'].lower(),
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
            'protocol': config.get('outbounds', [{}])[0].get('type', '未知').lower(),
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
                proc.wait(timeout=PROCESS_WAIT_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
        os.unlink(config_file)


# ==================== 批量处理 ====================
async def process_batch(
    uris: List[str],
    max_workers: int = 4,
    singbox_path: str = 'sing-box',
    include_details: bool = False,
    prefix: str = '',
    rate_limit_delay: float = 1.5
) -> Tuple[List[Dict], str, int, int]:
    """异步处理批量节点（过滤53端口的节点）
    
    Args:
        uris: URI 列表
        max_workers: 最大并发数
        singbox_path: sing-box 二进制路径
        include_details: 是否包含详细信息
        prefix: 节点名称前缀
        rate_limit_delay: 速率限制延时（秒）
        
    Returns:
        (结果列表, 新订阅base64, 总节点数, 成功节点数)
    """
    results = []
    new_uris = []
    semaphore = asyncio.Semaphore(max_workers)
    
    async def process_single(uri: str, index: int) -> Dict:
        """处理单个 URI"""
        async with semaphore:
            protocol, _ = parse_uri(uri) or ('未知', None)
            uri_preview = uri
            port = extract_port_from_uri(uri)
            
            # 过滤53端口的节点
            if port == FILTERED_PORT:
                logging.info(
                    f"[{index + 1}/{len(uris)}] 过滤53端口节点 | "
                    f"协议={protocol} | 端口={port} | URI={uri_preview}"
                )
                return {
                    'original_uri': uri,
                    'protocol': protocol,
                    'status': '已过滤(53端口)',
                    'reachable': False,
                    'new_uri': uri
                }
            
            config_info = parse_proxy_uri_to_singbox_config(uri)
            if not config_info:
                logging.warning(
                    f"[{index + 1}/{len(uris)}] URI解析失败 | "
                    f"协议={protocol} | 端口={port} | URI={uri_preview}"
                )
                return {
                    'original_uri': uri,
                    'protocol': protocol,
                    'status': 'URI 解析失败',
                    'reachable': False,
                    'new_uri': uri
                }
            
            result = await start_singbox_and_test(config_info, singbox_path)
            
            if result['reachable'] and result['countryCode'] != '未知' and result['region'] != '未知':
                new_name = f"{prefix}{result['countryCode']}-{result['region']}-{index + 1:03d}"
                new_uri = modify_uri_name(result['original_uri'], new_name)
                result['new_name'] = new_name
                result['new_uri'] = new_uri
                new_uris.append(new_uri)
                
                logging.info(
                    f"[{index + 1}/{len(uris)}] 测试成功 | "
                    f"协议={result['protocol']} | 端口={port} | "
                    f"出口IP={result['exit_ip']} | 国家={result['countryCode']}-{result['region']} | "
                    f"新名称={new_name} | 本地端口={result['local_port']} | URI={uri_preview}"
                )
            else:
                result['new_uri'] = result['original_uri']
                new_uris.append(result['original_uri'])
                
                logging.warning(
                    f"[{index + 1}/{len(uris)}] 测试失败 | "
                    f"协议={result['protocol']} | 端口={port} | "
                    f"状态={result['status']} | 本地端口={result.get('local_port', 'N/A')} | URI={uri_preview}"
                )
            
            return result
    
    # 并行处理所有节点
    tasks = [process_single(uri, i) for i, uri in enumerate(uris)]
    
    # 使用 as_completed 支持限流
    for task in asyncio.as_completed(tasks):
        result = await task
        results.append(result)
        # 速率限制延时
        await asyncio.sleep(rate_limit_delay)
    
    # 生成新订阅 base64（包含所有节点，无论是否成功，仅修改节点名称）
    all_new_uris = [r['new_uri'] for r in results]
    new_sub_content = '\n'.join(all_new_uris)
    new_sub_b64 = base64.b64encode(new_sub_content.encode('utf-8')).decode('utf-8')
    
    total_nodes = len(uris)
    success_count = len([r for r in results if r['reachable']])
    logging.info(
        f"处理完成: {total_nodes} 个节点，新订阅包含 {len(all_new_uris)} 个节点，"
        f"其中 {success_count} 个测试成功。"
    )
    
    return results, new_sub_b64, total_nodes, success_count


# ==================== 定时任务 ====================
def scheduled_job(
    sub_urls: List[str],
    interval_hours: int,
    max_workers: int = 4,
    singbox_path: str = 'sing-box',
    prefix: str = ''
):
    """定时任务：访问订阅、处理、保存本地、更新全局
    
    Args:
        sub_urls: 订阅 URL 列表
        interval_hours: 间隔小时数
        max_workers: 最大并发数
        singbox_path: sing-box 二进制路径
        prefix: 节点名称前缀
    """
    async def async_job():
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        output_file = f"{OUTPUT_DIR}/results_{timestamp}.json"
        sub_output_file = f"{OUTPUT_DIR}/new_sub_{timestamp}.txt"
        
        logging.info(f"\n=== 定时任务执行: {timestamp} ===")
        
        uris = await fetch_subscriptions(sub_urls)
        if uris:
            results, new_sub_b64, total, success = await process_batch(
                uris, max_workers, singbox_path, False, prefix
            )
            
            # 保存本地
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            with open(sub_output_file, 'w', encoding='utf-8') as f:
                f.write(new_sub_b64)
            
            # 更新全局（供 /subscribe 使用）
            global_state.latest_new_sub_b64 = new_sub_b64
            global_state.latest_results = results
            
            logging.info(f"结果保存: {output_file}, {sub_output_file}")
        else:
            logging.warning("无 URI，跳过处理")
    
    def job():
        """同步包装器，使用 asyncio.run() 执行异步任务"""
        asyncio.run(async_job())
    
    # 立即执行一次
    job()
    
    # 调度
    import schedule
    schedule.every(interval_hours).hours.do(job)
    
    logging.info(f"定时调度启动: 每 {interval_hours} 小时执行一次。")
    while True:
        schedule.run_pending()
        time.sleep(60)


# ==================== Flask Webhook API ====================
app = Flask(__name__)
API_KEY = os.getenv('API_KEY', DEFAULT_API_KEY)


@app.route('/process', methods=['POST'])
def webhook_process():
    """Webhook 端点：处理订阅，返回新订阅 JSON"""
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
                uris, max_workers, 'sing-box', include_details, data.get('prefix', '')
            )
            
            response = {
                'new_sub_b64': new_sub_b64,
                'success_count': success_count,
                'total_nodes': total_nodes,
                'success_rate': round((success_count / total_nodes * 100), 2) if total_nodes > 0 else 0
            }
            
            if include_details:
                response['results'] = results
            
            # 更新全局
            global_state.latest_new_sub_b64 = new_sub_b64
            global_state.latest_results = results
            
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
    """外部订阅端点：返回最新 new_sub_b64（纯 base64 或 JSON）"""
    if not global_state.latest_new_sub_b64:
        return jsonify({
            'error': 'No subscription data available yet. '
                    'Wait for first scheduled run or webhook call.'
        }), 404
    
    # 检查 Accept header
    accept_header = request.headers.get('Accept', '')
    if 'application/base64' in accept_header or 'text/plain' in accept_header:
        # 返回纯 base64（订阅客户端友好）
        return Response(global_state.latest_new_sub_b64, mimetype='text/plain')
    else:
        # 返回 JSON
        return global_state.latest_new_sub_b64


@app.route('/health', methods=['GET'])
def health_check():
    """健康检查端点"""
    return jsonify({
        'status': 'healthy',
        'latest_update': time.strftime('%Y-%m-%d %H:%M:%S')
    })


# ==================== 主函数 ====================
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="代理订阅节点定时测试与 Webhook")
    parser.add_argument(
        '--sub_urls',
        type=str,
        default='subs.txt',
        help="订阅链接，逗号分隔 或 文件路径（定时用）"
    )
    parser.add_argument(
        '--prefix',
        type=str,
        default='',
        help="节点名称前缀 (e.g., MyVPN-)"
    )
    parser.add_argument(
        '--interval_hours',
        type=int,
        default=1,
        help="定时间隔（小时）"
    )
    parser.add_argument(
        '--output_dir',
        type=str,
        default=OUTPUT_DIR,
        help="输出目录"
    )
    parser.add_argument(
        '--max_workers',
        type=int,
        default=4,
        help="并发线程数"
    )
    parser.add_argument(
        '--singbox_path',
        type=str,
        default='sing-box',
        help="Sing-box 二进制路径"
    )
    parser.add_argument(
        '--mode',
        choices=['webhook', 'cli'],
        default='webhook',
        help="运行模式: webhook (API + 定时) 或 cli (命令行测试)"
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help="Webhook 端口"
    )
    parser.add_argument(
        '--api_key',
        type=str,
        help="API Key"
    )
    
    args = parser.parse_args()
    
    if args.api_key:
        os.environ['API_KEY'] = args.api_key
    
    if args.mode == 'webhook':
        # 解析 sub_urls（定时用）
        if os.path.isfile(args.sub_urls):
            with open(args.sub_urls, 'r') as f:
                sub_urls_list = [line.strip() for line in f if line.strip()]
        else:
            sub_urls_list = [
                url.strip() for url in args.sub_urls.split(',') if url.strip()
            ]
        
        if not sub_urls_list:
            logging.error("无有效订阅链接")
            exit(1)
        
        # 启动后台定时线程
        scheduler_thread = threading.Thread(
            target=scheduled_job,
            args=(sub_urls_list, args.interval_hours, args.max_workers, args.singbox_path, args.prefix),
            daemon=True
        )
        scheduler_thread.start()
        
        logging.info(
            f"启动 Webhook API 于端口 {args.port} + 后台定时（订阅: {len(sub_urls_list)} 个）"
        )
        app.run(host='0.0.0.0', port=args.port, debug=False)
