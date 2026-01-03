# 使用官方 Python 3.12 作为基础镜像（slim 版）
FROM python:3.12-slim

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# 下载并安装 sing-box（支持 Hysteria2 的最新版本）
RUN wget https://github.com/SagerNet/sing-box/releases/download/v1.10.0/sing-box-1.10.0-linux-amd64.tar.gz \
    && tar -xzf sing-box-1.10.0-linux-amd64.tar.gz \
    && mv sing-box-1.10.0-linux-amd64/sing-box /usr/local/bin/ \
    && chmod +x /usr/local/bin/sing-box \
    && rm -rf sing-box-1.10.0-linux-amd64.tar.gz sing-box-1.10.0-linux-amd64

# 复制依赖文件和 Python 脚本
COPY proxy_test_exit_ip.py /app/

# 安装 Python 依赖
RUN pip install --no-cache-dir httpx[socks] schedule flask

# 创建输出目录
RUN mkdir -p /app/output

# 默认命令
CMD ["python", "proxy_test_exit_ip.py", "--help"]