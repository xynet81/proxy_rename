# 使用官方 Python 3.12 作为基础镜像（slim 版）
FROM python:3.12-slim

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# 下载并安装 Xray-core（最新版 v25.12.8）
RUN wget https://github.com/XTLS/Xray-core/releases/download/v25.12.8/Xray-linux-64.zip \
    && unzip Xray-linux-64.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/xray \
    && rm Xray-linux-64.zip

# 复制依赖文件和 Python 脚本
COPY proxy_test_exit_ip.py /app/

# 安装 Python 依赖
RUN pip install --no-cache-dir httpx[socks] schedule flask

# 创建输出目录
RUN mkdir -p /app/output

# 默认命令
CMD ["python", "proxy_test_exit_ip.py", "--help"]