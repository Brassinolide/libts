#!/bin/bash

# 更新版本时修改此变量
OSSL_SOURCE="openssl-3.4.1.tar.gz"
OSSL_DIR="${OSSL_SOURCE%.tar.gz}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p $SCRIPT_DIR/openssl/linux
OSSL_INSTALL_DIR=$SCRIPT_DIR/openssl/linux

if [ ! -f "$OSSL_SOURCE" ]; then
  echo "错误: 源文件 $OSSL_SOURCE 不存在."
  exit 1
fi

echo "开始解压 $OSSL_SOURCE..."
tar -xzf "$OSSL_SOURCE"
if [ $? -ne 0 ]; then
  echo "解压失败!"
  exit 1
fi
echo "解压完成."

cd "$OSSL_DIR" || { echo "进入目录 $OSSL_DIR 失败!"; exit 1; }

echo "开始配置..."
./config --prefix=$OSSL_INSTALL_DIR no-filenames no-shared no-apps no-autoload-config no-tests no-deprecated no-docs no-legacy no-sock no-srp no-srtp no-psk no-ui-console no-quic no-dgram no-http no-ssl no-ssl3 no-tls no-dtls no-engine no-comp no-ec no-ec2m no-dynamic-engine no-ocsp no-cms
if [ $? -ne 0 ]; then
  echo "配置失败!"
  exit 1
fi
echo "配置完成."

echo "开始编译..."
make
if [ $? -ne 0 ]; then
  echo "编译失败!"
  exit 1
fi
echo "编译完成."

echo "开始安装..."
sudo make install
if [ $? -ne 0 ]; then
  echo "安装失败!"
  exit 1
fi
echo "安装完成."

echo "OpenSSL 已成功安装到 $OSSL_INSTALL_DIR"

cd ..

make
