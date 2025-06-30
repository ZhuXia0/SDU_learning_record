@echo off
setlocal enabledelayedexpansion

echo 正在创建证书目录...
mkdir certs 2>nul
cd certs

echo 生成 CA 根证书...
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/OU=IT/CN=MyRootCA"

echo 生成服务器证书...
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/OU=Server/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

:: 创建临时扩展文件
echo subjectAltName=DNS:localhost,IP:127.0.0.1 > extfile.cnf

openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -extfile extfile.cnf

:: 删除临时文件
del extfile.cnf

echo 生成客户端证书...
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=MyOrg/OU=Client/CN=client1"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAserial ca.srl -out client.crt

echo 验证证书...
openssl verify -CAfile ca.crt server.crt
openssl verify -CAfile ca.crt client.crt

echo 生成PEM格式的证书链...
type server.crt ca.crt > server-chain.pem
type client.crt ca.crt > client-chain.pem

echo 证书生成完成!
dir

endlocal