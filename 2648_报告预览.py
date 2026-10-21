"""仅提供两份公开演示报告，私有输入、密钥和映射库不会通过本服务提供。"""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

ROOT=Path(__file__).resolve().parent/'2648_演示数据'
ALLOWED={'/2648_演示总览.html':('2648_演示总览.html','text/html; charset=utf-8'),'/2648_演示核验.json':('2648_演示核验.json','application/json; charset=utf-8')}
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import unquote
        choice=ALLOWED.get(unquote(self.path))
        if choice is None:self.send_error(404);return
        path,mime=choice;payload=(ROOT/path).read_bytes()
        self.send_response(200);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
    def log_message(self,*args):pass
if __name__=='__main__':
    server=ThreadingHTTPServer(('127.0.0.1',8773),Handler)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()
