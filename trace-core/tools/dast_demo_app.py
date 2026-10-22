"""Explicitly labelled local header-test fixture; contains no exploit endpoint."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class Demo(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path not in ('/missing','/secured'):
   self.send_error(404);return
  body=b'<!doctype html><title>TRACE local test fixture</title><h1>Local HTTP header test fixture</h1>'
  self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(body)))
  if self.path=='/secured':
   self.send_header('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'");self.send_header('X-Content-Type-Options','nosniff')
  self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
if __name__=='__main__':
 print('TRACE local test fixture on http://127.0.0.1:8878; Ctrl+C stops it',flush=True)
 ThreadingHTTPServer(('127.0.0.1',8878),Demo).serve_forever()
