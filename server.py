import os
import sys
import json
import tempfile
from http.server import HTTPServer, SimpleHTTPRequestHandler
from apk_analyzer.pipeline import APKAnalysisPipeline
from apk_analyzer.ingestion import APKIngestionError

class APKAnalyzerHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/analyze':
            try:
                content_type = self.headers.get('Content-Type', '')
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)

                if "boundary=" not in content_type:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"error": "Invalid Content-Type"}')
                    return

                boundary = content_type.split("boundary=")[-1].encode()
                parts = body.split(b"--" + boundary)

                file_data = None
                for part in parts:
                    if b'filename="' in part:
                        headers, file_data = part.split(b"\r\n\r\n", 1)
                        file_data = file_data.rsplit(b"\r\n", 1)[0]
                        break

                if not file_data:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"error": "No file uploaded"}')
                    return

                with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
                    tmp.write(file_data)
                    tmp_path = tmp.name

                try:
                    pipeline = APKAnalysisPipeline(tmp_path)
                    json_report = pipeline.run_json(indent=2)
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    self.wfile.write(json_report.encode('utf-8'))
                finally:
                    if os.path.exists(tmp_path):
                        try:
                            os.remove(tmp_path)
                        except OSError:
                            pass
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def run_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, APKAnalyzerHandler)
    print(f"[+] APK Analyzer Backend Server running at http://localhost:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[-] Server stopped.")

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port)
