"""Local preview only. Binds loopback and serves only the public dist directory."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PUBLIC = Path(__file__).resolve().parent / 'dist'

class Preview(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PUBLIC), **kwargs)

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        super().end_headers()

    def list_directory(self, path):
        self.send_error(404)
        return None

if __name__ == '__main__':
    print('TraceGuard preview: http://127.0.0.1:4173', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 4173), Preview).serve_forever()
