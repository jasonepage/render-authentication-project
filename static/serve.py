import http.server
import socketserver

PORT = 8000

Handler = http.server.SimpleHTTPRequestHandler
httpd = socketserver.TCPServer(("", PORT), Handler)

print(f"Serving at http://localhost:{PORT}")
print("Note: WebAuthn requires HTTPS in production, but HTTP works on localhost for testing")
httpd.serve_forever() 
