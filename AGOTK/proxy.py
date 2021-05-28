import socketserver
import http.server
import urllib.request
PORT = 80


class MyProxy(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        url = 'https://' + self.headers['Host'] + self.path
        reqObj = urllib.request.Request(url, None, self.headers)
        request = urllib.request.urlopen(reqObj)
        self.send_response(request.status)
        for (header, val) in request.getheaders():
            self.send_header(header, val)
        self.end_headers()
        self.copyfile(request, self.wfile)
    def do_POST(self):
        url = 'https://' + self.headers['Host'] + self.path
        reqObj = urllib.request.Request(url, None, self.headers)
        request = urllib.request.urlopen(reqObj)
        self.send_response(request.status)
        for (header, val) in request.getheaders():
            self.send_header(header, val)
        self.end_headers()
        self.copyfile(request, self.wfile)

httpd = socketserver.ForkingTCPServer(('', PORT), MyProxy)
print("Now serving at " + str(PORT))
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    pass
print("Killing " + str(PORT))
httpd.server_close()
