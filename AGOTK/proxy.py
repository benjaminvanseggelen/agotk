import socketserver
import http.server
import requests
PORT: int = 80


class MyProxy(http.server.SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
        url = 'http://' + self.headers['Host'] + self.path
        req = requests.get(url, headers=self.headers)
        self.send_response_only(req.status_code)
        for header in req.headers:
            if header != 'Content-Encoding' and header != 'Content-Length':
                self.send_header(header, req.headers[header])
        self.end_headers()
        newData = req.text
        #remove https
        newData = newData.replace('https://', 'http://')
        print(newData)
        self.wfile.write(bytes(newData, 'utf-8'))

    def do_POST(self) -> None:
        url = 'https://' + self.headers['Host'] + self.path
        data = self.rfile.read(int(self.headers['Content-Length']))
        req = requests.post(url, data=data, headers=self.headers)
        self.send_response_only(req.status_code)
        for header in req.headers:
            #skip a few headers as we remove the encoding used
            if header != 'Content-Encoding' and header != 'Content-Length' and header != 'Transfer-Encoding':
                self.send_header(header, req.headers[header])
        self.end_headers()
        newData = req.text
        #remove https
        newData = newData.replace('https://', 'http://')
        print(newData)
        self.wfile.write(bytes(newData, 'utf-8'))


httpd = socketserver.ForkingTCPServer(('', PORT), MyProxy)
print("Now serving at " + str(PORT))
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    pass
print("Killing " + str(PORT))
httpd.server_close()
