from threading import Thread
import http.server
import socketserver
import requests

PORT: int = 80

class ProxyServer():
    def __init__(self) -> None:
        self.thread: Thread = Thread(target=self.run_proxy)
        self.httpd = socketserver.ForkingTCPServer(('', PORT), MyProxy)

    def start(self) -> None:
        #self.thread.daemon = True
        self.thread.start()

    def stop(self) -> None:
        self.is_stopped = True
        print("Killing " + str(PORT))
        self.httpd.server_close()
        self.httpd.shutdown()

    def run_proxy(self):
        print("Now serving at " + str(PORT))
        self.httpd.serve_forever()


class MyProxy(http.server.SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
        url = 'https://' + self.headers['Host'] + self.path
        req = requests.get(url, headers=self.headers)
        self.send_response_only(req.status_code)
        for header in req.headers:
            if header != 'Content-Encoding' and header != 'Content-Length' and header != 'Transfer-Encoding':
                print(header)
                print(req.headers[header])
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
        print(data)
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
