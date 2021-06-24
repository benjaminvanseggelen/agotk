from threading import Thread
import http.server
import socketserver
import requests

PORT: int = 10000

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
        filteredheaders = {}
        for header in self.headers:
            headlow = header.lower()
            #skip a few headers as we remove the encoding used
            if headlow != 'connection' and headlow != 'accept-encoding' and headlow != 'upgrade-insecure-requests':
                filteredheaders[header] = self.headers[header]

        req = requests.get(url, headers=filteredheaders)
        self.send_response_only(req.status_code)
        isTextReq = False
        for header in req.headers:
            headlow = header.lower()
            if headlow == 'content-type' and 'text/' in req.headers[header]:
                isTextReq = True
            #skip a few headers as we remove the encoding used
            if headlow != 'content-encoding' and headlow != 'content-length' and headlow != 'transfer-encoding' and headlow != 'upgrade-insecure-requests' and headlow != 'connection':
                self.send_header(header, req.headers[header])
        self.end_headers()
        print(self.headers['Host'] + self.path)
        if isTextReq:
            print('IS TEXT')
            newData = req.text
            #remove https
            newData = newData.replace('https://', 'http://')
            self.wfile.write(bytes(newData, 'utf-8'))
        else:
            print('IS NOT TEXT')
            self.wfile.write(req.content)


    def do_POST(self) -> None:
        url = 'https://' + self.headers['Host'] + self.path
        data = None
        filteredheaders = {}
        for header in self.headers:
            headlow = header.lower()
            if headlow == 'content-length':
                data = self.rfile.read(int(self.headers[header]))
            #skip a few headers as we remove the encoding used
            if headlow != 'connection' and headlow != 'accept-encoding' and headlow != 'upgrade-insecure-requests':
                filteredheaders[header] = self.headers[header]

        req = requests.post(url, data=data, headers=filteredheaders)
        self.send_response_only(req.status_code)
        isTextReq = False
        for header in req.headers:
            headlow = header.lower()
            if headlow == 'content-type' and 'text/' in req.headers[header]:
                isTextReq = True
            #skip a few headers as we remove the encoding used
            if headlow != 'content-encoding' and headlow != 'content-length' and headlow != 'transfer-encoding' and headlow != 'upgrade-insecure-requests' and headlow != 'connection':
                self.send_header(header, req.headers[header])
        self.end_headers()
        print(self.headers['Host'] + self.path)
        if isTextReq:
            print('IS TEXT')
            newData = req.text
            #remove https
            newData = newData.replace('https://', 'http://')
            self.wfile.write(bytes(newData, 'utf-8'))
        else:
            print('IS NOT TEXT')
            self.wfile.write(req.content)
        print(data)
