import socket
from lib.verify import verify

vuln = ['docker', '2375']


def check(ip, ports, apps):
    socket.setdefaulttimeout(2)
    if verify(vuln, ports, apps):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, 2375))
            s.send("GET /containers/json HTTP/1.1\r\nHost: %s:%s\r\n\r\n" % (ip, 2375))
            recv = s.recv(1024)
            if "HTTP/1.1 200 OK" in recv and 'Docker' in recv and 'Api-Version' in recv:
                return '2375 Docker unauthorized success'
        except Exception as e:
            # return '2375 Docker  Failed'
            pass
