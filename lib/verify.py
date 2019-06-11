# coding=utf-8

import re
from lib.settings import PASS

apps = ["PHP", "Apache", "jQuery"]
port = ['Unknown:28017', 'ssh:22']
vuln = ['jsp', 'tomcat', 'java']


def verify(vuln, port, apps):
    if vuln[0] == 'True':
        return True
    vuln = list(map(lambda x: x.lower(), vuln))
    apps = list(map(lambda x: x.lower(), apps))
    for i in port:
        server, port = i.split(':')
        if (server in vuln) or (port in vuln):
            return True
    for _ in apps:
        if _ in vuln:
            return True
    return False


def Probe(ip, ports):
    result = []
    for i in ports:
        server, port = i.split(':')
        if (server == 'http') and not (server == 'http' and port == '443'):
            url = server + '://' + ip + ':' + port
            if ':80' in url:
                url = re.sub(r':80$', '', url)
            result.append(url)
    return result


def GetHosts(ip, USER):
    result = []
    for name in USER:
        for passwd in PASS:
            result.append('{}|{}|{}'.format(ip, name, passwd))
    return result