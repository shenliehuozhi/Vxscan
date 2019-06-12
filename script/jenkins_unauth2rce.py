import requests
from lib.verify import get_hosts, get_list
from lib.random_header import HEADERS


def check(ip, ports, apps):
    try:
        payload = "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile"
        probe = get_list(ip, ports)
        for url in probe:
            r = requests.get(url + payload, timeout=5, headers=HEADERS)
            if 'java.lang.NullPointerException' in r.text:
                return "CVE-2018-1000861 Jenkins_unauth2rce"
    except Exception as e:
        print(e)
