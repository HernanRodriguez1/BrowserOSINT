# coding=utf-8
import requests
import shodan
import argparse
import time
import json

parser = argparse.ArgumentParser(description="Script para obtener subdominios y información de Shodan")
parser.add_argument('--target', help='Nombre de dominio a analizar')
parser.add_argument('--Key', help='API key de Shodan')
args = parser.parse_args()

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
}

print ('\n'+"===================OBTENIENDO SUBDOMINIOS API HACKERTARGET================"+'\n')

target = args.target
domain = target
domain = domain.lstrip("www.") 
domain = domain.replace("www.", "")
request = requests.get('https://api.hackertarget.com/hostsearch/?q=' + domain, headers=headers)
response = request.text
print(response)

print ('\n'+"===================OBTENIENDO CRT.SH================"+'\n')


url = "https://crt.sh/?q={domain}&output=json".format(domain=domain)
resp = requests.get(url, headers=headers).text
resp = json.loads(resp)
result = []
for item in resp:
    subdomain = item['name_value']
    if domain in subdomain and not subdomain.startswith("*.{domain}"):
        if "*." not in subdomain:
            if subdomain not in result:
                result.append(subdomain)
                print(subdomain)
pass
#---------------------API SHODAN----------------------- 

print ('\n'+"Recopilación de información con shodan"+'\n')

try:
    Key = args.Key
    api = shodan.Shodan(Key)
    #Obteniendo la IP del servidor
    dnsResolve = ('https://api.shodan.io/dns/resolve?hostnames=') + target  + '&key=' + Key

    resolved = requests.get(dnsResolve)
    hostIP = resolved.json()[target]

    #Obteniendo Banner Grabbing
    host = api.host(hostIP)
    print ("===================INFORMACIÓN SHODAN================")
    print('''
[!] Direccion IP: {}
[!] Nombre Dominio: {}
[!] Ciudad: {}
[!] ISP: {}
[!] Organización: {}
[!] Puertos: {}
[!] Sistema Operativo: {}
    '''.format(host['ip_str'], host['hostnames'], host['city'],host['isp'],host['org'],host['ports'],host['os']))

except:
        print ("Error de API")
try:

    for item in host['data']:
        print ("Port: %s" % item['port'])
        print ("Banner: %s" % item['data'])


    for item in host['vulns']:
        CVE = item.replace('!','')
        print ('[+] VULNERABILIDAD: %s' % item)
        exploits = api.exploits.search(CVE)
        for item in exploits['matches']:
            if item.get('cve')[0] == CVE:
                print (item.get("description"))
except:
        print ('No se encontraron vulnerabilidades en SHODAN')


print ('\n'+"==================== INFORMACIÓN VULNERABILIDADES CRIMINALIP==============="+'\n')

payload={}
headers = {
  "x-api-key": ""     #Añadir API
}

url2 = "https://api.criminalip.io/v1/ip/data?ip="+ (host['ip_str']) +"&full=true"
response2 = requests.request("GET", url2, headers=headers, data=payload)
data2 = json.loads(response2.text)

root = {}
root["vulnerability"] = {}
root["vulnerability"]["count"] = data2["vulnerability"]["count"]
root["vulnerability"]["data"] = []

for item in data2["vulnerability"]["data"]:
    root["vulnerability"]["data"].append({"cve_id": item["cve_id"], "cvssv3_score": item["cvssv3_score"], "app_name": item["app_name"], "app_version": item["app_version"], "open_port_no": item["open_port_no"]  })

for item in root["vulnerability"]["data"]:
    print(json.dumps(item))

pass

print ('\n'+"===================OBTENIENDO REPUTACIÓN IP ABUSEIPDB================"+'\n')


url = "https://api.abuseipdb.com/api/v2/check"
params = {
    "ipAddress": (host['ip_str']),
    "maxAgeInDays": "90",
    "verbose": ""
}
headers = {
    "Key": "",     #Añadir API
    "Accept": "application/json"
}

response = requests.get(url, params=params, headers=headers)
print(response.json())

pass

print ('\n'+"===================OBTENIENDO CORREOS CORPORATIVOS COMPROMETIDOS================"+'\n')

domain = target
domain = domain.lstrip("www.") 
domain = domain.replace("www.", "")  


url = "https://api.proxynova.com/comb"
query = {"query": domain}

response = requests.get(url, params=query)

if response.status_code == 200:
    data = response.json()
    print(json.dumps(data, indent=4))
else:
    print("Error en la solicitud: ", response.status_code)
