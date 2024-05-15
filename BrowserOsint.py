# coding=utf-8
import requests
import shodan
import argparse
import time
import json
import socket
import base64
import urllib.parse
from colorama import Fore, Style

print(Fore.RED + """\n
  ____                                   ___      _       _   
 | __ ) _ __ _____      _____  ___ _ __ / _ \ ___(_)_ __ | |_ 
 |  _ \| '__/ _ \ \ /\ / / __|/ _ \ '__| | | / __| | '_ \| __|
 | |_) | | | (_) \ V  V /\__ \  __/ |  | |_| \__ \ | | | | |_ 
 |____/|_|  \___/ \_/\_/ |___/\___|_|   \___/|___/_|_| |_|\__| 2.0
                                                              
Create By: Hernan Rodriguez | Team Offsec Peru \n""" + Style.RESET_ALL)

parser = argparse.ArgumentParser(description="Script para obtener subdominios y información de Shodan")
parser.add_argument('--target', help='Nombre de dominio a analizar')
parser.add_argument('--Key', help='API key de Shodan')
args = parser.parse_args()

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"
}

print(Fore.GREEN + '\n'+"===================OBTENIENDO SUBDOMINIOS API HACKERTARGET================"+'\n'+ Style.RESET_ALL)
target = args.target
domain = target
domain = domain.lstrip("www.") 
domain = domain.replace("www.", "")
request = requests.get('https://api.hackertarget.com/hostsearch/?q=' + domain, headers=headers)
response = request.text
print(response)

print(Fore.GREEN + '\n' + "===================OBTENIENDO CRT.SH================" + '\n'+ Style.RESET_ALL)

def resolve_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "Inactive"

url = f"https://crt.sh/?q={domain}&output=json"
headers = {"User-Agent": "Mozilla/5.0"}  

try:
    resp = requests.get(url, headers=headers).json()
    active_hosts = set()
    inactive_hosts = set()

    for item in resp:
        subdomain = item['name_value']
        if domain in subdomain and not subdomain.startswith(f"*.{domain}"):
            if "*." not in subdomain:
                try:
                    ip_address = resolve_ip(subdomain)
                    if ip_address != "Inactive":
                        active_hosts.add((subdomain, ip_address))
                    else:
                        inactive_hosts.add(subdomain)
                except Exception as e:
                    print(f"Error resolving {subdomain}: {e}")

    print(Fore.GREEN + "\n-----------Active Hosts-----------" + Style.RESET_ALL)
    for subdomain, ip_address in active_hosts:
        print(f"{subdomain} {ip_address}")

    print(Fore.RED + "\n-----------Inactive Hosts-----------" + Style.RESET_ALL)
    for subdomain in inactive_hosts:
        print(f"{subdomain}")

except requests.RequestException as e:
    print(f"Error making the request: {e}")
except json.JSONDecodeError as e:
    print(f"Error decoding JSON: {e}")

print(Fore.GREEN +'\n' + "===================OBTENIENDO SUBDOMINIOS CON CENSYS================" + '\n' + Style.RESET_ALL)

def resolve_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "Inactive"

censys_api_key = "6c0xxxd8-fxx9-4xxd-bxxb-xxxxxxx27:OxxxxxxxxxxxxxxxxxYH" #Añadir API
url2 = f"https://search.censys.io/api/v2/certificates/search?q=names={domain}"
headers3 = {
    "Authorization": f"Basic {base64.b64encode(censys_api_key.encode()).decode()}"
}

resp = requests.get(url2, headers=headers3)

if resp.status_code == 200:
    data = resp.json()
    result = []
    for hit in data.get("result", {}).get("hits", []):
        names = hit.get("names", [])
        for subdomain in names:
            if domain in subdomain and not subdomain.startswith(f"*.{domain}"):
                if "*." not in subdomain:
                    if subdomain not in result:
                        result.append(subdomain)
    active_hosts = []
    inactive_hosts = []

    for subdomain in result:
        ip_address = resolve_ip(subdomain)
        if ip_address == "Inactive":
            inactive_hosts.append((subdomain, ip_address))
        else:
            active_hosts.append((subdomain, ip_address))

    print(Fore.GREEN +"\n------------Active Hosts-----------" + Style.RESET_ALL)
    for host, ip in active_hosts:
        print(f"{host} {ip}")

    print(Fore.RED +"\n-----------Inactive Hosts-----------" + Style.RESET_ALL)
    for host, ip in inactive_hosts:
        print(f"{host} {ip}")
else:
    print(f"Failed to retrieve data from Censys API. Status code: {resp.status_code}")



print(Fore.GREEN +'\n' + "===================HISTORICO SUBDOMINIOS CON ZOOM EYES================" + '\n' + Style.RESET_ALL)

def resolve_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        return None  

api_url = f'https://api.zoomeye.hk/domain/search?q={domain}&type=1&page=1'
api_key = '' #Añadir API
headers = {'API-KEY': api_key, 'User-Agent': 'Mozilla/5.0'}

try:
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        status = data.get("status", None)
        total = data.get("total", 0)
        domain_list = data.get("list", [])
        
        active_hosts = []  
        inactive_hosts = []  

        for item in domain_list:
            name = item.get("name", "")
            ips = item.get("ip", [])
            print(name, ips)
            
            ip_address = resolve_ip(name)
            if ip_address is not None:
                active_hosts.append((name, ip_address))
            else:
                inactive_hosts.append(name)

        print(Fore.GREEN + "\n-----------Active Hosts-----------" + Style.RESET_ALL)
        for subdomain, ip_address in active_hosts:
            print(f"{subdomain} {ip_address}")

        print(Fore.RED + "\n-----------Inactive Hosts-----------" + Style.RESET_ALL)
        for subdomain in inactive_hosts:
            print(f"{subdomain}")
    else:
        print(f"Error en la solicitud: {response.status_code}")
except requests.RequestException as e:
    print(f"Error haciendo la solicitud: {e}")

print(Fore.GREEN +'\n'+"Recopilación de información con shodan"+'\n'+ Style.RESET_ALL)

try:
    Key = args.Key
    api = shodan.Shodan(Key)
    #Obteniendo la IP del servidor
    dnsResolve = ('https://api.shodan.io/dns/resolve?hostnames=') + target  + '&key=' + Key

    resolved = requests.get(dnsResolve)
    hostIP = resolved.json()[target]

    #Obteniendo Banner Grabbing
    host = api.host(hostIP)
    print(Fore.GREEN +"===================INFORMACIÓN SHODAN================"+ Style.RESET_ALL)
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


print(Fore.GREEN +'\n'+"==================== INFORMACIÓN VULNERABILIDADES CRIMINALIP==============="+'\n'+ Style.RESET_ALL)

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

print (Fore.GREEN +'\n'+"===================OBTENIENDO REPUTACIÓN IP ABUSEIPDB================"+'\n'+ Style.RESET_ALL)


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

print (Fore.GREEN +'\n'+"===================OBTENIENDO CORREOS CORPORATIVOS COMPROMETIDOS================"+'\n'+ Style.RESET_ALL)

domain = target
domain = domain.lstrip("www.") 
domain = domain.replace("www.", "")  
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
}

url = "https://api.proxynova.com/comb"
query = {"query": domain}

MAX_RETRIES = 3  
RETRY_DELAY = 5  

for _ in range(MAX_RETRIES):
    response = requests.get(url, params=query, headers=headers)

    if response.status_code == 200:
        data = response.json()
        print(json.dumps(data, indent=4))
        break 
    elif response.status_code == 429:
        print("Recibido el código 429 - Demasiadas solicitudes. Esperando y reintentando...")
        time.sleep(RETRY_DELAY)  # Esperar antes de reintentar
    else:
        print("Error en la solicitud:", response.status_code)
        break 
else:
    print("Se agotaron los reintentos. No se pudo obtener una respuesta exitosa.")
