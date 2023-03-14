# coding=utf-8
import requests
import shodan
import argparse
import time

parser = argparse.ArgumentParser(description="Script para obtener subdominios y información de Shodan")
parser.add_argument('--target', help='Nombre de dominio a analizar')
parser.add_argument('--Key', help='API key de Shodan')
args = parser.parse_args()

print ('\n'+"===================OBTENIENDO SUBDOMINIOS================"+'\n')

target = args.target
request = requests.get('https://api.hackertarget.com/hostsearch/?q='+target)
response = request.text
print(response)

#---------------------API SHODAN----------------------- 

print ('\n'+"Recopilación de información con shodan"+'\n')

try:
    Key = args.Key
    api = shodan.Shodan(Key)
    #Obteniendo la IP del servidor
    dnsResolve = ('https://api.shodan.io/dns/resolve?hostnames=') + target + '&key=' + Key

    resolved = requests.get(dnsResolve)
    hostIP = resolved.json()[target]

    #Obteniendo Banner Grabbing
    host = api.host(hostIP)
    print ("===================INFORMACIÓN SHODAN================")
    print('''
[!] Direccion IP: {}
[!] Ciudad: {}
[!] ISP: {}
[!] Organización: {}
[!] Puertos: {}
[!] Sistema Operativo: {}
    '''.format(host['ip_str'],host['city'],host['isp'],host['org'],host['ports'],host['os']))

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
