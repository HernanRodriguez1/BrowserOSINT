# BrowserOSINT

This script allows to enumerate and extract data from HACKERTARGET,CRT.SH, SHODAN,IPCRIMINAL, ABUSEIPDB, CENSYS, ZOOMEYE from the enumeration phase of subdomains, services and possible CVE vulnerabilities,compromised emails, everything is used passively.

## Add API:

```sh
https://api.criminalip.io/v1/ip/data?ip=
"x-api-key": ""
```

```sh
https://api.abuseipdb.com/api/v2/check
"Key": ""
```

```sh
https://search.censys.io/api/v2/certificates/search?q=names=
censys_api_key = ""
```

```sh
api_url = f'https://api.zoomeye.hk/domain/search?q={domain}&type=1&page=1'
api_key = ''
```

## Example

```sh
python3 BrowserOSINT.py --target www.target.com --Key xYtuQsB1IPNd3iEV7bSjVmHKUjPqPXpY
```
posdata: Use you Key Shodan.


https://github.com/HernanRodriguez1/BrowserOSINT/assets/66162160/8f15ad61-870d-43de-8ff5-c9c25d8c1d91
