# BrowserOSINT

This script allows to enumerate and extract data from HACKERTARGET,CRT.SH, SHODAN,IPCRIMINAL, ABUSEIPDB, CENSYS from the enumeration phase of subdomains, services and possible CVE vulnerabilities,compromised emails, everything is used passively.

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

![image](https://github.com/HernanRodriguez1/BrowserOSINT/assets/66162160/5c1a22cd-eeff-4908-8429-18edb0ff4d74)

![2](https://github.com/HernanRodriguez1/BrowserOSINT/assets/66162160/0bd70380-05bf-48a4-9aff-ee498c994e51)

![3](https://github.com/HernanRodriguez1/BrowserOSINT/assets/66162160/058c419f-740d-44aa-b19c-4e29b9c81078)

![4](https://github.com/HernanRodriguez1/BrowserOSINT/assets/66162160/fe6f3018-8c81-4d60-a20b-8e698330fac7)
