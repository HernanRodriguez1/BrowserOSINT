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
censys_api_key = "6c0ac3d8-f989-4bdd-b2ab-2def8134e527:YUq24v3C0ecNkjZfpbeEeG6PTX6WwZY0"
```

## Example

```sh
python3 BrowserOSINT.py --target www.target.com --Key xYtuQsB1IPNd3iEV7bSjVmHKUjPqPXpY
```
posdata: Use you Key Shodan.

![1](https://github.com/HernanRodriguez1/BrowserOSINT/assets/66162160/780760f3-c310-4825-9975-67861afa8dd2)

![2](https://github.com/HernanRodriguez1/BrowserOSINT/assets/66162160/0bd70380-05bf-48a4-9aff-ee498c994e51)

![3](https://github.com/HernanRodriguez1/BrowserOSINT/assets/66162160/058c419f-740d-44aa-b19c-4e29b9c81078)

![4](https://github.com/HernanRodriguez1/BrowserOSINT/assets/66162160/fe6f3018-8c81-4d60-a20b-8e698330fac7)
