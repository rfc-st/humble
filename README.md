# humble

<p align=center>
<a target="_blank" href="https://www.python.org/downloads/" title="Python version"><img src="https://img.shields.io/badge/python-%3E=_3.2-green.svg"></a>
<a target="_blank" href="LICENSE" title="License: MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
<br />
<br />
HTTP Headers Analyzer<br />
<br />
<i>"A journey of a thousand miles begins with a single step. - Lao Tzu"</i>
</p>
<br />
.: Brief analysis<br />
<p></p>
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_b_20200911.JPG" alt="Brief Analysis">
<br />
.: Brief analysis + retrieved headers<br />
<p></p>
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_br_20200911.JPG" alt="Brief analysis + retrieved headers">
<br />
.: Full analysis<br />
<p></p>
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_20200911.JPG" alt="Full analysis">
<br />

## Installation

**NOTE**: Python 3.2 or higher is required.

```bash
# clone the repo
$ git clone https://github.com/rfc-st/humble.git

# change the working directory to humble
$ cd humble

# install python3 and python3-pip if not exist

# install the requirements
$ pip3 install -r requirements.txt
```

## Usage

```bash
$ python3 humble.py
usage: humble.py [-h] [-d DOMAIN] [-b] [-o {html,pdf,txt}] [-r] [-g] [-v]

humble (HTTP Headers Analyzer) - https://github.com/rfc-st/humble

optional arguments:
  -h, --help         show this help message and exit
  -d DOMAIN          domain to scan, including schema. E.g., https://google.com
  -b                 show brief analysis (no details/advices)
  -o {html,pdf,txt}  save analysis to file (domain_yyyymmdd)
  -r                 show retrieved HTTP headers
  -g                 show guidelines on securing most used web servers
  -v, --version      show version
```

## Missing headers check
||||
| ------------- | ------------- | ------------- | 
| `Cache-Control` | `Pragma` | `Clear-Site-Data` | 
| `Referrer-Policy` | `Content-Security-Policy` | `Strict-Transport-Security` | 
| `Expect-CT` | `X-Content-Type-Options` | `NEL` | 
| `X-Frame-Options` | `Permissions-Policy` | `X-XSS-Protection` |
||||

## Fingerprint headers check
||||
| ------------- | ------------- | ------------- |
| `Liferay-Portal` | `MicrosoftOfficeWebServer` | `MicrosoftSharePointTeamServices` |
| `MS-Author-Via` | `Powered-By` | `Server` | 
| `Via` | `X-AspNet-Version` | `X-AspNetMvc-Version` | 
| `X-Backend` | `X-Backend-Server` | `X-BEServer` | 
| `X-Cache-Only-Varnish` | `X-CF-Powered-By` | `X-Cocoon-Version` | 
| `X-Content-Powered-By` | `X-Drupal-Cache` | `X-Drupal-Dynamic-Cache` | 
| `X-FEServer` | `X-FW-Server` | `X-Generator` | 
| `X-Litespeed-Cache` | `X-Litespeed-Cache-Control` | `X-LiteSpeed-Purge` |
| `X-LiteSpeed-Tag` | `X-LiteSpeed-Vary` | `X-Mod-Pagespeed` | 
| `X-Nginx-Cache-Status` | `X-OWA-Version` | `X-Page-Speed` | 
| `X-Powered-By` | `X-Powered-By-Plesk` |  `X-Powered-CMS` | 
| `X-Redirect-By` | `X-Server` | `X-Server-Powered-By` | 
| `X-Shopify-Stage` | `X-Turbo-Charged-By` | `X-Varnish` | 
| `X-Debug-Token` | `X-Debug-Token-Link` | `swift-performance` | 
| `Servlet-Engine` | | |
||||

## Insecure values check
||||
| ------------- | ------------- | ------------- |
| `Access-Control-Allow-Origin` | `Strict-Transport-Security` | `Cache-Control` | 
| `Timing-Allow-Origin` | `Content-Security-Policy` | `X-Content-Type-Options` |
| `Etag` | `X-Frame-Options` | `Permissions-Policy` | 
| `X-Permitted-Cross-Domain-Policies` | `Public-Key-Pins` | `X-Runtime` |
| `Referrer-Policy` | `X-XSS-Protection` | `Set-Cookie` |
||||

## Empty values check
* Any response header

## Guidelines included to enable security HTTP headers
* Amazon AWS
* Apache HTTP Server
* Cloudflare
* MaxCDN
* Microsoft Internet Information Services
* Nginx

## To-do

- [ ] Add more header/value checks (only security-oriented)
- [ ] Save analysis to more formats (ex.: PDF, HTML)

## Further reading

https://caniuse.com/<br />
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers<br />
https://github.com/search?q=http+headers+analyze<br />
https://github.com/search?q=http+headers+secure<br />
https://github.com/search?q=http+headers+security<br />
https://owasp.org/www-project-secure-headers/<br />
https://securityheaders.com/<br />
https://scotthelme.co.uk/<br />
https://webtechsurvey.com/common-response-headers<br />
https://www.w3.org<br />

## License

MIT © Rafa 'Bluesman' Faura<br/>
Original Creator - Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)
