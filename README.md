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
.: Brief report (Windows)<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_b.PNG" alt="Brief Analysis">
</p>
<br />
.: Brief report and retrieved headers (Linux)<br />
<p></p>
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_br.PNG" alt="Brief analysis + retrieved headers">
<br />
.: Full report (Linux)<br />
<p></p>
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble.PNG" alt="Full analysis">
<br />
.: Export analysis to PDF (Windows)<br />
<p></p>
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_pdf.PNG" alt="Export analysis to PDF">
<br />

## Installation & Update

**NOTE**: Python 3.2 or higher is required.

```bash
# install python3 and python3-pip if not exist
(Windows) https://www.python.org/downloads/windows/
(Linux) if not installed by default, install them via, e.g. Synaptic, apt, dnf, yum ...

# install git
(Windows) https://git-scm.com/download/win
(Linux) https://git-scm.com/download/linux

# clone the repository
$ git clone https://github.com/rfc-st/humble.git

# change the working directory to humble
$ cd humble

# install the requirements
$ pip3 install -r requirements.txt

# update humble (every couple of weeks, inside humble's working directory)
$ git pull
```

## Usage

```bash
(Windows) $ py humble.py
(Linux)   $ python3 humble.py

usage: humble.py [-h] [-d DOMAIN] [-b] [-o {html,pdf,txt}] [-r] [-g] [-v]

humble (HTTP Headers Analyzer) - https://github.com/rfc-st/humble

optional arguments:
  -h, --help         show this help message and exit
  -d DOMAIN          domain to scan, including schema. E.g., https://google.com
  -b                 show brief report (no details/advices)
  -o {html,pdf,txt}  save report to file (domain_yyyymmdd)
  -r                 show retrieved HTTP headers
  -g                 show guidelines on securing most used web servers/services
  -v, --version      show version
```

## Missing headers check
<details>

<br />

<summary>Show / Hide</summary>

||||
| ------------- | ------------- | ------------- | 
| `Cache-Control` | `Pragma` | `Clear-Site-Data` | 
| `Cross-Origin-Embedder-Policy` | `Cross-Origin-Opener-Policy` | `Cross-Origin-Resource-Policy` |
| `Referrer-Policy` | `Content-Security-Policy` | `Strict-Transport-Security` | 
| `Expect-CT` | `X-Content-Type-Options` | `NEL` | 
| `X-Frame-Options` | `Permissions-Policy` | |
||||

</details>

## Fingerprint headers check
<details>

<br />

<summary>Show / Hide</summary>

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
| `Servlet-Engine` | `X-Nginx-Upstream-Cache-Status` | `X-Cache-Handler` |
| `X-DevSrv-CMS` | `X-FW-Version` | `X-Application-Context` | 
| `X-Version` | `X-Version-Id` | |
||||

</details>

## Insecure values check
<details>

<br />

<summary>Show / Hide</summary>

||||
| ------------- | ------------- | ------------- |
| `Access-Control-Allow-Origin` | `Strict-Transport-Security` | `Cache-Control` | 
| `Timing-Allow-Origin` | `Content-Security-Policy` | `X-Content-Type-Options` |
| `Etag` | `X-Frame-Options` | `Permissions-Policy` | 
| `X-Permitted-Cross-Domain-Policies` | `Public-Key-Pins` | `X-Runtime` |
| `Referrer-Policy` | `X-XSS-Protection` | `Set-Cookie` |
| `X-Pingback` | `X-DNS-Prefetch-Control` | `Server-Timing` |
| `HTTP instead HTTPS` | | |
||||

</details>

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
- [ ] Add analysis rating
- [ ] Save report to more formats (ex.: HTML)

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

MIT © 2020-2021 Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)<br/>
Original Creator - Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)
