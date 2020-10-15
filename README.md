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
usage: humble.py [-h] -d DOMAIN [-b] [-o {html,txt,pdf}] [-r] [-v]

humble (HTTP Headers Analyzer) - https://github.com/rfc-st/humble

required arguments:
  -d DOMAIN          domain to scan, including schema. E.g., https://google.com

optional arguments:
  -h, --help         show this help message and exit
  -b                 show brief analysis (no details/advices)
  -o {html,txt,pdf}  save analysis to file (domain_yyyymmdd)
  -r                 show retrieved HTTP headers
  -v, --version      show version
```

## Missing headers check
|||
| ------------- | ------------- |
| `Cache-Control`| `Clear-Site-Data` |
| `Content-Security-Policy` | `Expect-CT` |
| `Permissions-Policy` | `NEL` | 
| `Pragma` | `Referrer-Policy` |
| `Strict-Transport-Security` | `X-Content-Type-Options` |
| `X-Frame-Options` | `X-XSS-Protection` |
|||

## Fingerprint headers check
|||
| ------------- | ------------- |
| `MicrosoftOfficeWebServer` | `X-Drupal-Dynamic-Cache` | 
| `MicrosoftSharePointTeamServices` | `X-Generator` | 
| `MS-Author-Via` | `X-Mod-Pagespeed` | 
| `Powered-By` | `X-Nginx-Cache-Status` | 
| `Server` | `X-Page-Speed` | 
| `X-AspNet-Version` | `X-Powered-By` | 
| `X-AspNetMvc-Version` | `X-Powered-By-Plesk` | 
| `X-Backend` | `X-Powered-CMS` | 
| `X-Backend-Server` | `X-Redirect-By` | 
| `X-CF-Powered-By` | `X-Server-Powered-By` | 
| `X-Cocoon-Version` | `X-Shopify-Stage` |
| `X-FW-Server` | `X-Litespeed-Cache` |
| `X-Server` | `X-Litespeed-Cache-Control` |   
| `X-Content-Powered-By`| `X-LiteSpeed-Purge` | 
| `X-Drupal-Cache` | `X-LiteSpeed-Tag` |
| `X-LiteSpeed-Vary` | `Via` |
|||

## Insecure values check
|||
| ------------- | ------------- |
| `Access-Control-Allow-Origin` | `Cache-Control` |
| `Content-Security-Policy` | `Etag` |
| `Permissions-Policy` | `Referrer-Policy` |
| `Timing-Allow-Origin` | `X-Frame-Options` |
| `Set-Cookie` | `X-XSS-Protection` |
| `Strict-Transport-Security` | `X-Permitted-Cross-Domain-Policies` |
| `X-Content-Type-Options` | `X-Runtime` |
|||

## Empty values check
* Any response header

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
Original Creator - Rafa 'Bluesman' Faura
