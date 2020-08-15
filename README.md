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
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_b_22062025.jpg" alt="Brief Analysis">
<br />
.: Brief analysis + retrieved headers<br />
<p></p>
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_br_22062025.jpg" alt="Brief analysis + retrieved headers">
<br />
.: Full analysis<br />
<p></p>
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_22062025.jpg" alt="Full analysis">
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
* `Cache-Control`
* `Clear-Site-Data`
* `Content-Security-Policy`
* `Expect-CT`
* `Feature-Policy`
* `NEL`
* `Pragma`
* `Referrer-Policy`
* `Strict-Transport-Security`
* `X-Content-Type-Options`
* `X-Frame-Options`
* `X-XSS-Protection`

## Fingerprint headers check
* `MicrosoftOfficeWebServer`
* `MicrosoftSharePointTeamServices`
* `MS-Author-Via`
* `Powered-By`
* `Server`
* `X-AspNet-Version`
* `X-AspNetMvc-Version`
* `X-Backend`
* `X-CF-Powered-By`
* `X-Cocoon-Version`
* `X-Content-Powered-By`
* `X-Drupal-Cache`
* `X-Drupal-Dynamic-Cache`
* `X-Generator`
* `X-Mod-Pagespeed`
* `X-Nginx-Cache-Status`
* `X-Page-Speed`
* `X-Powered-By`
* `X-Powered-By-Plesk`
* `X-Powered-CMS`
* `X-Redirect-By`
* `X-Server-Powered-By`
* `X-Shopify-Stage`

## Insecure values check
* `Access-Control-Allow-Origin`
* `Cache-Control`
* `Content-Security-Policy`
* `Etag`
* `Feature-Policy`
* `Referrer-Policy`
* `Set-Cookie`
* `Strict-Transport-Security`
* `X-Content-Type-Options`
* `X-Frame-Options`
* `X-Permitted-Cross-Domain-Policies`
* `X-XSS-Protection`

## Empty values check
* `Cache-Control`
* `Clear-Site-Data`
* `Content-Security-Policy`
* `Expect-CT`
* `Feature-Policy`
* `NEL`
* `Pragma`
* `Referrer-Policy`
* `Strict-Transport-Security`
* `X-Content-Type-Options`
* `X-Frame-Options`
* `X-XSS-Protection`

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
