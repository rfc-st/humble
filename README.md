# humble

<p align=center>
<a target="_blank" href="https://www.python.org/downloads/" title="Python version"><img src="https://img.shields.io/badge/python-%3E=_3.6-green.svg"></a>
<a target="_blank" href="LICENSE" title="License: MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
<br />
<br />
HTTP Headers Analyzer<br />
<br />
<i>"A journey of a thousand miles begins with a single step. - Lao Tzu"</i>
<br />
<br />
<i>"And if you don't keep your feet, there's no knowing where you might be swept off to. - Bilbo Baggins"</i>
<br />
<br />

### Table of contents

[Features](#features)<br />
[Screenshots](#screenshots)<br />
[Installation & Update](#installation--update)<br />
[Usage](#usage)<br />
[Missing Headers Check](#missing-headers-check)<br />
[Fingerprint Headers Check](#fingerprint-headers-check)<br />
[Deprecated Headers and Insecure Values Checks](#deprecated-headers-and-insecure-values-checks)<br />
[Empty Values Check](#empty-values-check)<br />
[Guidelines included](#guidelines-included-to-enable-security-http-headers)<br />
[To-Do](#to-do)<br />
[Further Reading](#further-reading)<br />
[Contribute](#contribute)<br />
[License](#license)<br />
<br />

## Features

:heavy_check_mark: 14 checks of missing HTTP response headers.<br />
:heavy_check_mark: 108 checks of fingerprinting through HTTP response headers.<br />
:heavy_check_mark: 25 checks of deprecated HTTP response headers or with values considered insecure.<br />
:heavy_check_mark: Browser compatibility check for enabled security headers.<br />
:heavy_check_mark: Two types of analysis: brief and complete, along with HTTP response headers.<br />
:heavy_check_mark: Export of analysis to html, pdf and txt.<br />
:heavy_check_mark: <a href="http://pep8online.com/" target="_blank">PEP8</a> compliant code.<br />
:heavy_check_mark: Tested, one by one, on hundreds of URLs.<br />
:heavy_check_mark: Fully working on Windows (10 20H2 - 19042.985) and Linux (Kali 2021.1).<br />
:heavy_check_mark: Permissive license (<a href="https://github.com/rfc-st/humble/blob/master/LICENSE" target="_blank">MIT<a>).<br />
:heavy_check_mark: Regularly <a href="https://github.com/rfc-st/humble/commits/master" target="_blank">updated</a>.<br />
<br />

## Screenshots

.: Brief report (Windows)<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_b.PNG" alt="Brief Analysis">
</p>
<br />
.: Brief report and retrieved headers (Linux)<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_br.PNG" alt="Brief analysis + retrieved headers" width=70% height=70%>
</p>
<br />
.: Full report (Linux)<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble.PNG" alt="Full analysis" width=70% height=70%>
</p>
<br />
.: Analysis exported to PDF. <a href="https://github.com/rfc-st/humble/raw/master/samples/facebook_headers_20220220.pdf">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_pdf_s.PNG" alt="Export analysis to PDF" width=70% height=70%>
</p>
<br />
.: Analysis exported to HTML. <a href="https://htmlpreview.github.io/?https://github.com/rfc-st/humble/blob/master/samples/facebook_headers_20220220.html">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_html_s.PNG" alt="Export analysis to HTML" width=70% height=70%>
</p>
<br />

## Installation & Update

**NOTE**: Python 3.6 or higher is required.

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

# or download the latest release
https://github.com/rfc-st/humble/releases
```

## Usage

```bash
(Windows) $ py humble.py
(Linux)   $ python3 humble.py

usage: humble.py [-h] [-d DOMAIN] [-b] [-o {html,pdf,txt} [-r] [-g] [-v]

humble (HTTP Headers Analyzer) - https://github.com/rfc-st/humble

optional arguments:
  -h, --help         show this help message and exit
  -d DOMAIN          domain to analyze, including schema. E.g., https://google.com
  -r                 show HTTP response headers and full analysis (with references and details)
  -b                 show brief analysis (without references or details)
  -o {html,pdf,txt}  save analysis to file (domain_yyyymmdd.ext)
  -g                 show guidelines on securing most used web servers/services
```

## Missing headers check
<details>

<br />

<summary>Show / Hide</summary>

||||
| ------------- | ------------- | ------------- | 
| `Cache-Control` | `Clear-Site-Data` | `Content-Security-Policy` |
| `Cross-Origin-Embedder-Policy` | `Cross-Origin-Opener-Policy` | `Cross-Origin-Resource-Policy` |
| `Expect-CT` | `NEL` | `Permissions-Policy` |
| `Pragma` | `Referrer-Policy` | `Strict-Transport-Security` | 
| `X-Content-Type-Options` | `X-Frame-Options` | |
||||

</details>

## Fingerprint headers check
<details>

<br />

<summary>Show / Hide</summary>

||||
| ------------- | ------------- | ------------- |
| `Composed-By` | `Generator` | `Hummingbird-Cache` |
| `Liferay-Portal` | `MicrosoftOfficeWebServer` | `MicrosoftSharePointTeamServices` |
| `MS-Author-Via` | `Oracle-Mobile-Runtime-Version` | `Powered-By` |
| `Product` | `Server` | `Servlet-Engine` |
| `simplycom-server` | `SPIisLatency` | `SPRequestDuration` |
| `SPRequestGuid` | `swift-performance` | `Via` |
| `WPO-Cache-Status` | `WP-Super-Cache` | `X-Accel-Buffering` |
| `X-Accel-Redirect` | `X-Accel-Charset` | `X-Accel-Expires` |
| `X-Accel-Limit-Rate` | `X-AH-Environment` | `X-Application-Context` |
| `X-AspNet-Version` | `X-AspNetMvc-Version` | `X-Backend` |
| `X-Backend-Server` | `X-BEServer` | `X-Bitrix-Composite` |
| `X-Cache-Handler` | `X-Cache-Only-Varnish` | `X-Cache-Type` |
| `X-CF-Powered-By` | `X-CMS-Version` | `X-Cocoon-Version` |
| `X-Compressed-By` | `X-Content-Powered-By` | `X-Debug-Token` |
| `X-Debug-Token-Link` | `X-DevSrv-CMS` | `X-Drupal-Cache` |
| `X-Drupal-Cache-Contexts` | `X-Drupal-Cache-Tags` | `X-Drupal-Dynamic-Cache` |
| `X-FEServer` | `X-FW-Server` | `X-FW-Version` |
| `X-Garden-Version` | `X-Generated-By` | `X-Generator` |
| `X-Hudson` | `X-Jenkins` | `X-Jenkins-Session` |
| `X-Litespeed-Cache` | `X-Litespeed-Cache-Control` | `X-Magento-Cache-Control` |
| `X-Magento-Cache-Debug` | `X-LiteSpeed-Purge` | `X-LiteSpeed-Tag` |
| `X-LiteSpeed-Vary` | `X-Mod-Pagespeed` | `X-MS-InvokeApp` |
| `X-Nextjs-Cache | ``X-Nginx-Cache` | `X-Nginx-Cache-Status` |
| `X-Nginx-Upstream-Cache-Status` | `X-Nitro-Cache` | `X-Nitro-Cache-From` |
| `X-Nitro-Rev` | `X-ORACLE-DMS-ECID` | `X-ORACLE-DMS-RID` |
| `X-OWA-Version` | `X-Page-Speed` | `X-Powered-By` |
| `X-Powered-By-Plesk` | `X-Powered-CMS` | `X-Provided-By` |
| `X-Rack-Cache` | `X-Redirect-By` | `X-Redirect-Powered-By` |
| `X-Server` | `X-ServerName` | `X-Server-Name` |
| `X-Server-Powered-By` | `X-ShardId` | `X-SharePointHealthScore` |
| `X-ShopId` | `X-Shopify-Request-Trackable` | `X-Shopify-Stage` |
| `X-Sorting-Hat-PodId` | `X-Sorting-Hat-ShopId` | `X-Storefront-Renderer-Rendered` |
| `X-Storefront-Renderer-Verified` | `X-Spip-Cache` | `X-TEC-API-ORIGIN` |
| `X-TEC-API-ROOT` | `X-TEC-API-VERSION` | `X-Turbo-Charged-By` |
| `X-Using-Nginx-Controller` | `X-Varnish` | `X-Varnish-Cache` |
| `X-Varnish-CC` | `X-Version` | `X-Version-Id` |
||||

</details>

## Deprecated headers and insecure values checks
<details>

<br />

<summary>Show / Hide</summary>

||||
| ------------- | ------------- | ------------- |
| `Access-Control-Allow-Methods` | `Access-Control-Allow-Origin` | `Allow` |
| `Cache-Control` | `Content-Security-Policy` | `Etag` | 
| `Feature-Policy` | `HTTP instead HTTPS` | `Permissions-Policy` | 
| `Public-Key-Pins` | `Referrer-Policy` | `Server-Timing` | 
| `Set-Cookie` | `Strict-Transport-Security` | `Timing-Allow-Origin` | 
| `X-Content-Security-Policy` | `X-Content-Type-Options` | `X-DNS-Prefetch-Control` |
| `X-Frame-Options` | `X-Pad` | `X-Permitted-Cross-Domain-Policies` |
| `X-Pingback` | `X-Runtime` | `X-Webkit-CSP` | 
| `X-XSS-Protection` |||
||||

</details>

## Empty values check

Any HTTP response header.

## Guidelines included to enable security HTTP headers
* Amazon AWS
* Apache HTTP Server
* Cloudflare
* MaxCDN
* Microsoft Internet Information Services
* Nginx

## To-do

- [ ] Update screenshots
- [ ] Add more header/value checks (only security-oriented)
- [ ] Add analysis rating
- [ ] Show the application related to each fingerprint header 

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

## Contribute
* Report a <a href="https://github.com/rfc-st/humble/issues/new?assignees=&labels=&template=bug_report.md&title=">Bug</a>.
* Create a <a href="https://github.com/rfc-st/humble/issues/new?assignees=&labels=&template=feature_request.md&title=">Feature request</a>.
* Report a <a href="https://github.com/rfc-st/humble/security/policy">Security Vulnerability</a>.
* Drop me an email (rafael.fcucalon@gmail.com).

Thanks for your time!! :).

## License

MIT © 2020-2022 Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)<br/>
Original Creator - Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)
