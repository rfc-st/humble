# humble

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/c51df2f848694537b544e67e4c373270)](https://app.codacy.com/gh/rfc-st/humble?utm_source=github.com&utm_medium=referral&utm_content=rfc-st/humble&utm_campaign=Badge_Grade_Settings)

<p align=center>
<a target="_blank" href="https://www.python.org/downloads/" title="Python version"><img src="https://img.shields.io/badge/python-%3E=_3.6-green.svg"></a>
<a target="_blank" href="LICENSE" title="License: MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
<a target="_blank" href="https://github.com/rfc-st/humble/releases" title="Latest Release"><img src="https://img.shields.io/github/v/release/rfc-st/humble?display_name=release&label=latest%20release"></a>
<a target="_blank" href="https://snyk.io/test/github/rfc-st/humble" title="Snyk Analysis"><img src="https://snyk.io/test/github/rfc-st/humble/badge.svg"></a>
<a target="_blank" href="https://www.codacy.com/gh/rfc-st/humble/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=rfc-st/humble&amp;utm_campaign=Badge_Grade" title="Codacy Analysis"><img src="https://app.codacy.com/project/badge/Grade/2a69fe20ad6a47c19f2d8f4fb05b1816"></a>
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
[Deprecated Headers and Insecure Values Checks](#deprecated-headersprotocols-and-insecure-values-checks)<br />
[Empty Values Check](#empty-values-check)<br />
[Guidelines included](#guidelines-included-to-enable-security-http-headers)<br />
[To-Do](#to-do)<br />
[Further Reading](#further-reading)<br />
[Contribute](#contribute)<br />
[License](#license)<br />
<br />

## Features

:heavy_check_mark: 15 checks of missing HTTP response headers.<br />
:heavy_check_mark: 202 checks of fingerprinting through HTTP response headers.<br />
:heavy_check_mark: 38 checks of deprecated HTTP response headers/protocols or with values considered insecure.<br />
:heavy_check_mark: Browser compatibility check for enabled security headers.<br />
:heavy_check_mark: Two types of analysis: brief and complete, along with HTTP response headers.<br />
:heavy_check_mark: Export of analysis to html, pdf and txt.<br />
:heavy_check_mark: The analysis includes dozens of references, official documentation and technical articles.<br />
:heavy_check_mark: <a href="http://pep8online.com/" target="_blank">PEP8</a> compliant code.<br />
:heavy_check_mark: Tested, one by one, on hundreds of URLs.<br />
:heavy_check_mark: Fully working on Windows (10 20H2 - 19042.985) and Linux (Kali 2021.1).<br />
:heavy_check_mark: Permissive license (<a href="https://github.com/rfc-st/humble/blob/master/LICENSE" target="_blank">MIT<a>).<br />
:heavy_check_mark: Regularly <a href="https://github.com/rfc-st/humble/commits/master" target="_blank">updated</a>.<br />
:heavy_check_mark: Technical resource in the OWASP <a href="https://owasp.org/www-project-secure-headers/#div-technical" target="_blank">Secure Headers</a> Project.<br />
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
.: Analysis exported to PDF. <a href="https://github.com/rfc-st/humble/raw/master/samples/facebook_headers_20220617.pdf">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_pdf_s.PNG" alt="Export analysis to PDF" width=70% height=70%>
</p>
<br />
.: Analysis exported to HTML. <a href="https://htmlpreview.github.io/?https://github.com/rfc-st/humble/blob/master/samples/facebook_headers_20220618.html">Example.</a><br />
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
| `Cache-Control` | `Clear-Site-Data` | `Content-Type` |
| `Content-Security-Policy` | `Cross-Origin-Embedder-Policy` | `Cross-Origin-Opener-Policy` |
| `Cross-Origin-Resource-Policy` | `Expect-CT` | `NEL` |
| `Permissions-Policy` | `Pragma` | `Referrer-Policy` |
| `Strict-Transport-Security` | `X-Content-Type-Options` | `X-Frame-Options` |
||||

</details>

## Fingerprint headers check

Check <a href="https://github.com/rfc-st/humble/blob/master/fingerprint.txt">this</a> file.

## Deprecated headers/protocols and insecure values checks

Check <a href="https://github.com/rfc-st/humble/blob/master/insecure.txt">this</a> file.

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

- [ ] Add more header/value checks (only security-oriented)
- [ ] Add analysis rating
- [ ] Show the application related to each fingerprint header
- [ ] Improve PDF output through fpdf2 library

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
