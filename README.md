# humble
HTTP Headers Analyzer

<p align=center>
<a target="_blank" href="https://www.python.org/downloads/" title="Python version"><img src="https://img.shields.io/badge/python-%3E=_3.2-green.svg"></a>
<a target="_blank" href="LICENSE" title="License: MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
</p>

![Imgur Image](https://imgur.com/JEkLfNJ.jpg)

![Imgur Image](https://imgur.com/tla5ZmV.jpg)

## Installation

**NOTE**: Python 3.2 or higher is required.

```bash
# clone the repo
$ git clone https://github.com/rfc-st/humble.git

# change the working directory to sherlock
$ cd humble

# install python3 and python3-pip if not exist

# install the requirements
$ pip3 install -r requirements.txt
```

## Usage

```bash
$ python3 humble.py --help
usage: humble.py [-h] -d DOMAIN [-b] [-r] [-v]

humble (HTTP Headers Analyzer) - https://github.com/rfc-st/humble

required arguments:
  -d DOMAIN      domain to scan, including schema. E.g., https://google.com

optional arguments:
  -h, --help     show this help message and exit
  -b             show brief analysis (no details/advices)
  -r             show retrieved HTTP headers
  -v, --version  show version
```

## Missing headers check
Cache-Control\
Content-Security-Policy\
Expect-CT\
Feature-Policy\
Pragma\
Referrer-Policy\
Strict-Transport-Security\
X-Content-Type-Options\
X-Frame-Options\
X-XSS-Protection

## Fingerprint headers check
Server\
X-AspNet-Version\
X-AspNetMvc-Version\
X-Generator\
X-Nginx-Cache-Status\
X-Powered-By\
X-Powered-By-Plesk\
X-Powered-CMS\
X-Drupal-Cache\
X-Drupal-Dynamic-Cache


## Insecure values check
Access-Control-Allow-Origin\
Cache-Control\
Content-Security-Policy\
Etag\
Referrer-Policy\
Set-Cookie\
Strict-Transport-Security\
X-XSS-Protection


## License

MIT © Rafa 'Bluesman' Faura<br/>
Original Creator - Rafa 'Bluesman' Faura
