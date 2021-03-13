#! /usr/bin/env python3

# humble (HTTP Headers Analyzer)
#
# MIT License
#
# Copyright (c) 2020-2021 Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# INFO:
# PEP8 compliant (http://pep8online.com/). Yay!
# Recommended terminal width for best output: 152
# This is my *first* Python script, bear with me!. I'm still learning :)

# TO-DO:
# Add more checks (missing, fingerprint, insecure)
# Add more output formats
# Add analysis rating (tricky ...)

from datetime import datetime
from colorama import Fore, Style, init
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import sys
import requests
import tldextract

if sys.version_info < (3, 2):
    print("\nError: this tool requires, at least, Python 3.2.\n")
    sys.exit()

version = '\r\n' + "2021/03/14, by Rafa 'Bluesman' Faura \
(rafael.fcucalon@gmail.com)" + '\r\n' + '\r\n'

guides = '\r\n' + 'Links that may be useful to secure servers/services and \
enable security HTTP headers (the author of this program bears no relation to \
them).' + '\r\n' + '\r\n' + Style.BRIGHT + '[Amazon AWS]' + Style.NORMAL + \
 '\r\n' + '\r\n' + 'https://medium.com/faun/hardening-the-http-security-\
headers-with-aws-lambda-edge-and-cloudfront-2e2da1ae4d83' + '\r\n' + '\r\n' + \
 Style.BRIGHT + '[Apache HTTP Server]' + Style.NORMAL + '\r\n' + '\r\n' + \
 'https://htaccessbook.com/important-security-headers/' + '\r\n' + 'https://\
geekflare.com/apache-web-server-hardening-security/' + '\r\n' + 'https://www\
.adminbyaccident.com/security/how-to-harden-apache-http/' + '\r\n' + \
 'https://www.digitalocean.com/community/tutorials/recommended-steps-to-\
harden-apache-http-on-freebsd-12-0' + '\r\n' + '\r\n' + Style.BRIGHT + \
 '[Cloudflare]' + '\r\n' + '\r\n' + Style.NORMAL + 'https://jarv.is/notes/\
security-headers-cloudflare-workers/' + '\r\n' + 'https://blog.headforcloud.\
com/2020/06/26/static-hosting-cf-workers/' + '\r\n' + '\r\n' + \
 Style.BRIGHT + '[MaxCDN]' + Style.NORMAL + '\r\n' + '\r\n' + 'https://\
support.maxcdn.com/hc/en-us/articles/360036557712-Edge-Rules-Recipes' + \
 '\r\n' + '\r\n' + Style.BRIGHT + '[Microsoft Internet Information \
Services]' + Style.NORMAL + '\r\n' + '\r\n' + 'https://geekflare.com/http-\
header-implementation/' + '\r\n' + 'https://www.ryadel.com/en/iis-web-config\
-secure-http-response-headers-pass-securityheaders-io-scan/' + '\r\n' + \
 'https://www.linkedin.com/pulse/hardening-your-http-response-headers-iis-\
server-omar-el-sergany' + '\r\n' + '\r\n' + Style.BRIGHT + \
 '[Nginx]' + Style.NORMAL + '\r\n' + '\r\n' + 'https://www.acunetix.com/\
blog/web-security-zone/hardening-nginx/' + '\r\n' + 'https://www.getpagespeed\
.com/server-setup/nginx-security-headers-the-right-way' + '\r\n'


def print_section(title):
    if not args.output:
        print(Style.BRIGHT + title)
    else:
        print(title)


def print_ok():
    if not args.output:
        print(Fore.GREEN + ' Nothing to report, all seems OK!')
    else:
        print(' Nothing to report, all seems OK!')


def print_header(header):
    if not args.output:
        print(Fore.RED + " " + header)
    else:
        print(" " + header)


def print_summary():
    now = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
    print_section('\r\n' + '\r\n' + "[0. Info]\n")
    print(" Date:  ", now)
    print(' Domain: ' + domain)


def print_headers():
    if args.retrieved:
        print_section('\r\n' + '\r\n' + "[HTTP Headers]\n")
        for key, value in sorted(headers.items()):
            print(" " + key + ':', value)
    print('\n')


def print_detail(id, mode):
    with open('details.txt') as rf:
        for line in rf:
            line = line.strip()
            if line.startswith(id):
                if mode == 'd':
                    print(next(rf), end='')
                    print(next(rf))
                elif mode == 'a':
                    print(next(rf))


def request_exceptions():
    try:
        r = requests.get(domain, timeout=6)
        r.raise_for_status()
    except requests.exceptions.MissingSchema:
        print("\nError: No schema supplied (e.g., https)\n")
        raise SystemExit
    except requests.exceptions.InvalidURL:
        print("\nError: '" + domain + "' is not a valid URL\n")
        raise SystemExit
    except requests.exceptions.HTTPError:
        if r.status_code == 401:
            print("\nError: Unauthorized access to '" + domain + "'.\n")
            raise SystemExit
        elif r.status_code == 404:
            print("\nError: '" + domain + "' not found\n")
            raise SystemExit
        elif r.status_code == 407:
            print("\nError: Proxy required to access'" + domain + "'\n")
            raise SystemExit
        elif str(r.status_code).startswith("5"):
            print("\nError: Server error requesting '" + domain + "' \n")
            raise SystemExit
    except requests.exceptions.ConnectionError:
        print("\nError: '" + domain + "' not found\n")
        raise SystemExit
    except requests.exceptions.Timeout:
        print("\nError: '" + domain + "' is taking too long to respond\n")
        raise SystemExit
    except requests.exceptions.RequestException as err:
        raise SystemExit(err)


# Arguments

init(autoreset=True)

parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
                        description="humble (HTTP Headers Analyzer) - \
https://github.com/rfc-st/humble")
optional = parser._action_groups.pop()
required = parser.add_argument_group('required arguments')
optional.add_argument('-d', type=str, dest='domain', required=False,
                      help="domain to scan, including schema. \
                      E.g., https://google.com")
optional.add_argument("-r", dest='retrieved', action="store_true",
                      required=False, help="show retrieved HTTP headers")
optional.add_argument("-b", dest='brief', action="store_true", required=False,
                      help="show brief report (no details/advices)")
optional.add_argument("-o", dest='output', choices=['html', 'pdf', 'txt'],
                      help="save report to file (domain_yyyymmdd)")
optional.add_argument("-g", dest='guides', action="store_true", required=False,
                      help="show guidelines on securing most used web servers/\
services")
optional.add_argument("-v", "--version", action='version',
                      version=version, help="show version")
parser._action_groups.append(optional)

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

domain = args.domain

# Show guides

if args.guides:
    print(guides)
    sys.exit()

# Exception handling

request_exceptions()

# Headers retrieval

c_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:\
82.0) Gecko/20100101 Firefox/82.0'}

r = requests.get(domain, headers=c_headers)
headers = r.headers

# Save report to file

if args.output is not None:
    if args.output == 'txt':
        orig_stdout = sys.stdout
        name_s = tldextract.extract(domain)
        name_e = name_s.domain + "_" + datetime.now().strftime("%Y%m%d") +\
            ".txt"
        f = open(name_e, 'w')
        sys.stdout = f
    else:
        print('\r\n' + 'Not implemented, yet! :)')
        raise SystemExit

# Date and domain

print_summary()

# Retrieved headers

print_headers()

# Report - 1. Missing headers

m_cnt = 0

print_section("[1. Missing headers]\n")

list_miss = ['Cache-Control', 'Clear-Site-Data',
             'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy',
             'Cross-Origin-Resource-Policy', 'Content-Security-Policy',
             'Expect-CT', 'NEL', 'Permissions-Policy', 'Pragma',
             'Referrer-Policy', 'Strict-Transport-Security',
             'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection']

list_detail = ['[mcache]', '[mcsd]', '[mcoe]', '[mcop]', '[mcor]', '[mcsp]',
               '[mexpect]', '[mnel]', '[mpermission]', '[mpragma]',
               '[mreferrer]', '[msts]', '[mxcto]', '[mxfo]', '[mxxp]']

if any(elem.lower() in headers for elem in list_miss):
    for key in list_miss:
        if key not in headers:
            print_header(key)
            if not args.brief:
                idx_m = list_miss.index(key)
                print_detail(list_detail[idx_m], "d")
            m_cnt += 1

if args.brief and m_cnt != 0:
    print("")

if m_cnt == 0:
    print_ok()

print("")

# Report - 2. Fingerprinting through headers / values

f_cnt = 0

print_section("[2. Fingerprint headers]\n")

if not args.brief:
    print_detail("[afgp]", "a")

list_fng = ['Liferay-Portal', 'MicrosoftOfficeWebServer',
            'MicrosoftSharePointTeamServices', 'MS-Author-Via', 'Powered-By',
            'Server', 'Via', 'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Backend', 'X-Backend-Server', 'X-BEServer',
            'X-Cache-Only-Varnish', 'X-CF-Powered-By', 'X-Cocoon-Version',
            'X-Content-Powered-By', 'X-Drupal-Cache', 'X-Drupal-Dynamic-Cache',
            'X-FEServer', 'X-FW-Server', 'X-Generator', 'X-Litespeed-Cache',
            'X-Litespeed-Cache-Control', 'X-LiteSpeed-Purge',
            'X-LiteSpeed-Tag', 'X-LiteSpeed-Vary', 'X-Mod-Pagespeed',
            'X-Nginx-Cache-Status', 'X-Nginx-Upstream-Cache-Status',
            'X-OWA-Version', 'X-Page-Speed', 'X-Powered-By',
            'X-Powered-By-Plesk', 'X-Powered-CMS', 'X-Redirect-By',
            'X-Server', 'X-Server-Powered-By', 'X-Shopify-Stage',
            'X-Turbo-Charged-By', 'X-Varnish', 'X-Debug-Token',
            'X-Debug-Token-Link', 'swift-performance', 'Servlet-Engine']

if any(elem.lower() in headers for elem in list_fng):
    for key in list_fng:
        if key in headers:
            if headers[key]:
                print_header(key)
                if not args.brief:
                    print(" " + headers[key])
                    print("")
                f_cnt += 1

if args.brief and f_cnt != 0:
    print("")

if f_cnt == 0:
    print_ok()
    print("")

print("")

# Report - 3. Insecure values

i_cnt = 0

print_section("[3. Insecure values]\n")
if not args.brief:
    print_detail("[aisc]", "a")

if 'Access-Control-Allow-Origin' in headers:
    list_access = ['*', 'null']
    if any(elem.lower() in headers["Access-Control-Allow-Origin"].lower() for
       elem in list_access):
        print_header("Access-Control-Allow-Origin")
    if not args.brief:
        print(" Review the value '" +
              headers["Access-Control-Allow-Origin"] + "' regarding your \
CORS (Cross-origin resource sharing) requirements.")
        print("")
    i_cnt += 1

if 'Cache-Control' in headers:
    list_cache = ['no-cache', 'no-store', 'must-revalidate']
    if not all(elem.lower() in headers["Cache-Control"].lower() for elem in
               list_cache):
        print_header("Cache-Control")
        if not args.brief:
            print_detail("[icache]", "a")
        i_cnt += 1

if 'Content-Security-Policy' in headers:
    list_csp = ['unsafe-inline', 'unsafe-eval']
    if any(elem.lower() in headers["Content-Security-Policy"].lower() for
       elem in list_csp):
        print_header("Content-Security-Policy")
        if not args.brief:
            print_detail("[icsp]", "a")
        i_cnt += 1

if 'Etag' in headers:
    print_header("Etag")
    if not args.brief:
        print(" Make sure the value " + headers["Etag"] + " does not include \
inodes information.")
        print("")
    i_cnt += 1

if 'Permissions-Policy' in headers:
    if '*' in headers['Permissions-Policy']:
        print_header("Permissions-Policy")
        if not args.brief:
            print_detail("[ifpol]", "a")
        i_cnt += 1

if 'Public-Key-Pins' in headers:
    print_header("Public-Key-Pins")
    if not args.brief:
        print_detail("[ipkp]", "d")
    i_cnt += 1

if 'Referrer-Policy' in headers:
    list_ref = ['strict-origin', 'strict-origin-when-cross-origin',
                'no-referrer-when-downgrade', 'no-referrer']
    if not any(elem.lower() in headers["Referrer-Policy"].lower() for elem in
               list_ref):
        print_header("Referrer-Policy")
        if not args.brief:
            print_detail("[iref]", "d")
        i_cnt += 1

if 'Set-Cookie' in headers:
    list_cookie = ['secure', 'httponly']
    if not all(elem.lower() in headers["Set-Cookie"].lower() for elem in
       list_cookie):
        print_header("Set-Cookie")
        if not args.brief:
            print_detail("[iset]", "a")
        i_cnt += 1

if 'Strict-Transport-Security' in headers:
    list_sts = ['includeSubDomains', 'max-age']
    age = int(''.join([n for n in headers["Strict-Transport-Security"] if
              n.isdigit()]))
    if not all(elem.lower() in headers["Strict-Transport-Security"].lower() for
       elem in list_sts) or (age is None or age < 31536000):
        print_header("Strict-Transport-Security")
        if not args.brief:
            print_detail("[ists]", "a")
        i_cnt += 1

if 'Timing-Allow-Origin' in headers:
    if '*' in headers['Timing-Allow-Origin']:
        print_header("Timing-Allow-Origin")
        if not args.brief:
            print_detail("[itao]", "a")
        i_cnt += 1

if 'X-Content-Type-Options' in headers:
    if ',' in headers['X-Content-Type-Options']:
        print_header("X-Content-Type-Options")
        if not args.brief:
            print(" The value '" + headers["X-Content-Type-Options"] + "' is \
invalid. Use only 'nosniff'.")
            print("")
        i_cnt += 1

if 'X-Frame-Options' in headers:
    if ',' in headers['X-Frame-Options']:
        print_header("X-Frame-Options")
        if not args.brief:
            print(" The value '" + headers["X-Frame-Options"] + "' is \
invalid. Use only 'DENY', 'SAMEORIGIN' or 'ALLOW-FROM'.\n Better yet: \
replace this header with the 'frame-ancestors' directive from the \
Content-Security-Policy header. ")
            print("")
        i_cnt += 1

if 'X-Permitted-Cross-Domain-Policies' in headers:
    if 'all' in headers['X-Permitted-Cross-Domain-Policies']:
        print_header("X-Permitted-Cross-Domain-Policies")
        if not args.brief:
            print_detail("[ixcd]", "a")
        i_cnt += 1

if 'X-Pingback' in headers:
    if 'xmlrpc.php' in headers['X-Pingback']:
        print_header("X-Pingback")
        if not args.brief:
            print_detail("[ixpb]", "d")
        i_cnt += 1

if 'X-Runtime' in headers:
    print_header("X-Runtime")
    if not args.brief:
        print(" The value '" + headers["X-Runtime"] + "' could allow valid \
user harvesting attacks (by providing the time it takes to process each \
request). ")
        print("")
        i_cnt += 1

if 'X-XSS-Protection' in headers:
    if not headers["X-XSS-Protection"].startswith('1; mode=block'):
        print_header("X-XSS-Protection")
        if not args.brief:
            print_detail("[ixxp]", "a")
        i_cnt += 1

if args.brief and i_cnt != 0:
    print("")

if i_cnt == 0:
    print_ok()
    print("")

print("")

# Report - 4. Empty values

e_cnt = 0

print_section("[4. Empty values]\n")
if not args.brief:
    print_detail("[aemp]", "a")

for key in headers:
    if not headers[key]:
        print_header(key)
        print("")
        e_cnt += 1

if e_cnt == 0:
    print_ok()
    print("")

print("")

if args.output == 'txt':
    sys.stdout = orig_stdout
    print('\r\n' + 'Analysis saved to "' + name_e + '"')
    f.close()
