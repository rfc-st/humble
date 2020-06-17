#! /usr/bin/env python3

# humble (HTTP Headers Analyzer)
#
# MIT License
#
# Copyright (c) 2020 Rafa 'Bluesman' Faura
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

# PEP8 compliant (http://pep8online.com/). Yay!
# Recommended terminal width for best output: 152

# TO-DO:
# Add more checks (missing, fingerprint, insecure)
# Ouput analysis to file (Ex. HTML with template)

from datetime import datetime
from colorama import Fore, Style, init
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import sys
import requests

if sys.version_info < (3, 2):
    print("\nError: this tool requires, at least, Python 3.2.\n")
    sys.exit()

version = "v.17/06/2020, by Rafa 'Bluesman' Faura"


def print_section(title):
    print(Style.BRIGHT + title)


def print_ok():
    print(Fore.GREEN + ' Nothing to report, all seems OK!')


def print_header(header):
    print(Fore.RED + " " + header)


def print_summary():
    print('\n')
    now = datetime.now().strftime("%d/%m/%Y - %H:%M:%S")
    print_section("[0. Info]\n")
    print(" Date:  ", now)
    print(' Domain: ' + domain)


def print_headers():
    if args.retrieved:
        print('\n')
        print_section("[HTTP Headers]\n")
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
        print("\nError: No schema supplied (e.g., http, https)\n")
        raise SystemExit
    except requests.exceptions.InvalidURL:
        print("\nError: '" + domain + "' is not a valid URL\n")
        raise SystemExit
    except requests.exceptions.HTTPError:
        if r.status_code == 401:
            print("\nError: Unauthorized access to '" + domain + "'.\n")
            raise SystemExit
        elif r.status_code == 403:
            print("\nError: Forbidden access to '" + domain + "'.\n")
            raise SystemExit
        elif r.status_code == 404:
            print("\nError: '" + domain + "' not found\n")
            raise SystemExit
        elif r.status_code == 407:
            print("\nError: Proxy required to acess'" + domain + "'\n")
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
required.add_argument('-d', type=str, dest='domain', required=True,
                      help="domain to scan, including schema. \
                      E.g., https://google.com")
optional.add_argument("-b", dest='brief', action="store_true", required=False,
                      help="show brief analysis (no details/advices)")
optional.add_argument("-r", dest='retrieved', action="store_true",
                      required=False, help="show retrieved HTTP headers")
optional.add_argument("-v", "--version", action='version',
                      version=version, help="show version")
parser._action_groups.append(optional)

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

domain = args.domain

# Exception handling

request_exceptions()

# Headers retrieval

r = requests.get(domain)
headers = r.headers

# Date and domain

print_summary()

# Retrieved headers

print_headers()

# Analysys - Missing headers

m_cnt = 0

print_section("[1. Missing headers]\n")

list_miss = ['Cache-Control', 'Content-Security-Policy', 'Expect-CT',
             'Feature-Policy', 'NEL', 'Pragma', 'Referrer-Policy',
             'Strict-Transport-Security', 'X-Content-Type-Options',
             'X-Frame-Options', 'X-XSS-Protection']

list_detail = ['[mcache]', '[mcsp]', '[mexpect]', '[mfeature]', '[mnel]',
               '[mpragma]', '[mreferrer]', '[msts]', '[mxcto]', '[mxfo]',
               '[mxxp]']

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

# Analysis - Fingerprinting through headers / values

f_cnt = 0

print_section("[2. Fingerprint headers]\n")

if not args.brief:
    print_detail("[afgp]", "a")

list_fng = ['Server', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator',
            'X-Nginx-Cache-Status', 'X-Powered-By', 'X-Powered-By-Plesk',
            'X-Powered-CMS', 'X-Drupal-Cache', 'X-Drupal-Dynamic-Cache']

if any(elem.lower() in headers for elem in list_fng):
    for key in list_fng:
        if key in headers:
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

# Analysis - Insecure values

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

if 'X-Content-Type-Options' in headers:
    list_xcto = [',']
    if any(elem.lower() in headers["X-Content-Type-Options"].lower() for
       elem in list_xcto):
        print_header("X-Content-Type-Options")
        if not args.brief:
            print(" The value '" + headers["X-Content-Type-Options"] + "' is \
invalid. Use only 'nosniff'.")
            print("")
        i_cnt += 1

if 'X-Frame-Options' in headers:
    list_xfo = [',']
    if any(elem.lower() in headers["X-Frame-Options"].lower() for
       elem in list_xfo):
        print_header("X-Frame-Options")
        if not args.brief:
            print(" The value '" + headers["X-Frame-Options"] + "' is \
invalid. Use only 'DENY' or 'SAMEORIGIN'.")
            print("")
        i_cnt += 1

if 'X-XSS-Protection' in headers and headers["X-XSS-Protection"] != \
                      '1; mode=block':
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
