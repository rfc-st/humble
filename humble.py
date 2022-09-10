#! /usr/bin/env python3

# humble (HTTP Headers Analyzer)
#
# MIT License
#
# Copyright (c) 2020-2022 Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)
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
# Keep improving i18n

# TO-DO:
# Add more checks (missing, fingerprint, insecure)
# Add analysis rating (*at the beginning of the output* .... tricky, tricky)
# Show the application related to each fingerprint header

# ADVICE:
# Use the information provided by this program *wisely*: there is far more
# merit in teaching, learning and helping others than in taking shortcuts to
# harm, attack or take advantage. Think about it!

from datetime import datetime
from fpdf import FPDF, HTMLMixin
from colorama import Fore, Style, init
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import os
import sys
import time
import platform
import requests
import tldextract

start = time.time()

if platform.system() == 'Windows':
    spacing = '\n'
else:
    spacing = '\r\n'

version = '\r\n' + "2022/09/10. Rafa 'Bluesman' Faura \
(rafael.fcucalon@gmail.com)" + '\r\n' + '\r\n'


class PDF(FPDF, HTMLMixin):

    # PDF Header & Footer

    def header(self):
        self.set_font('Courier', 'B', 10)
        self.set_y(15)
        self.cell(0, 5, get_detail('[pdf_t]'), new_x="CENTER",
                  new_y="NEXT", align='C')
        self.ln(1)
        self.cell(0, 5, "(https://github.com/rfc-st/humble)", align='C')
        if self.page_no() == 1:
            self.ln(9)
        else:
            self.ln(13)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, get_detail('[pdf_p]') + str(self.page_no()) +
                  ' of {nb}', align='C')


def pdf_metadata():
    title = (get_detail('[pdf_m]')).replace('\n', '') + URL
    git_url = "https://github.com/rfc-st/humble" + " (v." + \
              version.strip()[:10] + ")"
    pdf.set_author(git_url)
    pdf.set_creation_date = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
    pdf.set_creator(git_url)
    pdf.set_keywords(get_detail('[pdf_k]').replace('\n', ''))
    pdf.set_lang(get_detail('[pdf_l]'))
    pdf.set_subject(get_detail('[pdf_s]').replace('\n', ''))
    pdf.set_title(title)
    pdf.set_producer(git_url)


def pdf_sections():

    list_secpos = ['[0.', '[HTTP R', '[1.', '[2.', '[3.', '[4.', '[5.',
                   '[Cabeceras']
    list_sectxt = ['[0section_s]', '[0headers_s]', '[1missing_s]',
                   '[2fingerprint_s]', '[3depinsecure_s]', '[4empty_s]',
                   '[5compat_s]', '[0headers_s]']

    for index, element in enumerate(list_secpos):
        if x.startswith(element):
            pdf.start_section(get_detail(list_sectxt[index]))


def get_language():
    if args.language == 'es':
        details_file = 'details_es.txt'
    else:
        details_file = 'details.txt'
    return details_file


def analysis_time():
    print(".:")
    print("")
    seconds = end - start
    print_detail('[analysis_time]', 'l')
    print(str(round(seconds, 2)), end='')
    print_detail('[analysis_time_sec]', 'l')
    print("")
    analysis_detail()


def clean_output():

    # Kudos to Aniket Navlur!!!: https://stackoverflow.com/a/52590238

    sys.stdout.write('\x1b[1A')
    sys.stdout.write('\x1b[2K')
    sys.stdout.write('\x1b[1A')
    sys.stdout.write('\x1b[2K')
    sys.stdout.write('\x1b[1A')
    sys.stdout.write('\x1b[2K')


def print_path(filename):
    clean_output()
    print("")
    print_detail('[report]', 'l')
    print('"' + os.path.normcase(os.path.dirname(os.path.realpath(filename)) +
          '/' + filename + '"'))


def print_ok():
    print_detail('[ok]', 'a')


def print_header(header):
    if not args.output:
        print(Style.BRIGHT + Fore.RED + " " + header)
    else:
        print(" " + header)


def print_summary():
    now = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
    if not args.output:
        clean_output()
        print("")
        banner = '''  _                     _     _
 | |__  _   _ _ __ ___ | |__ | | ___
 | '_ \\| | | | '_ ` _ \\| '_ \\| |/ _ \\
 | | | | |_| | | | | | | |_) | |  __/
 |_| |_|\\__,_|_| |_| |_|_.__/|_|\\___|
'''
        print(banner)
        print(" (https://github.com/rfc-st/humble)")
    elif args.output != 'pdf':
        print(spacing)
        print(" Humble HTTP headers analyzer" + "\n" +
              " (https://github.com/rfc-st/humble)")
    print(spacing)
    print_detail('[0section]', 's')
    print_detail('[info]', 'l')
    print(" " + now)
    print(' URL  : ' + URL)


def print_headers():
    if args.retrieved:
        print("")
        print("")
        print_detail('[0headers]', 's')
        for key, value in sorted(headers.items()):
            if not args.output:
                print(" " + Fore.CYAN + key + ':', value)
            else:
                print(" " + key + ':', value)
    print('\n')


def print_detail(id, mode):
    details_file = get_language()
    with open(details_file) as rf:
        for line in rf:
            line = line.strip()
            if line.startswith(id):
                if mode == 'd':
                    print(next(rf), end='')
                    print(next(rf))
                elif mode == 'a':
                    print(next(rf), end='')
                    print("")
                elif mode == 'l':
                    print(next(rf).replace('\n', ''), end='')
                elif mode == 's':
                    if not args.output:
                        print(Style.BRIGHT + next(rf), end='')
                        print("")
                    else:
                        print(next(rf), end='')
                        print("")
                elif mode == 'm':
                    print(next(rf), end='')
                    print(next(rf), end='')
                    print(next(rf))


def get_detail(id):
    details_file = get_language()
    with open(details_file) as rf:
        for line in rf:
            line = line.strip()
            if line.startswith(id):
                detail_line = next(rf)
    return detail_line


def python_ver():
    if sys.version_info < (3, 6):
        print("")
        print_detail('[python]', 'd')
        sys.exit()


def print_guides():
    print("")
    print_detail('[guides]', 'a')
    with open('guides.txt', 'r') as gd:
        for line in gd:
            if line.startswith('['):
                print(Style.BRIGHT + line, end='')
            else:
                print(line, end='')


def get_location():
    response = requests.get(f'https://ipapi.co/country_name/')
    return response


def analysis_detail():
    print(" ")
    print_detail('[miss_cnt]', 'l')
    print(str(m_cnt))
    print_detail('[finger_cnt]', 'l')
    print(str(f_cnt))
    print_detail('[insecure_cnt]', 'l')
    print(str(i_cnt))
    print_detail('[empty_cnt]', 'l')
    print(str(e_cnt))
    print("")
    print(".:")
    print("")


def request_exceptions():
    try:
        r = requests.get(URL, timeout=6)
        r.raise_for_status()
    except (requests.exceptions.MissingSchema,
            requests.exceptions.InvalidSchema):
        clean_output()
        print("")
        print_detail('[e_schema]', 'l')
        raise SystemExit
    except requests.exceptions.InvalidURL:
        clean_output()
        print("")
        print_detail('[e_invalid]', 'l')
        raise SystemExit
    except requests.exceptions.HTTPError:
        httpcode = str(r.status_code)
        if r.status_code == 403:
            clean_output()
            print("")
            print_detail('[e_waf_gdpr]', 'l')
            raise SystemExit
        elif r.status_code == 407:
            clean_output()
            print("")
            print_detail('[e_proxy]', 'l')
            raise SystemExit
        elif str(r.status_code).startswith("5"):
            clean_output()
            print("")
            print_detail('[e_serror]', 'l')
            raise SystemExit

    # Can be useful with self-signed certificates, development environments ...

    except requests.exceptions.SSLError:
        pass
    except requests.exceptions.ConnectionError:
        clean_output()
        print("")
        print_detail('[e_404]', 'l')
        raise SystemExit
    except requests.exceptions.Timeout:
        clean_output()
        print("")
        print_detail('[e_timeout]', 'l')
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
optional.add_argument('-u', type=str, dest='URL', required=False,
                      help="URL to analyze, including schema. \
                      E.g., https://google.com")
optional.add_argument("-r", dest='retrieved', action="store_true",
                      required=False, help="show HTTP response headers and \
                          full analysis (with references and details)")
optional.add_argument("-b", dest='brief', action="store_true", required=False,
                      help="show brief analysis (without references or \
                          details)")
optional.add_argument("-o", dest='output', choices=['html', 'pdf', 'txt'],
                      help="save analysis to file (URL_yyyymmdd.ext)")
optional.add_argument("-l", dest='language', choices=['es'],
                      help="Displays the analysis in the indicated language; \
                        if omitted, English will be used")
optional.add_argument("-g", dest='guides', action="store_true", required=False,
                      help="show guidelines on securing most used web servers/\
services")
optional.add_argument("-v", "--version", action='version',
                      version=version, help="show version")
parser._action_groups.append(optional)

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

URL = args.URL

python_ver()

# Show guides

if args.guides:
    print_guides()
    sys.exit()

# Peace
# https://github.com/rfc-st/humble/blob/master/CODE_OF_CONDUCT.md#update-20220326

suffix = tldextract.extract(URL).suffix
country = get_location()

if suffix[-2:] == "ru" or b'Russia' in country:
    print("")
    print_detail("[bcnt]", "d")
    sys.exit()
elif suffix[-2:] == "ua" or b'Ukraine' in country:
    print_detail('[analysis_ua]', 'a')
else:
    print("")
    print_detail('[analysis]', 'a')

# Regarding 'dh key too small' errors.
# https://stackoverflow.com/a/41041028

requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS \
        += ':HIGH:!DH:!aNULL'
except AttributeError:
    pass

# Exception handling

request_exceptions()

# Headers retrieval

c_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; \
 rv:100.0) Gecko/20100101 Firefox/100.0'}

# About suppression of warnings and non-verification of SSL certificates:
# could be useful with self-signed certificates, development environments ...

requests.packages.urllib3.disable_warnings()
r = requests.get(URL, verify=False, headers=c_headers, timeout=60)

headers = r.headers
infix = "_headers_"

# Save analysis to file

if args.output is not None:
    orig_stdout = sys.stdout
    name_s = tldextract.extract(URL)
    name_e = name_s.domain + infix + datetime.now().strftime("%Y%m%d")\
        + ".txt"
    if args.output == 'pdf' or args.output == 'html':
        name_e = name_s.domain + infix +\
         datetime.now().strftime("%Y%m%d") + "t.txt"
    f = open(name_e, 'w')
    sys.stdout = f

# Date and URL

print_summary()

# Retrieved headers

print_headers()

# Report - 1. Missing HTTP Security Headers

m_cnt = 0

print_detail('[1missing]', 's')

list_miss = ['Cache-Control', 'Clear-Site-Data', 'Content-Type',
             'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy',
             'Cross-Origin-Resource-Policy', 'Content-Security-Policy',
             'NEL', 'Permissions-Policy', 'Pragma', 'Referrer-Policy',
             'Strict-Transport-Security', 'X-Content-Type-Options']

list_detail = ['[mcache]', '[mcsd]', '[mctype]', '[mcoe]', '[mcop]', '[mcor]',
               '[mcsp]', '[mnel]', '[mpermission]', '[mpragma]', '[mreferrer]',
               '[msts]', '[mxcto]', '[mxfo]']

if any(elem.lower() in headers for elem in list_miss):
    for key in list_miss:
        if key not in headers:
            print_header(key)
            if not args.brief:
                idx_m = list_miss.index(key)
                print_detail(list_detail[idx_m], "d")
            m_cnt += 1

# 'frame-ancestors' directive obsoletes the 'X-Frame-Options' header
# https://www.w3.org/TR/CSP2/#frame-ancestors-and-frame-options

elif 'X-Frame-Options' not in headers:
    if 'Content-Security-Policy' in headers:
        if 'frame-ancestors' not in headers['Content-Security-Policy']:
            print_header('X-Frame-Options')
            if not args.brief:
                print_detail("[mxfo]", "d")
            m_cnt += 1

# Shame, shame on you!. Have you not enabled *any* security HTTP header?.

list_miss.append('X-Frame-Options')

if not any(elem.lower() in headers for elem in list_miss):
    for key in list_miss:
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

# Part of the content of the file 'fingerprint.txt' has been made possible
# thanks to Wappalyzer, under MIT license.
# https://github.com/wappalyzer/wappalyzer/tree/master/src/technologies
# https://github.com/wappalyzer/wappalyzer/blob/master/LICENSE

f_cnt = 0

print_detail('[2fingerprint]', 's')

if not args.brief:
    print_detail("[afgp]", "a")

with open('fingerprint.txt', 'r') as fn:
    list_fng = []
    for line in fn:
        list_fng.append(line.strip())

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

# Report - 3. Deprecated HTTP Headers/Protocols and Insecure values

i_cnt = 0

print_detail('[3depinsecure]', 's')

if not args.brief:
    print_detail("[aisc]", "a")

list_ins = ['Access-Control-Allow-Methods', 'Access-Control-Allow-Origin',
            'Allow', 'Etag', 'Feature-Policy', 'HTTP instead HTTPS',
            'Public-Key-Pins', 'Set-Cookie', 'Server-Timing',
            'Timing-Allow-Origin', 'X-Content-Security-Policy',
            'X-DNS-Prefetch-Control', 'X-Download-Options', 'X-Pad',
            'X-Permitted-Cross-Domain-Policies', 'X-Pingback', 'X-Runtime',
            'X-Webkit-CSP', 'X-XSS-Protection']

list_methods = ['PUT', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE', 'TRACK',
                'DELETE', 'DEBUG', 'PATCH', '*']

if 'Access-Control-Allow-Methods' in headers:
    if any(elem.lower() in headers["Access-Control-Allow-Methods"].lower() for
       elem in list_methods):
        print_header("Access-Control-Allow-Methods (Insecure Methods)")
        if not args.brief:
            methods_list = "".join(str(x) for x in
                                   headers["Access-Control-Allow-Methods"])
            match_method = [x for x in list_methods if x in methods_list]
            match_method_str = ','.join(match_method)
            print(" Make sure these enabled HTTP methods are needed: " +
                  match_method_str + ".")
            print_detail("[imethods]", "a")
        i_cnt += 1

if 'Access-Control-Allow-Origin' in headers:
    list_access = ['*', 'null']
    if any(elem.lower() in headers["Access-Control-Allow-Origin"].lower() for
       elem in list_access):
        if not ('.*' and '*.') in headers["Access-Control-Allow-Origin"]:
            print_header("Access-Control-Allow-Origin (Unsafe Values)")
            if not args.brief:
                print_detail("[iaccess]", "d")
            i_cnt += 1

if 'Allow' in headers:
    if any(elem.lower() in headers["Allow"].lower() for elem in list_methods):
        print_header("Allow (Insecure Methods)")
        if not args.brief:
            print(" Make sure these enabled HTTP methods are needed: '" +
                  headers["Allow"] + "'.")
            print_detail("[imethods]", "a")
        i_cnt += 1

if 'Cache-Control' in headers:
    list_cache = ['no-cache', 'no-store', 'must-revalidate']
    if not all(elem.lower() in headers["Cache-Control"].lower() for elem in
               list_cache):
        print_header("Cache-Control (Recommended Values)")
        if not args.brief:
            print_detail("[icache]", "d")
        i_cnt += 1

if 'Content-Security-Policy' in headers:

    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

    list_csp_directives = ['child-src', 'connect-src', 'default-src',
                           'font-src', 'frame-src', 'img-src', 'manifest-src',
                           'media-src', 'object-src', 'prefetch-src',
                           'script-src', 'script-src-elem', 'script-src-attr',
                           'style-src', 'style-src-elem', 'style-src-attr',
                           'worker-src', 'base-uri', 'sandbox', 'form-action',
                           'frame-ancestors', 'navigate-to', 'report-to',
                           'upgrade-insecure-requests', 'require-sri-for',
                           'require-trusted-types-for', 'trusted-types']
    list_csp_deprecated = ['block-all-mixed-content', 'plugin-types',
                           'referrer', 'report-uri']
    list_csp_insecure = ['unsafe-inline', 'unsafe-eval']
    list_csp_equal = ['nonce', 'sha', 'style-src-elem', 'report-uri',
                      'report-to']
    if any(elem.lower() in headers["Content-Security-Policy"].lower() for
       elem in list_csp_insecure):
        print_header("Content-Security-Policy (Unsafe Values)")
        if not args.brief:
            print_detail("[icsp]", "m")
        i_cnt += 1
    elif not any(elem.lower() in headers["Content-Security-Policy"].lower() for
                 elem in list_csp_directives):
        print_header("Content-Security-Policy (No Valid Directives)")
        if not args.brief:
            print_detail("[icsi]", "d")
        i_cnt += 1
    if any(elem.lower() in headers["Content-Security-Policy"].lower() for
           elem in list_csp_deprecated):
        print_header("Content-Security-Policy (Deprecated Directives)")
        if not args.brief:
            csp_list = "".join(str(x) for x in
                               headers["Content-Security-Policy"])
            match = [x for x in list_csp_deprecated if x in csp_list]
            match_str = ', '.join(match)
            print(" Avoid using deprecated directives: " + match_str + "." +
                  "\n Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/\
Headers/Content-Security-Policy")
            print("")
        i_cnt += 1
    if '=' in headers['Content-Security-Policy']:
        if not any(elem.lower() in headers["Content-Security-Policy"].lower()
                   for elem in list_csp_equal):
            print_header("Content-Security-Policy (Incorrect Values)")
            if not args.brief:
                print_detail("[icsn]", "d")
            i_cnt += 1
    if ('http:' in headers['Content-Security-Policy']) and \
            (URL[0:5] == 'https'):
        print_header("Content-Security-Policy (Insecure Schemes)")
        if not args.brief:
            print_detail("[icsh]", "m")
        i_cnt += 1

if 'Etag' in headers:
    print_header("Etag (Potentially Unsafe Header)")
    if not args.brief:
        print_detail("[ieta]", "d")
    i_cnt += 1

if 'Expect-CT' in headers:
    print_header("Expect-CT (Deprecated Header)")
    if not args.brief:
        print_detail("[iexct]", "d")
    i_cnt += 1

if 'Feature-Policy' in headers:
    print_header("Feature-Policy (Deprecated Header)")
    if not args.brief:
        print_detail("[iffea]", "d")
    i_cnt += 1

if URL[0:5] == 'http:':
    print_header("HTTP (URL Via Unsafe Scheme)")
    if not args.brief:
        print_detail("[ihttp]", "d")
    i_cnt += 1

if 'Permissions-Policy' in headers:

    # https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md
    # https://csplite.com/fp/

    list_per_features = ['accelerometer', 'ambient-light-sensor',
                         'autoplay', 'battery', 'browsing-topics', 'camera',
                         'clipboard-read', 'clipboard-write',
                         'conversion-measurement', 'cross-origin-isolated',
                         'display-capture', 'document-access',
                         'document-domain', 'document-write',
                         'encrypted-media', 'execution-while-not-rendered',
                         'execution-while-out-of-viewport',
                         'focus-without-user-activation',
                         'font-display-late-swap', 'fullscreen', 'gamepad',
                         'geolocation', 'gyroscope', 'hid', 'idle-detection',
                         'interest-cohort', 'layout-animations', 'lazyload',
                         'legacy-image-formats', 'loading-frame-default-eager',
                         'magnetometer', 'microphone', 'midi',
                         'navigation-override', 'oversized-images', 'payment',
                         'picture-in-picture', 'publickey-credentials-get',
                         'screen-wake-lock', 'serial', 'speaker',
                         'speaker-selection', 'sync-script', 'sync-xhr',
                         'trust-token-redemption', 'unoptimized-images',
                         'unoptimized-lossless-images',
                         'unoptimized-lossless-images-strict',
                         'unoptimized-lossy-images', 'unsized-media', 'usb',
                         'vertical-scroll', 'vibrate', 'wake-lock',
                         'web-share', 'window-placement',
                         'xr-spatial-tracking']
    if not any(elem.lower() in headers["Permissions-Policy"].lower() for
               elem in list_per_features):
        print_header("Permissions-Policy (No Valid Features)")
        if not args.brief:
            print_detail("[ifpoln]", "m")
        i_cnt += 1
    if '*' in headers['Permissions-Policy']:
        print_header("Permissions-Policy (Too Permissive Value)")
        if not args.brief:
            print_detail("[ifpol]", "d")
        i_cnt += 1
    if 'none' in headers['Permissions-Policy']:
        print_header("Permissions-Policy (Incorrect Value)")
        if not args.brief:
            print_detail("[ifpoli]", "d")
        i_cnt += 1

if 'Public-Key-Pins' in headers:
    print_header("Public-Key-Pins (Deprecated Header)")
    if not args.brief:
        print_detail("[ipkp]", "d")
    i_cnt += 1

if 'Referrer-Policy' in headers:
    list_ref = ['strict-origin', 'strict-origin-when-cross-origin',
                'no-referrer-when-downgrade', 'no-referrer']
    if not any(elem.lower() in headers["Referrer-Policy"].lower() for elem in
               list_ref):
        print_header("Referrer-Policy (Recommended Values)")
        if not args.brief:
            print_detail("[iref]", "m")
        i_cnt += 1
    if 'unsafe-url' in headers['Referrer-Policy']:
        print_header("Referrer-Policy (Unsafe Value)")
        if not args.brief:
            print_detail("[irefi]", "d")
        i_cnt += 1

if 'Server-Timing' in headers:
    print_header("Server-Timing (Potentially Unsafe Header)")
    if not args.brief:
        print_detail("[itim]", "d")
    i_cnt += 1

if 'Set-Cookie' in headers:
    list_cookie = ['secure', 'httponly']
    if not all(elem.lower() in headers["Set-Cookie"].lower() for elem in
       list_cookie):
        print_header("Set-Cookie (Insecure Attributes)")
        if not args.brief:
            print_detail("[iset]", "d")
        i_cnt += 1

if ('Strict-Transport-Security' in headers) and (URL[0:5] != 'http:'):
    list_sts = ['includeSubDomains', 'max-age']
    age = int(''.join([n for n in headers["Strict-Transport-Security"] if
              n.isdigit()]))
    if not all(elem.lower() in headers["Strict-Transport-Security"].lower() for
       elem in list_sts) or (age is None or age < 31536000):
        print_header("Strict-Transport-Security (Recommended Values)")
        if not args.brief:
            print_detail("[ists]", "m")
        i_cnt += 1
    if ',' in headers['Strict-Transport-Security']:
        print_header("Strict-Transport-Security (Duplicated Values)")
        if not args.brief:
            print_detail("[istsd]", "d")
        i_cnt += 1

if (URL[0:5] == 'http:') and ('Strict-Transport-Security' in headers):
    print_header("Strict-Transport-Security (Ignored Header)")
    if not args.brief:
        print_detail("[ihsts]", "d")
    i_cnt += 1

if 'Timing-Allow-Origin' in headers:
    if '*' in headers['Timing-Allow-Origin']:
        print_header("Timing-Allow-Origin (Potentially Unsafe Header)")
        if not args.brief:
            print_detail("[itao]", "d")
        i_cnt += 1

if (URL[0:5] == 'http:') and ('WWW-Authenticate' in headers) and\
   ('Basic' in headers['WWW-Authenticate']):
    print_header("WWW-Authenticate (Unsafe Value)")
    if not args.brief:
        print_detail("[ihbas]", "d")
    i_cnt += 1

if 'X-Content-Security-Policy' in headers:
    print_header("X-Content-Security-Policy (Deprecated Header)")
    if not args.brief:
        print_detail("[ixcsp]", "d")
    i_cnt += 1

if 'X-Content-Type-Options' in headers:
    if ',' in headers['X-Content-Type-Options']:
        print_header("X-Content-Type-Options (Duplicated Values)")
        if not args.brief:
            print_detail("[ictpd]", "d")
        i_cnt += 1
    elif 'nosniff' not in headers['X-Content-Type-Options']:
        print_header("X-Content-Type-Options (Incorrect Value)")
        if not args.brief:
            print_detail("[ictp]", "d")
        i_cnt += 1

if 'X-DNS-Prefetch-Control' in headers:
    if 'on' in headers['X-DNS-Prefetch-Control']:
        print_header("X-DNS-Prefetch-Control (Potentially Unsafe Header)")
        if not args.brief:
            print_detail("[ixdp]", "d")
        i_cnt += 1

if 'X-Download-Options' in headers:
    print_header("X-Download-Options (Deprecated Header)")
    if not args.brief:
        print_detail("[ixdow]", "m")
    i_cnt += 1

if 'X-Frame-Options' in headers:
    if ',' in headers['X-Frame-Options']:
        print_header("X-Frame-Options (Duplicated Values)")
        if not args.brief:
            print_detail("[ixfo]", "m")
        i_cnt += 1

if 'X-Pad' in headers:
    print_header("X-Pad (Deprecated Header)")
    if not args.brief:
        print_detail("[ixpad]", "d")
    i_cnt += 1

if 'X-Permitted-Cross-Domain-Policies' in headers:
    if 'all' in headers['X-Permitted-Cross-Domain-Policies']:
        print_header("X-Permitted-Cross-Domain-Policies (Unsafe Value)")
        if not args.brief:
            print_detail("[ixcd]", "m")
        i_cnt += 1

if 'X-Pingback' in headers:
    if 'xmlrpc.php' in headers['X-Pingback']:
        print_header("X-Pingback (Unsafe Value)")
        if not args.brief:
            print_detail("[ixpb]", "d")
        i_cnt += 1

if 'X-Robots-Tag' in headers:
    if 'all' in headers['X-Robots-Tag']:
        print_header("X-Robots-Tag (Unsafe Value)")
        if not args.brief:
            print_detail("[ixrob]", "m")
        i_cnt += 1

if 'X-Runtime' in headers:
    print_header("X-Runtime (Unsafe Value)")
    if not args.brief:
        print_detail("[ixrun]", "d")
        i_cnt += 1

if 'X-Webkit-CSP' in headers:
    print_header("X-Webkit-CSP (Deprecated Header)")
    if not args.brief:
        print_detail("[ixcsp]", "d")
    i_cnt += 1

if 'X-XSS-Protection' in headers:
    if '0' not in headers["X-XSS-Protection"]:
        print_header("X-XSS-Protection (Unsafe Value)")
        if not args.brief:
            print_detail("[ixxp]", "d")
        i_cnt += 1
    if ',' in headers['X-XSS-Protection']:
        print_header("X-XSS-Protection (Duplicated Values)")
        if not args.brief:
            print_detail("[ixxpd]", "d")
        i_cnt += 1

if args.brief and i_cnt != 0:
    print("")

if i_cnt == 0:
    print_ok()
    print("")

print("")

# Report - 4. Empty HTTP Response Headers Values

e_cnt = 0

print_detail('[4empty]', 's')

if not args.brief:
    print_detail("[aemp]", "a")

for key in sorted(headers):
    if not headers[key]:
        print_header(key)
        if not args.brief:
            print(" " + headers[key])
        e_cnt += 1

if args.brief and e_cnt != 0:
    print("")

if e_cnt == 0:
    print_ok()

print("")

# Report - 5. Browser Compatibility for Enabled HTTP Security Headers

# caniuse.com support data contributions under CC-BY-4.0 license
# https://github.com/Fyrd/caniuse/blob/main/LICENSE

print_detail('[5compat]', 's')

compat_site = "https://caniuse.com/?search="
csp_replace = "contentsecuritypolicy2"

list_sec = ['Cache-Control', 'Clear-Site-Data', 'Content-Type',
            'Content-Security-Policy', 'Cross-Origin-Embedder-Policy',
            'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy',
            'NEL', 'Permissions-Policy', 'Pragma', 'Referrer-Policy',
            'Strict-Transport-Security', 'X-Content-Type-Options',
            'X-Frame-Options']

if any(elem.lower() in headers for elem in list_sec):
    for key in list_sec:
        if key in headers:
            if not args.output:
                print(" " + Fore.CYAN + key + Fore.RESET + ": " +
                      compat_site +
                      key.replace("Content-Security-Policy", csp_replace))
            elif args.output != 'html':
                print(" " + key + ": " + compat_site +
                      key.replace("Content-Security-Policy", csp_replace))
            else:
                print("  " + key + ": " + compat_site +
                      key.replace("Content-Security-Policy", csp_replace))

if not any(elem.lower() in headers for elem in list_miss):
    if not args.output:
        print(Style.BRIGHT + Fore.RED + " No HTTP security headers are \
enabled.")
    else:
        print(" No HTTP security headers are enabled.")

print("")
print("")
end = time.time()
analysis_time()

# Export analysis

bold_strings = ("[0.", "HTTP R", "[1.", "[2.", "[3.", "[4.", "[5.",
                "[Cabeceras")

if args.output == 'txt':
    sys.stdout = orig_stdout
    print_path(name_e)
    f.close()
elif args.output == 'pdf':
    sys.stdout = orig_stdout
    f.close()
    pdf = PDF()
    pdf.alias_nb_pages()
    pdf_metadata()
    pdf.set_display_mode(zoom='real')
    pdf.add_page()

    # PDF Body

    pdf.set_font("Courier", size=9)
    f = open(name_e, "r")
    for x in f:
        if '[' in x:
            pdf_sections()
        if 'https://' in x and 'content-security' not in x:
            x = (str(pdf.write_html(x.replace(x[x.index("https://"):],
                 '<a href=' + x[x.index("https://"):] + '">' +
                 x[x.index("https://"):-1] + '</a>')))).replace('None', "")
        if any(s in x for s in bold_strings):
            pdf.set_font(style="B")
        else:
            pdf.set_font(style="")
        pdf.multi_cell(197, 2.6, txt=x, align='L')
    name_p = name_e[:-5] + ".pdf"
    pdf.output(name_p)
    print_path(name_p)
    f.close()
    os.remove(name_e)
elif args.output == 'html':
    sys.stdout = orig_stdout
    f.close()

    # HTML Template

    title = "HTTP headers analysis"
    header = '<!DOCTYPE HTML><html lang="en"><head><meta charset="utf-8"/>\
<title>' + title + '</title><style>pre {overflow-x: auto;\
white-space: pre-wrap;white-space: -moz-pre-wrap;\
white-space: -pre-wrap;white-space: -o-pre-wrap;\
word-wrap: break-word; font-size: medium;}\
a {color: blue; text-decoration: none;} .ok {color: green;}\
.header {color: #660033;} .ko {color: red;} </style></head>'
    body = '<body><pre>'
    footer = '</pre></body></html>'

    name_p = name_e[:-5] + ".html"

    list_miss.append('WWW-Authenticate')
    list_miss.append('X-Frame-Options')
    list_final = list_miss + list_fng + list_ins
    list_final.sort()

    with open(name_e, 'r') as input, open(name_p, 'w') as output:
        output.write(str(header))
        output.write(str(body))

        for line in input:

            # TO-DO: this is a mess ... simplify, use templates, etc
            # Adapt it for i18n

            if 'rfc-st' in line:
                output.write(line[:2] + '<a href="' + line[2:-2] + '">' +
                             line[2:] + '</a>')
            elif ' URL  : ' in line:
                output.write(line[:6] + '<a href="' + line[6:] + '">' +
                             line[6:] + '</a>')
            elif any(s in line for s in bold_strings):
                output.write('<strong>' + line + '</strong>')
            elif ' Nothing to ' in line or ' Nada que ' in line:
                output.write('<span class="ok">' + line + '</span>')
            elif ' No HTTP' in line:
                output.write('<span class="ko">' + line + '</span>')
            elif ' Ref: ' in line:
                output.write(line[:6] + '<a href="' + line[6:] + '">' +
                             line[6:] + '</a>')
            elif 'caniuse' in line:
                line = line[1:]
                line = line.replace(line[0: line.index(": ")],
                                    '<span class="header">' +
                                    line[0: line.index(": ")] + '</span>')
                line = line.replace(line[line.index("https"):],
                                    '''<a href="''' +
                                    line[line.index("https"):] + '''">''' +
                                    line[line.index("https"):] + '</a>')
                output.write(line)
            else:
                for i in list(headers):
                    if str(i + ": ") in line and 'Date:   ' not in line:
                        line = line.replace(line[0: line.index(":")],
                                            '<span class="header">' +
                                            line[0: line.index(":")] +
                                            '</span>')
                for i in list_final:
                    if i in line and ':' not in line and '"' not in line:
                        line = line.replace(line, '<span class="ko">' + line +
                                            '</span>')
                output.write(line)

        output.write(footer)

    print_path(name_p)
    os.remove(name_e)
