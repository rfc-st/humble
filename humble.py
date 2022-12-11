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
# Recommended terminal width for best output: 152

# ADVICE:
# Use the information provided by this script *wisely*: there is far more
# merit in teaching, learning and helping others than in taking shortcuts to
# harm, attack or take advantage.
#
# Don't just be a 'script kiddie'. If you are interested in this world,
# research, learn, and become a Security analyst. Good luck!.

# GREETINGS (for the moments, and above all, for your wisdom!):
# María Antonia, Fernando, Joanna, Eduardo, Ana, Iván, Luis Joaquín,
# Juan Carlos, David, Carlos, Juán, Alejandro, Pablo, Íñigo, Naiara, Ricardo,
# Gabriel, Miguel Angel, David (x2), Sergio, Marta, Alba, Montse & Eloy.
#
# You know who you are!.

from fpdf import FPDF
from datetime import datetime
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

version = '\r\n' + "2022-12-11. Rafa 'Bluesman' Faura \
(rafael.fcucalon@gmail.com)" + '\r\n' + '\r\n'


class PDF(FPDF):

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
    print_detail_l('[analysis_time]')
    print(str(round(seconds, 2)), end='')
    print_detail_l('[analysis_time_sec]')
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
    print_detail_l('[report]')
    print('"' + os.path.normcase(os.path.dirname(os.path.realpath(filename)) +
          '/' + filename + '"'))


def print_ok():
    print_detail_a('[ok]')


def print_header(header):
    if not args.output:
        print(Style.BRIGHT + Fore.RED + " " + header)
    else:
        print(" " + header)


def print_header_fng(header):
    if not args.output:
        if '[' in header:
            print(Style.BRIGHT + Fore.RED + " " +
                  header.partition(' [')[0].strip() + Style.NORMAL +
                  Fore.RESET + " [" + header.partition(' [')[2].strip())
        else:
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
        print_detail_d('[humble]')
    print(spacing)
    print_detail_s('[0section]')
    print_detail_l('[info]')
    print(" " + now)
    print(' URL  : ' + URL)


def print_headers():
    if args.retrieved:
        print("")
        print("")
        print_detail_s('[0headers]')
        for key, value in sorted(headers.items()):
            if not args.output:
                print(" " + Fore.CYAN + key + ':', value)
            else:
                print(" " + key + ':', value)
    print('\n')


def print_detail_a(id_mode):
    with open(details_file, encoding='utf8') as rf:
        for line in rf:
            line = line.strip()
            if line.startswith(id_mode):
                print(next(rf), end='')
                print("")


def print_detail_d(id_mode):
    with open(details_file, encoding='utf8') as rf:
        for line in rf:
            line = line.strip()
            if line.startswith(id_mode):
                print(next(rf), end='')
                print(next(rf))


def print_detail_l(id_mode):
    with open(details_file, encoding='utf8') as rf:
        for line in rf:
            line = line.strip()
            if line.startswith(id_mode):
                print(next(rf).replace('\n', ''), end='')


def print_detail_m(id_mode):
    with open(details_file, encoding='utf8') as rf:
        for line in rf:
            line = line.strip()
            if line.startswith(id_mode):
                print(next(rf), end='')
                print(next(rf), end='')
                print(next(rf))


def print_detail_s(id_mode):
    with open(details_file, encoding='utf8') as rf:
        for line in rf:
            line = line.strip()
            if line.startswith(id_mode):
                if not args.output:
                    print(Style.BRIGHT + next(rf), end='')
                    print("")
                else:
                    print(next(rf), end='')
                    print("")


def print_detail_h(id_mode):
    with open(details_file, encoding='utf8') as rf:
        for line in rf:
            line = line.strip()
            if line.startswith(id_mode):
                if not args.output:
                    print(Style.BRIGHT + Fore.RED + next(rf), end='')
                else:
                    print(next(rf), end='')


def get_detail(id_mode):
    with open(details_file, encoding='utf8') as rf:
        for line in rf:
            line = line.strip()
            if line.startswith(id_mode):
                detail_line = next(rf)
    return detail_line


def python_ver():
    if sys.version_info < (3, 6):
        print("")
        print_detail_d('[python]')
        sys.exit()


def print_guides():
    print("")
    print_detail_a('[guides]')
    with open('guides.txt', 'r', encoding='utf8') as gd:
        for line in gd:
            if line.startswith('['):
                print(Style.BRIGHT + line, end='')
            else:
                print(line, end='')


def ongoing_analysis():
    suffix = tldextract.extract(URL).suffix
    country = requests.get(f'https://ipapi.co/country_name/')
    if suffix[-2:] == "ru" or b'Russia' in country:
        print("")
        print_detail_d("[bcnt]")
        sys.exit()
    elif suffix[-2:] == "ua" or b'Ukraine' in country:
        print("")
        if args.output:
            print_detail_a('[analysis_ua_output]')
        else:
            print_detail_a('[analysis_ua]')
    else:
        print("")
        if args.output:
            print_detail_a('[analysis_output]')
        else:
            print_detail_a('[analysis]')


def analysis_detail():
    print(" ")
    print_detail_l('[miss_cnt]')
    print(str(m_cnt))
    print_detail_l('[finger_cnt]')
    print(str(f_cnt))
    print_detail_l('[insecure_cnt]')
    print(str(i_cnt))
    print_detail_l('[empty_cnt]')
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
        print_detail_l('[e_schema]')
        raise SystemExit
    except requests.exceptions.InvalidURL:
        clean_output()
        print("")
        print_detail_l('[e_invalid]')
        raise SystemExit
    except requests.exceptions.HTTPError:
        if r.status_code == 407:
            clean_output()
            print("")
            print_detail_l('[e_proxy]')
            raise SystemExit
        elif str(r.status_code).startswith("5"):
            clean_output()
            print("")
            print_detail_l('[e_serror]')
            raise SystemExit

    # Can be useful with self-signed certificates, development environments ...

    except requests.exceptions.SSLError:
        pass
    except requests.exceptions.ConnectionError:
        clean_output()
        print("")
        print_detail_l('[e_404]')
        raise SystemExit
    except requests.exceptions.Timeout:
        clean_output()
        print("")
        print_detail_l('[e_timeout]')
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
                      help="URL to analyze, including schema. E.g., \
https://google.com")
optional.add_argument("-r", dest='retrieved', action="store_true",
                      required=False, help="show HTTP response headers and a \
detailed analysis.")
optional.add_argument("-b", dest='brief', action="store_true", required=False,
                      help="show a brief analysis; if omitted, a detailed \
analysis will be shown.")
optional.add_argument("-o", dest='output', choices=['html', 'pdf', 'txt'],
                      help="save analysis to file (URL_yyyymmdd.ext).")
optional.add_argument("-l", dest='language', choices=['es'],
                      help="Displays the analysis in the indicated language; \
if omitted, English will be used.")
optional.add_argument("-g", dest='guides', action="store_true", required=False,
                      help="show guidelines on securing most used web servers/\
services.")
optional.add_argument("-v", "--version", action='version',
                      version=version, help="show version")
parser._action_groups.append(optional)

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

URL = args.URL

details_file = get_language()

python_ver()

# Show guides

if args.guides:
    print_guides()
    sys.exit()

# Peace!
# https://github.com/rfc-st/humble/blob/master/CODE_OF_CONDUCT.md#update-20220326

ongoing_analysis()

# Regarding 'dh key too small' errors: https://stackoverflow.com/a/41041028

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

# Yes: Server certificates should be verified during SSL/TLS connections.
# Despite this, I think 'verify=False' would benefit analysis of URLs with
# self-signed certificates, associated with development environments, etc.

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
    f = open(name_e, 'w', encoding='utf8')
    sys.stdout = f

# Date and URL

print_summary()

# Retrieved headers

print_headers()

# Report - 1. Missing HTTP Security Headers

m_cnt = 0

print_detail_s('[1missing]')

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
                print_detail_d(list_detail[idx_m])
            m_cnt += 1

# 'frame-ancestors' directive obsoletes the 'X-Frame-Options' header
# https://www.w3.org/TR/CSP2/#frame-ancestors-and-frame-options

elif 'X-Frame-Options' not in headers and 'Content-Security-Policy' in headers:
    if 'frame-ancestors' not in headers['Content-Security-Policy']:
        print_header('X-Frame-Options')
        if not args.brief:
            print_detail_d("[mxfo]")
        m_cnt += 1

# Shame, shame on you!. Have you not enabled *any* security HTTP header?.

list_miss.append('X-Frame-Options')

if not any(elem.lower() in headers for elem in list_miss):
    for key in list_miss:
        print_header(key)
        if not args.brief:
            idx_m = list_miss.index(key)
            print_detail_d(list_detail[idx_m])
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

print_detail_s('[2fingerprint]')

if not args.brief:
    print_detail_a("[afgp]")

with open('fingerprint.txt', 'r', encoding='utf8') as fn:
    list_fng = []
    list_fng_ex = []
    for line in fn:
        list_fng.append(line.partition(' [')[0].strip())
        list_fng_ex.append(line.strip())

if any(elem.lower() in headers for elem in list_fng):
    for key in list_fng:
        if key in headers and headers[key]:
            index_fng = list_fng.index(key)
            if not args.brief:
                print_header_fng(list_fng_ex[index_fng])
                print(" " + headers[key])
                print("")
            else:
                print_header(key)
            f_cnt += 1

if args.brief and f_cnt != 0:
    print("")

if f_cnt == 0:
    print_ok()

print("")

# Report - 3. Deprecated HTTP Headers/Protocols and Insecure values

i_cnt = 0

print_detail_s('[3depinsecure]')

if not args.brief:
    print_detail_a("[aisc]")

list_access = ['*', 'null']

list_ins = ['Access-Control-Allow-Methods', 'Access-Control-Allow-Origin',
            'Allow', 'Content-Type', 'Etag', 'Expect-CT', 'Feature-Policy',
            'Onion-Location', 'Public-Key-Pins', 'Set-Cookie', 'Server-Timing',
            'Timing-Allow-Origin', 'X-Content-Security-Policy',
            'X-DNS-Prefetch-Control', 'X-Download-Options', 'X-Pad',
            'X-Permitted-Cross-Domain-Policies', 'X-Pingback', 'X-Runtime',
            'X-Webkit-CSP', 'X-XSS-Protection']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods

list_methods = ['PUT', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE', 'TRACK',
                'DELETE', 'DEBUG', 'PATCH', '*']

list_cache = ['no-cache', 'no-store', 'must-revalidate']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

list_csp_directives = ['base-uri', 'child-src', 'connect-src',
                       'default-src', 'font-src', 'form-action',
                       'frame-ancestors', 'frame-src', 'img-src',
                       'manifest-src', 'media-src', 'navigate-to',
                       'object-src', 'prefetch-src', 'report-to',
                       'require-trusted-types-for', 'sandbox', 'script-src',
                       'script-src-elem', 'script-src-attr', 'style-src',
                       'style-src-elem', 'style-src-attr', 'trusted-types',
                       'upgrade-insecure-requests', 'worker-src']

list_csp_deprecated = ['block-all-mixed-content', 'plugin-types', 'referrer',
                       'report-uri', 'require-sri-for']

list_csp_insecure = ['unsafe-eval', 'unsafe-inline']

list_csp_equal = ['nonce', 'sha', 'style-src-elem', 'report-to', 'report-uri']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types

list_legacy = ['application/javascript', 'application/ecmascript',
               'application/x-ecmascript', 'application/x-javascript',
               'text/ecmascript', 'text/javascript1.0',
               'text/javascript1.1', 'text/javascript1.2',
               'text/javascript1.3', 'text/javascript1.4',
               'text/javascript1.5', 'text/jscript', 'text/livescript',
               'text/x-ecmascript', 'text/x-javascript']

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
                     'trust-token-redemption', 'unload',
                     'unoptimized-images', 'unoptimized-lossless-images',
                     'unoptimized-lossless-images-strict',
                     'unoptimized-lossy-images', 'unsized-media', 'usb',
                     'vertical-scroll', 'vibrate', 'wake-lock', 'web-share',
                     'window-placement', 'xr-spatial-tracking']

list_ref = ['strict-origin', 'strict-origin-when-cross-origin',
            'no-referrer-when-downgrade', 'no-referrer']

list_sts = ['includeSubDomains', 'max-age']

list_cookie = ['secure', 'httponly']

# https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag
# https://www.bing.com/webmasters/help/which-robots-metatags-does-bing-support-5198d240

list_robots = ['all', 'indexifembedded', 'max-image-preview', 'max-snippet',
               'max-video-preview', 'noarchive', 'noodp', 'nofollow',
               'noimageindex', 'noindex', 'none', 'nositelinkssearchbox',
               'nosnippet', 'notranslate', 'noydir', 'unavailable_after']

insecure_s = 'http:'

if 'Accept-CH-Lifetime' in headers:
    print_detail_h('[ixacl_h]')
    if not args.brief:
        print_detail_d("[ixacld]")
    i_cnt += 1

if 'Access-Control-Allow-Methods' in headers and \
                                  any(elem.lower() in headers["Access-Control-\
Allow-Methods"].lower() for elem in list_methods):
    print_detail_h('[imethods_h]')
    if not args.brief:
        methods_list = "".join(str(x) for x in
                               headers["Access-Control-Allow-Methods"])
        match_method = [x for x in list_methods if x in methods_list]
        match_method_str = ', '.join(match_method)
        print_detail_l("[imethods_s]")
        print(match_method_str)
        print_detail_a("[imethods]")
    i_cnt += 1

if ('Access-Control-Allow-Origin' in headers) and (any(elem.lower()
                                                   in headers["Access-Control-\
Allow-Origin"].lower() for elem in list_access)) and (('.*' and '*.') not in
                                                      headers["Access-Control-\
Allow-Origin"]):
    print_detail_h('[iaccess_h]')
    if not args.brief:
        print_detail_d("[iaccess]")
    i_cnt += 1

if ('Allow' in headers) and (any(elem.lower() in headers["Allow"].lower() for
                             elem in list_methods)):
    print_detail_h('[imethods_hh]')
    if not args.brief:
        print_detail_l("[imethods_s]")
        print(headers["Allow"])
        print_detail_a("[imethods]")
    i_cnt += 1

if ('Cache-Control' in headers) and (not all(elem.lower() in
                                     headers["Cache-Control"].lower() for elem
                                     in list_cache)):
    print_detail_h('[icache_h]')
    if not args.brief:
        print_detail_d("[icache]")
    i_cnt += 1

if ('Clear-Site-Data' in headers) and (URL[0:5] == insecure_s):
    print_detail_h('[icsd_h]')
    if not args.brief:
        print_detail_d("[icsd]")
    i_cnt += 1

if 'Content-DPR' in headers:
    print_detail_h('[ixcdpr_h]')
    if not args.brief:
        print_detail_d("[ixcdprd]")
    i_cnt += 1

if 'Content-Security-Policy' in headers:
    if any(elem.lower() in headers["Content-Security-Policy"].lower() for
       elem in list_csp_insecure):
        print_detail_h('[icsp_h]')
        if not args.brief:
            print_detail_m("[icsp]")
        i_cnt += 1
    elif not any(elem.lower() in headers["Content-Security-Policy"].lower() for
                 elem in list_csp_directives):
        print_detail_h('[icsi_h]')
        if not args.brief:
            print_detail_d("[icsi]")
        i_cnt += 1
    if any(elem.lower() in headers["Content-Security-Policy"].lower() for
           elem in list_csp_deprecated):
        print_detail_h('[icsi_d]')
        if not args.brief:
            csp_list = "".join(str(x) for x in
                               headers["Content-Security-Policy"])
            match = [x for x in list_csp_deprecated if x in csp_list]
            match_str = ', '.join(match)
            print_detail_l("[icsi_d_s]")
            print(match_str)
            print_detail_a("[icsi_d_r]")
        i_cnt += 1
    if '=' in headers['Content-Security-Policy']:
        if not any(elem.lower() in headers["Content-Security-Policy"].lower()
                   for elem in list_csp_equal):
            print_detail_h('[icsn_h]')
            if not args.brief:
                print_detail_d("[icsn]")
            i_cnt += 1
    if (insecure_s in headers['Content-Security-Policy']) and \
            (URL[0:5] == 'https'):
        print_detail_h('[icsh_h]')
        if not args.brief:
            print_detail_d("[icsh]")
        i_cnt += 1
    if ' * ' in headers['Content-Security-Policy']:
        print_detail_h('[icsw_h]')
        if not args.brief:
            print_detail_d("[icsw]")
        i_cnt += 1

if ('Content-Type' in headers) and (any(elem.lower() in
                                    headers["Content-Type"].lower() for elem in
                                    list_legacy)):
    print_detail_h("[ictlg_h]")
    if not args.brief:
        print_detail_m("[ictlg]")
    i_cnt += 1

if 'Etag' in headers:
    print_detail_h('[ieta_h]')
    if not args.brief:
        print_detail_d("[ieta]")
    i_cnt += 1

if 'Expect-CT' in headers:
    print_detail_h('[iexct_h]')
    if not args.brief:
        print_detail_m("[iexct]")
    i_cnt += 1

if 'Feature-Policy' in headers:
    print_detail_h('[iffea_h]')
    if not args.brief:
        print_detail_d("[iffea]")
    i_cnt += 1

if URL[0:5] == insecure_s:
    print_detail_h('[ihttp_h]')
    if not args.brief:
        print_detail_d("[ihttp]")
    i_cnt += 1

if 'Large-Allocation' in headers:
    print_detail_h('[ixlalloc_h]')
    if not args.brief:
        print_detail_d("[ixallocd]")
    i_cnt += 1

if 'Permissions-Policy' in headers:
    if not any(elem.lower() in headers["Permissions-Policy"].lower() for
               elem in list_per_features):
        print_detail_h('[ifpoln_h]')
        if not args.brief:
            print_detail_m("[ifpoln]")
        i_cnt += 1
    if '*' in headers['Permissions-Policy']:
        print_detail_h('[ifpol_h]')
        if not args.brief:
            print_detail_d("[ifpol]")
        i_cnt += 1
    if 'none' in headers['Permissions-Policy']:
        print_detail_h('[ifpoli_h]')
        if not args.brief:
            print_detail_d("[ifpoli]")
        i_cnt += 1

if 'Onion-Location' in headers:
    print_detail_h('[ionloc_h]')
    if not args.brief:
        print_detail_m("[ionloc]")
    i_cnt += 1

if 'Public-Key-Pins' in headers:
    print_detail_h('[ipkp_h]')
    if not args.brief:
        print_detail_d("[ipkp]")
    i_cnt += 1

if 'Referrer-Policy' in headers:
    if not any(elem.lower() in headers["Referrer-Policy"].lower() for elem in
               list_ref):
        print_detail_h('[iref_h]')
        if not args.brief:
            print_detail_m("[iref]")
        i_cnt += 1
    if 'unsafe-url' in headers['Referrer-Policy']:
        print_detail_h('[irefi_h]')
        if not args.brief:
            print_detail_d("[irefi]")
        i_cnt += 1

if 'Server-Timing' in headers:
    print_detail_h('[itim_h]')
    if not args.brief:
        print_detail_d("[itim]")
    i_cnt += 1

if ('Set-Cookie' in headers) and (URL[0:5] != insecure_s) and \
                (not all(elem.lower() in headers["Set-Cookie"].lower()
                 for elem in list_cookie)):
    print_detail_h('[iset_h]')
    if not args.brief:
        print_detail_d("[iset]")
    i_cnt += 1

if ('Strict-Transport-Security' in headers) and (URL[0:5] != insecure_s):
    age = int(''.join([n for n in headers["Strict-Transport-Security"] if
              n.isdigit()]))
    if not all(elem.lower() in headers["Strict-Transport-Security"].lower() for
       elem in list_sts) or (age is None or age < 31536000):
        print_detail_h('[ists_h]')
        if not args.brief:
            print_detail_m("[ists]")
        i_cnt += 1
    if ',' in headers['Strict-Transport-Security']:
        print_detail_h('[istsd_h]')
        if not args.brief:
            print_detail_d("[istsd]")
        i_cnt += 1

if ('Strict-Transport-Security' in headers) and (URL[0:5] == insecure_s):
    print_detail_h('[ihsts_h]')
    if not args.brief:
        print_detail_d("[ihsts]")
    i_cnt += 1

if 'Timing-Allow-Origin' in headers and '*' in headers['Timing-Allow-Origin']:
    print_detail_h('[itao_h]')
    if not args.brief:
        print_detail_d("[itao]")
    i_cnt += 1

if 'Tk' in headers:
    print_detail_h('[ixtk_h]')
    if not args.brief:
        print_detail_d("[ixtkd]")
    i_cnt += 1

if 'Warning' in headers:
    print_detail_h('[ixwar_h]')
    if not args.brief:
        print_detail_d("[ixward]")
    i_cnt += 1

if ('WWW-Authenticate' in headers) and (URL[0:5] == insecure_s) and \
   ('Basic' in headers['WWW-Authenticate']):
    print_detail_h('[ihbas_h]')
    if not args.brief:
        print_detail_d("[ihbas]")
    i_cnt += 1

if 'X-Content-Security-Policy' in headers:
    print_detail_h('[ixcsp_h]')
    if not args.brief:
        print_detail_d("[ixcsp]")
    i_cnt += 1

if 'X-Content-Type-Options' in headers:
    if ',' in headers['X-Content-Type-Options']:
        print_detail_h('[ictpd_h]')
        if not args.brief:
            print_detail_d("[ictpd]")
        i_cnt += 1
    elif 'nosniff' not in headers['X-Content-Type-Options']:
        print_detail_h('[ictp_h]')
        if not args.brief:
            print_detail_d("[ictp]")
        i_cnt += 1

if ('X-DNS-Prefetch-Control' in headers) and \
   ('on' in headers['X-DNS-Prefetch-Control']):
    print_detail_h('[ixdp_h]')
    if not args.brief:
        print_detail_d("[ixdp]")
    i_cnt += 1

if 'X-Download-Options' in headers:
    print_detail_h('[ixdow_h]')
    if not args.brief:
        print_detail_m("[ixdow]")
    i_cnt += 1

if 'X-Frame-Options' in headers:
    if ',' in headers['X-Frame-Options']:
        print_detail_h('[ixfo_h]')
        if not args.brief:
            print_detail_m("[ixfo]")
        i_cnt += 1
    if 'allow-from' in headers['X-Frame-Options'].lower():
        print_detail_h('[ixfod_h]')
        if not args.brief:
            print_detail_m("[ixfod]")
        i_cnt += 1

if 'X-Pad' in headers:
    print_detail_h('[ixpad_h]')
    if not args.brief:
        print_detail_d("[ixpad]")
    i_cnt += 1

if ('X-Permitted-Cross-Domain-Policies' in headers) and \
   ('all' in headers['X-Permitted-Cross-Domain-Policies']):
    print_detail_h('[ixcd_h]')
    if not args.brief:
        print_detail_m("[ixcd]")
    i_cnt += 1

if 'X-Pingback' in headers and 'xmlrpc.php' in headers['X-Pingback']:
    print_detail_h('[ixpb_h]')
    if not args.brief:
        print_detail_d("[ixpb]")
    i_cnt += 1

if 'X-Robots-Tag' in headers:
    if 'all' in headers['X-Robots-Tag']:
        print_detail_h('[ixrob_h]')
        if not args.brief:
            print_detail_m("[ixrob]")
        i_cnt += 1
    elif not any(elem.lower() in headers["X-Robots-Tag"].lower() for
                 elem in list_robots):
        print_detail_h('[ixrobv_h]')
        if not args.brief:
            print_detail_m("[ixrobv]")
        i_cnt += 1

if 'X-Runtime' in headers:
    print_detail_h('[ixrun_h]')
    if not args.brief:
        print_detail_d("[ixrun]")
        i_cnt += 1

if 'X-Webkit-CSP' in headers:
    print_detail_h('[ixwcsp_h]')
    if not args.brief:
        print_detail_d("[ixcsp]")
    i_cnt += 1

if 'X-XSS-Protection' in headers:
    if '0' not in headers["X-XSS-Protection"]:
        print_detail_h('[ixxp_h]')
        if not args.brief:
            print_detail_d("[ixxp]")
        i_cnt += 1
    if ',' in headers['X-XSS-Protection']:
        print_detail_h('[ixxpd_h]')
        if not args.brief:
            print_detail_d("[ixxpd]")
        i_cnt += 1

if args.brief and i_cnt != 0:
    print("")

if i_cnt == 0:
    print_ok()

print("")

# Report - 4. Empty HTTP Response Headers Values

e_cnt = 0

print_detail_s('[4empty]')

if not args.brief:
    print_detail_a("[aemp]")

for key in sorted(headers):
    if not headers[key]:
        print_header(key)
        e_cnt += 1

if e_cnt != 0:
    print("")

if e_cnt == 0:
    print_ok()

print("")

# Report - 5. Browser Compatibility for Enabled HTTP Security Headers

# caniuse.com support data contributions under CC-BY-4.0 license
# https://github.com/Fyrd/caniuse/blob/main/LICENSE

print_detail_s('[5compat]')

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
                print(" " + Fore.CYAN + key + Fore.RESET + ": " + compat_site +
                      key.replace("Content-Security-Policy", csp_replace))
            elif args.output != 'html':
                print(" " + key + ": " + compat_site +
                      key.replace("Content-Security-Policy", csp_replace))
            else:
                print("  " + key + ": " + compat_site +
                      key.replace("Content-Security-Policy", csp_replace))

if not any(elem.lower() in headers for elem in list_miss):
    if not args.output:
        print_detail_h("[bcompat_n]")
    else:
        print_detail_l("[bcompat_n]")

print("")
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

    secure_s = "https://"

    pdf.set_font("Courier", size=9)
    f = open(name_e, "r", encoding='utf8')
    for x in f:
        if '[' in x:
            pdf_sections()

        # FIX NEEDED (it's driving me crazy, seriously ...)

        # The following code generates hyperlinks in the PDF (via '<a href=').
        # If two consecutive lines contain generated hyperlinks the PDF will
        # show the second line (and the following ones) without the
        # leading blank character of the first one.

        # Ex: https://postimg.cc/dL427tBQ

        #  Cache-Control: https://xxx               --> Proper
        # Content-Type: https://xxx                 --> Wrong
        # Content-Security-Policy: https://xxx      --> Wrong
        # Cross-Origin-Opener-Policy: https://xxx   --> Wrong

        # All lines in the above example should keep the leading blank
        # character (as in the first line).

        if 'https://' in x and 'content-security' not in x:
            x = (str(pdf.write_html('&nbsp;' + x.replace(x[x.index(secure_s):],
                 '<a href=' + x[x.index(secure_s):] + '">' +
                 x[x.index(secure_s):-1] + '</a>')))).replace('None', "")

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

    with open(name_e, 'r', encoding='utf8') as input_file,\
            open(name_p, 'w', encoding='utf8') as output:
        output.write(str(header))
        output.write(str(body))

        for line in input_file:

            # TO-DO: this is a mess ... simplify, use templates, i18n.

            ahref_s = '<a href="'
            span_s = '</span>'

            if 'rfc-st' in line:
                output.write(line[:2] + ahref_s + line[2:-2] + '">' +
                             line[2:] + '</a>')
            elif ' URL  : ' in line:
                output.write(line[:7] + ahref_s + line[7:] + '">' +
                             line[7:] + '</a>')
            elif any(s in line for s in bold_strings):
                output.write('<strong>' + line + '</strong>')
            elif get_detail('[ok]') in line:
                output.write('<span class="ok">' + line + span_s)
            elif get_detail('[bcompat_n]') in line:
                output.write('<span class="ko">' + line + span_s)
            elif ' Ref: ' in line:
                output.write(line[:6] + ahref_s + line[6:] + '">' +
                             line[6:] + '</a>')
            elif 'caniuse' in line:
                line = line[1:]
                line = line.replace(line[0: line.index(": ")],
                                    '<span class="header">' +
                                    line[0: line.index(": ")] + span_s)
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
                                            span_s)
                for i in list_final:
                    if i in line and ':' not in line and '"' not in line:
                        line = line.replace(line, '<span class="ko">' + line +
                                            span_s)
                output.write(line)

        output.write(footer)

    print_path(name_p)
    os.remove(name_e)
