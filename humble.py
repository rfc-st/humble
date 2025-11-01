#! /usr/bin/env python3

# 'humble' (HTTP Headers Analyzer)
# https://github.com/rfc-st/humble/
#
# MIT License
#
# Copyright (c) 2020-2025 Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)
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

# Notes on some Sourcery checks:
# https://marketplace.visualstudio.com/items?itemName=sourcery.sourcery
#
# To maintain compatibility with the minimum required Python version for
# 'humble' (especially regarding f-strings), and because some of Sourcery’s
# checks (in my opinion) offer little benefit, certain ones are explicitly
# ignored using inline comments.

# Advice:
# Use the information provided by 'humble' wisely. There is *far* more merit in
# helping others, learning and teaching than in attacking, harming or taking
# advantage. Do not just be a 'Script kiddie': if this really interests you
# learn, research and become a Security Analyst!.

# Greetings!:
# Alba, Aleix, Alejandro (x3), Álvaro, Ana, Carlos (x3), David (x3), Eduardo,
# Eloy, Fernando, Gabriel, Íñigo, Joanna, Juan Carlos, Juán, Julián, Julio,
# Iván, Lourdes, Luis Joaquín, María Antonia, Marta, Miguel, Miguel Angel,
# Montse, Naiara, Pablo, Sergio, Ricardo & Rubén!.

# Standard Library imports
import re
import ssl
import sys
import xml.etree.ElementTree as ET
from time import time
from json import dump, dumps
from shutil import copyfile
from platform import system
from base64 import b64decode
from itertools import islice
from datetime import datetime
from urllib.parse import urlparse
from subprocess import PIPE, Popen
from threading import Event, Thread
from os.path import dirname, abspath
from socket import create_connection
from csv import reader, writer, QUOTE_ALL
from collections import Counter, defaultdict
from os import access, linesep, path, remove, X_OK
from argparse import ArgumentParser, RawDescriptionHelpFormatter

# Third-Party imports
import requests
from colorama import Fore, Style, init
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict

BANNER = '''  _                     _     _
 | |__  _   _ _ __ ___ | |__ | | ___
 | '_ \\| | | | '_ ` _ \\| '_ \\| |/ _ \\
 | | | | |_| | | | | | | |_) | |  __/
 |_| |_|\\__,_|_| |_| |_|_.__/|_|\\___|
'''
BOLD_STRINGS = ('[0.', 'HTTP R', '[1.', '[2.', '[3.', '[4.', '[5.', '[6.',
                '[7.', '[Cabeceras')
CDN_HTTP_CODES = set(range(500, 512)) | set(range(520, 528)) | {530}
CSV_SECTION = ('0section', '0headers', '1enabled', '2missing', '3fingerprint',
               '4depinsecure', '5empty', '6compat', '7result')
DELETED_LINES = '\x1b[1A\x1b[2K\x1b[1A\x1b[2K\x1b[1A\x1b[2K'
DIR_MSG = ('[icsp_s]', '[icsp_si]', '[no_warnings]')
DTD_CONTENT = '''<!ELEMENT analysis (section+)>
<!ATTLIST analysis version CDATA #REQUIRED>
<!ATTLIST analysis generated CDATA #REQUIRED>
<!ELEMENT section (item*)>
<!ATTLIST section name CDATA #REQUIRED>
<!ELEMENT item (#PCDATA)>
<!ATTLIST item name CDATA #IMPLIED>
'''
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
EXP_HEADERS = ('activate-storage-access', 'critical-ch', 'document-policy',
               'nel', 'no-vary-search', 'observe-browsing-topics',
               'permissions-policy', 'speculation-rules',
               'supports-loading-mode')
FORCED_CIPHERS = ":".join(["HIGH", "!DH", "!aNULL"])
HASH_CHARS = {'sha256': 32, 'sha384': 48, 'sha512': 64}
HTML_TAGS = ('</a>', '<a href="', '">', '<span class="ko">',
             '<span class="header">', '</span>', '<span class="ok">',
             '</pre><div><details open><summary><strong>',
             '</strong></summary><pre>', 'class="ko"', '    class="ko"',
             '<br>', '</pre></details></div><pre>', '</pre><br></body></html>',
             '<strong>', '</strong>', '&nbsp;<font color="', '</font><br><br>',
             '</font>', '<font color="')
HTTP_SCHEMES = ('http:', 'https:')
HUMBLE_DESC = "'humble' (HTTP Headers Analyzer)"
HUMBLE_DIRS = ('additional', 'l10n')
HUMBLE_FILES = ('analysis_h.txt', 'check_path_permissions', 'fingerprint.txt',
                'guides.txt', 'details_es.txt', 'details.txt',
                'user_agents.txt', 'insecure.txt', 'html_template.html',
                'analysis_grades.txt', 'analysis_grades_es.txt', 'license.txt',
                'license_es.txt', 'testssl_windows.txt',
                'testssl_windows_es.txt', 'security_guides.txt',
                'security_guides_es.txt', 'security.txt',
                'owasp_best_practices.txt')
JSON_SECTION = ('0section', '0headers', '5compat', '6result')
L10N_IDXS = {'grades': (9, 10), 'license': (11, 12), 'testssl': (13, 14),
             'security_guides': (15, 16)}
METADATA_S = ('[pdf_meta_keywords', '[pdf_meta_subject]')
OS_PATH = dirname(abspath(__file__))
PDF_COLORS = ('#008000', '#000000', '#660033')
PDF_CONDITIONS = ('Ref:', ':', '"', '(*) ')
PDF_SECTION = {'[0.': '[0section_s]', '[HTTP R': '[0headers_s]',
               '[1.': '[1enabled_s]', '[2.': '[2missing_s]',
               '[3.': '[3fingerprint_s]', '[4.': '[4depinsecure_s]',
               '[5.': '[5empty_s]', '[6.': '[6compat_s]', '[7.': '[7result_s]',
               '[Cabeceras': '[0headers_s]'}
RE_PATTERN = (
    r'\((.*?)\)',
    (r'^(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.'
     r'(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})$|'
     r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
     r'^[0-9a-fA-F:]+$|'
     r'^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^::(?:[0-9a-fA-F]{1,4}:){1,7}$'),
    (r'\.\./|/\.\.|\\\.\.|\\\.\\|'
     r'%2e%2e%2f|%252e%252e%252f|%c0%ae%c0%ae%c0%af|'
     r'%uff0e%uff0e%u2215|%uff0e%uff0e%u2216'), r'\(([^)]+)\)',
    r'\d{4}-\d{2}-\d{2}', r'\[(.*?)\]\n', r"'nonce-([^']+)'",
    r'\(humble_pdf_style\)([^:]+):',
    r'<meta\s+http-equiv=["\'](.*?)["\']\s+content=["\'](.*?)["\']\s*/?>',
    r'\(humble_sec_style\)([^:]+)', r'\(humble_sec_style\)',
    r'(?: Nota : | Note : )', r'^[0-9a-fA-F]{32}$', r'^[A-Za-z0-9+/=]+$',
    r', (?=[^;,]+?=)', r"'nonce-[^']+'", r"(^|[\s;])({dir})($|[\s;])",
    r"'(sha256|sha384|sha512)-([A-Za-z0-9+/=]+)'",
    r"(?<!')\b(sha256|sha384|sha512)-[A-Za-z0-9+/=]+(?!')",
    r'^([a-zA-Z0-9\-]+)',
    r'\s{2,},',
    r"^(.*?):\s+(\d+)\s+\((.*?)\)$",
    r"<pre(?:\s[^>]*)?>\s*</pre>",
    r"<pre>/pre>'"
)
REF_LINKS = (' Ref  : ', ' Ref: ', 'Ref  :', 'Ref: ', ' ref:')
REQ_HEADERS = {
    'Accept': (
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    ),
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Upgrade-Insecure-Requests': '1',
}
REQ_TIMEOUT = 15
REQ_WARNING = 6
SECTION_S = ('[enabled_cnt]', '[missing_cnt]', '[fng_cnt]', '[insecure_cnt]',
             '[empty_cnt]', '[total_cnt]')
SECTION_V = ('[no_enabled]', '[no_missing]', '[no_fingerprint]',
             '[no_ins_deprecated]', '[no_empty]', '[average_warnings]',
             '[average_warnings_year]', '[average_enb]', '[average_miss]',
             '[average_fng]', '[average_dep]', '[average_ety]',
             '[most_analyzed]', '[least_analyzed]', '[most_warnings]',
             '[least_warnings]', '[most_enabled]', '[least_enabled]',
             '[most_missing]', '[least_missing]', '[most_fingerprints]',
             '[least_fingerprints]', '[most_insecure]', '[least_insecure]',
             '[most_empty]', '[least_empty]')
SLICE_INT = (30, 43, 25, 24, -4, -5, 46, 31, 6, 21, 10, 4, 20)
STYLE = (Style.BRIGHT, f"{Style.BRIGHT}{Fore.RED}", Fore.CYAN, Style.NORMAL,
         Style.RESET_ALL, Fore.RESET, '(humble_pdf_style)',
         f"(humble_sec_style){Fore.GREEN}", '(humble_sec_style)',
         f"{Style.RESET_ALL}{Fore.RESET}", Fore.GREEN)
TESTSSL_FILE = ("testssl", "testssl.sh")
# Check https://testssl.sh/doc/testssl.1.html to choose your preferred options
TESTSSL_OPTIONS = ['-f', '-g', '-p', '-U', '-s', '--hints']
URL_LIST = (': https://caniuse.com/?search=', ' Ref  : https://developers.\
cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors\
/', ' Ref  : https://developer.mozilla.org/en-US/docs/Web/HTTP/\
Reference/Status/', 'https://raw.githubusercontent.com/rfc-st/humble/master/\
humble.py', 'https://github.com/rfc-st/humble')
URL_STRING = ('rfc-st', ' URL  : ', 'https://caniuse.com/?')
VALIDATE_FILE = path.join(OS_PATH, HUMBLE_FILES[0])
XML_STRING = ('Ref: ', 'Value: ', 'Valor: ')

current_time = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
local_version = datetime.strptime('2025-11-01', '%Y-%m-%d').date()

BANNER_VERSION = f'{URL_LIST[4]} | v.{local_version}'


class SSLContextAdapter(requests.adapters.HTTPAdapter):
    """
    Custom SSL adapter that disables certificate verification to facilitate
    analysis.
    """
    def init_poolmanager(self, *args, **kwargs):
        # I have chosen to disable these checks to allow the analysis of URLs
        # in certain cases (E.g., development environments, hosts with outdated
        # servers/software, self-signed certificates, etc.).
        context = ssl._create_unverified_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.cert_reqs = ssl.CERT_NONE
        context.set_ciphers(FORCED_CIPHERS)
        kwargs['ssl_context'] = context
        return super(SSLContextAdapter, self).init_poolmanager(*args, **kwargs)


def check_python_version():
    """Checks the minimum required version of Python"""
    exit(print_detail('[python_version]', 3)) if sys.version_info < (3, 11) \
        else None


def process_proxy_url(proxy_url, timeout):
    """'-p' option: Proxy validation and connectivity check"""
    parsed_proxy_url = urlparse(proxy_url)
    proxy_host = parsed_proxy_url.hostname
    if not proxy_host:
        print_error_detail('[proxy_host]')
    try:
        proxy_port = parsed_proxy_url.port or 8080
    except ValueError:
        delete_lines()
        print_error_detail('[proxy_port]')
    failed_proxy = Event()
    proxy_thread = Thread(target=check_proxy_url, args=(proxy_host, proxy_port,
                                                        timeout, failed_proxy),
                          daemon=True)
    proxy_thread.start()
    proxy_thread.join(timeout)
    if proxy_thread.is_alive() or failed_proxy.is_set():
        delete_lines()
        print_error_detail('[proxy_url]')
    return True


def check_proxy_url(proxy_host, proxy_port, timeout, failed_proxy):
    try:
        with create_connection((proxy_host, proxy_port), timeout=timeout):
            pass
    except Exception:
        failed_proxy.set()


def check_updates(local_version):
    """'-v' option: Check for updates from GitHub"""
    try:
        github_repo = requests.get(URL_LIST[3], timeout=REQ_TIMEOUT).text
        github_date = re.search(RE_PATTERN[4], github_repo).group()
        github_version = datetime.strptime(github_date, '%Y-%m-%d').date()
        days_diff = (github_version - local_version).days
        check_updates_diff(days_diff, github_version, local_version)
    except requests.exceptions.RequestException:
        print_error_detail('[update_error]')
    sys.exit()


def check_updates_diff(days_diff, github_version, local_version):
    # Three weeks without updating 'humble' is too long ;)
    print(f" \n{STYLE[0]}{get_detail('[humble_latest]', replace=True)} \
{github_version} \n {get_detail('[humble_local]', replace=True)} \
{local_version}{STYLE[4]}")
    if days_diff > 21:
        print(f"\n{get_detail('[humble_not_recent]')}\n\
{get_detail('[github_humble]', replace=True)}\n")
    else:
        print_detail('[humble_recent]', 8)


def fng_statistics_top():
    """'-f' option: Show fingerprint statistics"""
    print(f"\n{STYLE[0]}{get_detail('[fng_stats]', replace=True)}\
{STYLE[4]}{get_detail('[fng_source]', replace=True)}\n")
    with open(path.join(OS_PATH, HUMBLE_DIRS[0], HUMBLE_FILES[2]), 'r',
              encoding='utf8') as fng_f:
        fng_lines = fng_f.readlines()
    fng_incl = sum(1 for _ in islice(fng_lines, SLICE_INT[0], None))
    fng_lines = fng_lines[SLICE_INT[0]:]
    fng_statistics_top_groups(fng_lines, fng_incl)
    sys.exit()


def fng_statistics_top_groups(fng_lines, fng_incl):
    top_groups_pattern = re.compile(RE_PATTERN[3])
    fng_top_groups = Counter(match.strip() for line in fng_lines for match in
                             top_groups_pattern.findall(line))
    fng_statistics_top_result(fng_top_groups, fng_incl)


def fng_statistics_top_result(fng_top_groups, fng_incl):
    max_ln_len = max(len(content) for content, _ in
                     fng_top_groups.most_common(20))
    print(f"{get_detail('[fng_top]', replace=True)} {fng_incl}\
{get_detail('[fng_top_2]', replace=True)}\n")
    for content, count in fng_top_groups.most_common(20):
        fng_global_pct = round(count / fng_incl * 100, 2)
        fng_padding = ' ' * (max_ln_len - len(content))
        print(f" [{content}]: {fng_padding}{fng_global_pct:.2f}% ({count})")


def fng_statistics_term(fng_term):
    print(f"\n{STYLE[0]}{get_detail('[fng_stats]', replace=True)}\
{STYLE[4]}{get_detail('[fng_source]', replace=True)}\n")
    with open(path.join(OS_PATH, HUMBLE_DIRS[0], HUMBLE_FILES[2]), 'r',
              encoding='utf8') as fng_source:
        fng_lines = fng_source.readlines()
    fng_incl = list(islice(fng_lines, SLICE_INT[0], None))
    fng_groups, term_cnt = fng_statistics_term_groups(fng_incl, fng_term)
    if not fng_groups:
        print(f"{get_detail('[fng_zero]', replace=True)} '{fng_term}'.\n\n\
{get_detail('[fng_zero_2]', replace=True)}.\n")
        sys.exit()
    fng_statistics_term_content(fng_groups, fng_term, term_cnt, fng_incl)


def fng_statistics_term_groups(fng_incl, fng_term):
    fng_matches = [match for line in fng_incl if
                   (match := re.search(RE_PATTERN[0], line)) and
                   fng_term.lower() in match[1].lower()]
    fng_groups = sorted({match[1].strip() for match in fng_matches})
    term_cnt = len(fng_matches)
    return fng_groups, term_cnt


def fng_statistics_term_content(fng_groups, fng_term, term_cnt, fng_incl):
    fng_pct = round(term_cnt / len(fng_incl) * 100, 2)
    print(f"{get_detail('[fng_add]', replace=True)} '{fng_term}': {fng_pct}%\
 ({term_cnt}{get_detail('[pdf_footer2]', replace=True)} {len(fng_incl)})")
    fng_statistics_term_sorted(fng_incl, fng_term.lower(), fng_groups)


def fng_statistics_term_sorted(fng_incl, fng_term, fng_groups):
    for content in fng_groups:
        print(f"\n [{STYLE[0]}{content}]")
        content = content.lower()
        for line in fng_incl:
            line_l = line.lower()
            if content in line_l and fng_term in line_l:
                print(f"  {line[:line.find('(')].strip()}")
    sys.exit()


def print_l10n_file(args, l10n_file, slice_ln=False):
    """Show localized guides content"""
    lang_es = args.lang == 'es'
    lang_idx = 1 if lang_es else 0
    l10n_file = HUMBLE_FILES[L10N_IDXS[l10n_file][lang_idx]]
    l10n_slice = SLICE_INT[2 if lang_es else 3]
    file_path = path.join(OS_PATH, HUMBLE_DIRS[1], l10n_file)
    with open(file_path, 'r', encoding='utf8') as l10n_source:
        l10n_lines = islice(l10n_source, l10n_slice, None) if slice_ln else \
            l10n_source
        for line in l10n_lines:
            prefix = f" {STYLE[0]}" if line.startswith('[') else "  "
            print(f"{prefix}{line}", end='')
    sys.exit()


def testssl_command(testssl_temp_path, uri):
    """'-e' option: Run TLS/SSL analysis using testssl.sh"""
    testssl_temp_path = path.abspath(testssl_temp_path)
    if not path.isdir(testssl_temp_path):
        print_error_detail('[notestssl_path]')
    testssl_path = next(
        (path.join(testssl_temp_path, filename)
         for filename in TESTSSL_FILE
         if path.isfile(path.join(testssl_temp_path, filename))),
        None
    )
    if not testssl_path:
        print_error_detail('[notestssl_file]')
    if not access(testssl_path, X_OK):
        print_error_detail('[notestssl_exec]')
    print("")
    print(f"{get_detail('[testssl_warning]', replace=True)} '{testssl_path}'")
    choice = input(
        f"{get_detail('[testssl_choice]', replace=True)} "
    ).strip().lower()
    if choice != "y":
        sys.exit()
    delete_lines()
    testssl_cmd = [testssl_path] + TESTSSL_OPTIONS + [uri]
    testssl_analysis(testssl_cmd)
    sys.exit()


def testssl_analysis(testssl_cmd):
    try:
        process = Popen(testssl_cmd, stdout=PIPE, stderr=PIPE, text=True)
        for ln in iter(process.stdout.readline, ''):
            print(ln, end='')
            if 'Done' in ln:
                process.terminate()
                process.wait()
                break
        if stderr := process.stderr.read():
            print(stderr, end='')
    except Exception:
        print_error_detail('[testssl_error]')


def get_l10n_content():
    """Show localized guides content"""
    l10n_path = path.join(OS_PATH, HUMBLE_DIRS[1], HUMBLE_FILES[4]
                          if args.lang == 'es' else HUMBLE_FILES[5])
    with open(l10n_path, 'r', encoding='utf8') as l10n_content:
        return l10n_content.readlines()


def get_analysis_results():
    """Show and save analysis results and summary"""
    analysis_t = str(round(end - start, 2)).rstrip()
    print(f"{get_detail('[analysis_time]', replace=True)} {analysis_t}\
{get_detail('[analysis_time_sec]', replace=True)}")
    t_cnt = sum([m_cnt, f_cnt, i_cnt[0], e_cnt])
    analysis_totals = save_analysis_results(t_cnt)
    analysis_diff = compare_analysis_results(*analysis_totals, en_cnt=en_cnt,
                                             m_cnt=m_cnt, f_cnt=f_cnt,
                                             i_cnt=i_cnt, e_cnt=e_cnt,
                                             t_cnt=t_cnt)
    en_cnt_w = '1' if en_cnt == 0 else None
    format_analysis_results(*analysis_diff, en_cnt_w=en_cnt_w, t_cnt=t_cnt)
    analysis_grade = grade_analysis(en_cnt, m_cnt, f_cnt, i_cnt, e_cnt)
    print(f"{get_detail(analysis_grade)}")
    print_detail('[experimental_header]', 3)


def save_analysis_results(t_cnt):
    ok, fallback = validate_file_access(VALIDATE_FILE, context='history')
    if not ok:
        return fallback
    with open(HUMBLE_FILES[0], 'a+', encoding='utf8') as all_analysis:
        all_analysis.seek(0)
        url_ln = [line for line in all_analysis if URL in line]
        # Format of the analysis history file, ('analysis_h.txt'): Date, URL,
        # Enabled, Missing, Fingerprint, Deprecated/Insecure, Empty headers and
        # Total warnings (the four previous totals).
        all_analysis.write(f"{current_time} ; {URL} ; {en_cnt} ; {m_cnt} ; "
                           f"{f_cnt} ; {i_cnt[0]} ; {e_cnt} ; {t_cnt}\n")
    return get_analysis_totals(url_ln) if url_ln else ("First",) * 6


def get_analysis_totals(url_ln):
    # To avoid errors with analyses performed before 11/28/2024, the date on
    # which enabled security headers began being considered when calculating
    # differences between analyses of the same URL.

    # Therefore, analyses performed before that date are assumed to have no
    # security headers enabled.
    # Ref: https://github.com/rfc-st/humble/commit/f7b376
    updated_lines = []
    for line in url_ln:
        fields = line.strip().split(' ; ')
        if len(fields) == 7:
            fields.insert(2, '0')
        updated_lines.append(' ; '.join(fields))
    url_ln = updated_lines
    analysis_date = max(line[:SLICE_INT[9]] for line in url_ln)
    for line in url_ln:
        if analysis_date in line:
            *totals, = line.strip().split(' ; ')
            break
    return tuple(totals[2:])


def compare_analysis_results(*analysis_totals, en_cnt, m_cnt, f_cnt, i_cnt,
                             e_cnt, t_cnt):
    if analysis_totals[0] == "First":
        return [get_detail('[first_analysis]', replace=True)] * 6
    elif analysis_totals[0] == "Not available":
        return [get_detail('[notaval_analysis]', replace=True)] * 6
    current = [int(val) for val in analysis_totals]
    differences = [en_cnt, m_cnt, f_cnt, i_cnt[0], e_cnt, t_cnt]
    return [get_detail('[no_changes]', replace=True) if (d - c) == 0
            else f"{d - c:+d}" for d, c in zip(differences, current)]


def format_analysis_results(*diff, en_cnt_w, t_cnt):
    results = [en_cnt, m_cnt, f_cnt, i_cnt[0], e_cnt, t_cnt]
    new_ln = ["\n" if int(en_cnt) > 0 else "", "", "", "", "", "\n\n"]
    totals = [f"{val:>2} ({diff[i]}){new_ln[i]}" for i, val in
              enumerate(results)]
    max_secl = get_max_lnlength(SECTION_S)
    print_analysis_results(totals, max_secl, en_cnt_w)


def print_analysis_results(totals, max_secl, en_cnt_w):
    for idx, (literal, total) in enumerate(zip(SECTION_S, totals)):
        print(f"{print_detail_s(literal, max_ln=True):<{max_secl}} {total}",
              end='')
        if idx == 0 and en_cnt_w:
            val1 = print_detail_s('[enabled_cnt_w]', max_ln=True)
            val2 = get_detail('[enabled_cnt_wt]')
            print(f"{val1:<{max_secl}} {val2}", end='')


def grade_analysis(en_cnt, m_cnt, f_cnt, i_cnt, e_cnt):
    """Show analysis grade"""
    if en_cnt == 0:
        return '[e_grade]'
    if i_cnt and sum(i_cnt) > 0:
        return '[d_grade]'
    if m_cnt > 0:
        return '[c_grade]'
    if f_cnt > 0:
        return '[b_grade]'
    return '[a_grade]' if e_cnt > 0 else '[perfect_grade]'


def check_analysis(filepath):
    """Check if analysis history file exists"""
    if not path.exists(filepath):
        detail = '[no_analysis]' if URL else '[no_global_analysis]'
        print_error_detail(detail)


def adjust_old_analysis(url_ln):
    """Adjust analysis totals from history prior to 11/28/2024"""
    # To avoid errors with analyses performed before 11/28/2024, the date on
    # which enabled security headers began being written to the analysis
    # history file ('analysis_h.txt') and considered for displaying statistics
    # (via the '-a' parameter).

    # Therefore, analyses performed before that date are assumed to have no
    # security headers enabled.
    # Ref: https://github.com/rfc-st/humble/commit/f7b376
    updated_lines = []
    for i in url_ln:
        fields = i.strip().split(';')
        if len(fields) == 7:
            fields = [field.strip() for field in fields]
            fields.insert(2, '0')
            updated_lines.append(' ; '.join(fields) + '\n')
        else:
            updated_lines.append(i)
    return updated_lines


def url_analytics(is_global=False):
    """'-a' option: Show analysis statistics"""
    url_scope = extract_global_metrics if is_global else get_analysis_metrics
    with open(HUMBLE_FILES[0], 'r', encoding='utf8') as all_analysis:
        analysis_metrics = url_scope(all_analysis)
    l10n_det = '[global_stats_analysis]' if is_global else '[stats_analysis]'
    url_string = '' if is_global else URL
    print(f"\n{get_detail(l10n_det, replace=True)} {url_string}\n")
    for key, value in analysis_metrics.items():
        key_style = f"{STYLE[0]}{key}{STYLE[4]}" if not value or not \
            key.startswith(' ') else key
        print(f"{key_style}: {value}")
    sys.exit()


def get_analysis_metrics(all_analysis):
    url_ln = [line for line in all_analysis if URL in line]
    if not url_ln:
        print_error_detail('[no_analysis]')
    adj_url_ln = adjust_old_analysis(url_ln)
    total_a = len(adj_url_ln)
    return print_metrics(
        get_analytics_length(SECTION_V[:5]),
        get_analytics_length(SECTION_V[5:12]),
        total_a,
        get_first_metrics(adj_url_ln),
        [get_second_metrics(adj_url_ln, i, total_a) for i in range(2, 7)],
        get_third_metrics(adj_url_ln),
        get_additional_metrics(adj_url_ln),
        get_highlights(adj_url_ln),
        get_trends(adj_url_ln)
    )


def get_first_metrics(adj_url_ln):
    first_a = min(line[:SLICE_INT[9]] for line in adj_url_ln)
    latest_a = max(line[:SLICE_INT[9]] for line in adj_url_ln)
    date_w = [(line[:SLICE_INT[9]], int(line.strip().split(" ; ")[-1]))
              for line in adj_url_ln]
    best_d, best_w = min(date_w, key=lambda x: x[1])
    worst_d, worst_w = max(date_w, key=lambda x: x[1])
    return (first_a, latest_a, best_d, best_w, worst_d, worst_w)


def get_second_metrics(adj_url_ln, index, total_a):
    metric_c = len([line for line in adj_url_ln if int(line.split(' ; ')
                                                       [index])
                    == 0])
    return f"{metric_c / total_a:.0%} ({metric_c}\
{get_detail('[pdf_footer2]', replace=True)} {total_a})"


def get_third_metrics(adj_url_ln):
    fields = [line.strip().split(';') for line in adj_url_ln]
    total_enb, total_miss, total_fng, total_dep, total_ety = \
        [sum(int(f[i]) for f in fields) for i in range(2, 7)]
    num_a = len(adj_url_ln)
    avg_enb, avg_miss, avg_fng, avg_dep, avg_ety = \
        [t // num_a for t in (total_enb, total_miss, total_fng, total_dep,
                              total_ety)]
    return (avg_enb, avg_miss, avg_fng, avg_dep, avg_ety)


def get_additional_metrics(adj_url_ln):
    avg_w = int(sum(int(line.split(' ; ')[-1]) for line in adj_url_ln) /
                len(adj_url_ln))
    year_a, avg_w_y, month_a = extract_date_metrics(adj_url_ln)
    return (avg_w, year_a, avg_w_y, month_a)


def extract_date_metrics(url_ln):
    year_cnt, year_wng = defaultdict(int), defaultdict(int)
    for line in url_ln:
        year = int(line[:SLICE_INT[11]])
        year_cnt[year] += 1
        year_wng[year] += int(line.rsplit(' ; ', 1)[-1])
    years_str = generate_date_groups(year_cnt, url_ln)
    avg_wng_y = sum(year_wng.values()) // len(year_wng)
    return years_str, avg_wng_y, year_wng


def generate_date_groups(year_cnt, url_ln):
    years_str = []
    for year in sorted(year_cnt.keys()):
        year_str = f" {year}: {year_cnt[year]} \
{get_detail('[analysis_y]').rstrip()}"
        month_cnts = get_month_counts(year, url_ln)
        months_str = '\n'.join([f"  ({count}){month_name.rstrip()}" for
                                month_name, count in month_cnts.items()])
        year_str += f"\n{months_str}\n"
        years_str.append(year_str)
    return '\n'.join(years_str)


def get_month_counts(year, url_ln):
    month_cnts = defaultdict(int)
    for line in url_ln:
        date_str = line[:SLICE_INT[10]]
        line_year, line_month, _ = map(int, date_str.split('/'))
        if line_year == year:
            month_cnts[get_detail(f'[month_{line_month:02d}]')] += 1
    return month_cnts


def get_highlights(adj_url_ln):
    sections_h = SECTION_S[:-1]
    best_lbl = print_detail_l('[best_analysis]', analytics=True)
    worst_lbl = print_detail_l('[worst_analysis]', analytics=True)
    results = []
    for i, field in enumerate(range(2, 7)):
        fns_cond = (min, max) if i else (max, min)
        section_lbl = print_detail_l(sections_h[i], analytics=True)
        best_val = calculate_highlights(adj_url_ln, field, fns_cond[0])
        worst_val = calculate_highlights(adj_url_ln, field, fns_cond[1])
        results.append(f" {section_lbl}\n  {best_lbl}: {best_val}\n"
                       f"  {worst_lbl}: {worst_val}\n")
    return results


def calculate_highlights(url_ln, field_index, func):
    values = [int(line.split(';')[field_index].strip()) for line in url_ln]
    target_value = func(values)
    target_line = next(line for line in url_ln
                       if int(line.split(';')[field_index].strip()) ==
                       target_value)
    return target_line.split(';')[0].strip()


def get_trends(adj_url_ln):
    """Calculate and show trends related to '-a' option"""
    sections_t = SECTION_S[1:]
    fields_t = [3, 4, 5, 6, 7]
    max_secl = (get_max_lnlength(SECTION_S))-2
    trends = []
    for section, field_idx in zip(sections_t, fields_t):
        values = [int(parts[field_idx].strip()) for line in adj_url_ln
                  if len((parts := line.strip().split(';'))) > field_idx]
        trends.append(f"{(get_detail(section, replace=True).ljust(max_secl))}\
 {calculate_trends(values)}")
    return trends


def calculate_trends(values):
    # Calculates the trend of values for several checks (Missing, Fingerprint,
    # Deprecated/Insecure, Empty headers, and Total warnings) for a given URL.
    #
    # At least five analyses of the URL are required to calculate reliable
    # trends, and only the five most recent analyses are considered. The
    # possible trends are:
    #
    # 'Stable': All five values are identical.
    # 'Improving': Values consistently decrease.
    # 'Worsening': Values consistently increase.
    # 'Fluctuating': No clear trend is detected; values alternate.
    if len(values) < 5:
        return print_detail_l('[t_insufficient]', analytics=True)
    trends_list = values[-5:]
    if all(x == trends_list[0] for x in trends_list):
        return print_detail_l('[t_stable]', analytics=True)
    inc_trend = sum(trends_list[i] > trends_list[i - 1] for i in range(1, 5))
    dec_trend = sum(trends_list[i] < trends_list[i - 1] for i in range(1, 5))
    if dec_trend > inc_trend:
        return print_detail_l('[t_improving]', analytics=True)
    if inc_trend > dec_trend:
        return print_detail_l('[t_worsening]', analytics=True)
    return print_detail_l('[t_fluctuating]', analytics=True)


def print_metrics(analytics_s, analytics_w, total_a, first_m, second_m,
                  third_m, additional_m, fourth_m, fifth_m):
    """Show metrics related to '-a' option"""
    basic_m = get_basic_metrics(total_a, first_m)
    error_m = get_security_metrics(analytics_s, second_m)
    warning_m = get_warnings_metrics(additional_m, analytics_w)
    averages_m = get_averages_metrics(analytics_w, third_m)
    fourth_m = get_highlights_metrics(fourth_m)
    trend_m = get_trend_metrics(fifth_m)
    analysis_year_m = get_date_metrics(additional_m)
    totals_m = {**basic_m, **error_m, **warning_m, **averages_m, **fourth_m,
                **trend_m, **analysis_year_m}
    return {get_detail(key, replace=True): value for key, value in
            totals_m.items()}


def get_basic_metrics(total_a, first_m):
    return {'[main]': "", '[total_analysis]': total_a,
            '[first_analysis_a]': first_m[0], '[latest_analysis]': first_m[1],
            '[best_analysis]': f"{first_m[2]} \
{get_detail('[total_warnings]', replace=True)}{first_m[3]})",
            '[worst_analysis]': f"{first_m[4]} \
{get_detail('[total_warnings]', replace=True)}{first_m[5]})\n"}


def get_security_metrics(analytics_s, second_m):
    return {'[analysis_y]': "",
            '[no_enabled]': f"{analytics_s[0]}{second_m[0]}",
            '[no_missing]': f"{analytics_s[1]}{second_m[1]}",
            '[no_fingerprint]': f"{analytics_s[2]}{second_m[2]}",
            '[no_ins_deprecated]': f"{analytics_s[3]}{second_m[3]}",
            '[no_empty]': f"{analytics_s[4]}{second_m[4]}\n"}


def get_warnings_metrics(additional_m, analytics_w):
    return {'[averages]': "",
            '[average_warnings]': f"{analytics_w[0]}{additional_m[0]}",
            '[average_warnings_year]': f"{analytics_w[1]}{additional_m[2]}\n"}


def get_averages_metrics(analytics_w, third_m):
    return {'[average_enb]': f"{analytics_w[2]}{third_m[0]}",
            '[average_miss]': f"{analytics_w[3]}{third_m[1]}",
            '[average_fng]': f"{analytics_w[4]}{third_m[2]}",
            '[average_dep]': f"{analytics_w[5]}{third_m[3]}",
            '[average_ety]': f"{analytics_w[6]}{third_m[4]}\n"}


def get_highlights_metrics(fourth_m):
    return {'[highlights]': "\n" + "\n".join(fourth_m)}


def get_trend_metrics(fifth_m):
    if '5' in fifth_m[0]:
        trends_s = get_detail('[t_insufficient]')
        return {'[trends]': "\n" + trends_s}
    return {'[trends]': "\n" + "\n".join(fifth_m) + "\n"}


def get_date_metrics(additional_m):
    return {'[analysis_year_month]': f"\n{additional_m[1]}"}


def extract_global_metrics(all_analysis):
    url_ln = list(all_analysis)
    if not url_ln:
        print_error_detail('[no_global_analysis]')
    adj_url_ln = adjust_old_analysis(url_ln)
    total_a = len(adj_url_ln)
    first_m = get_global_first_metrics(adj_url_ln)
    second_m = [get_second_metrics(adj_url_ln, i, total_a) for i
                in range(2, 7)]
    third_m = get_third_metrics(adj_url_ln)
    additional_m = get_additional_metrics(adj_url_ln)
    analytics_l = get_analytics_length(SECTION_V[12:26])
    analytics_s = get_analytics_length(SECTION_V[:5])
    analytics_w = get_analytics_length(SECTION_V[5:12])
    return print_global_metrics(analytics_l, analytics_s, analytics_w, total_a,
                                first_m, second_m, third_m, additional_m)


def get_global_first_metrics(adj_url_ln):
    split_lines = [line.split(' ; ') for line in adj_url_ln]
    url_lines = {}
    for entry in split_lines:
        url = entry[1]
        url_lines[url] = url_lines.get(url, 0) + 1
    return get_global_metrics(adj_url_ln, url_lines)


def get_global_metrics(url_ln, url_lines):
    first_a = min(line[:SLICE_INT[9]] for line in url_ln)
    latest_a = max(line[:SLICE_INT[9]] for line in url_ln)
    unique_u = len({line.split(' ; ')[1] for line in url_ln})
    most_analyzed_u = max(url_lines, key=url_lines.get)
    most_analyzed_c = url_lines[most_analyzed_u]
    most_analyzed_cu = f"({most_analyzed_c}) {most_analyzed_u}"
    least_analyzed_u = min(url_lines, key=url_lines.get)
    least_analyzed_c = url_lines[least_analyzed_u]
    least_analyzed_cu = f"({least_analyzed_c}) {least_analyzed_u}"
    fields = [-1, 2, 3, 4, 5, 6]
    totals = [get_global_totals(url_ln, field) for field in fields]
    return (first_a, latest_a, unique_u, most_analyzed_cu, least_analyzed_cu,
            *(item for total in totals for item in total))


def get_global_totals(url_ln, field):
    most_totals = max(url_ln, key=lambda line: int(line.split(' ; ')[field]))
    least_totals = min(url_ln, key=lambda line: int(line.split(' ; ')[field]))
    most_totals_c, most_totals_cu = most_totals.split(' ; ')[1], \
        str(most_totals.split(' ; ')[field]).strip()
    most_totals_p = f"({most_totals_cu}) {most_totals_c}"
    least_totals_c, least_totals_cu = least_totals.split(' ; ')[1], \
        str(least_totals.split(' ; ')[field]).strip()
    least_totals_p = f"({least_totals_cu}) {least_totals_c}"
    return (most_totals_p, least_totals_p)


def get_basic_global_metrics(analytics_l, total_a, first_m):
    return {'[main]': "", '[total_analysis]': total_a,
            '[total_global_analysis]': str(first_m[2]),
            '[first_analysis_a]': first_m[0],
            '[latest_analysis]': f"{first_m[1]}\n",
            '[urls]': "",
            '[most_analyzed]': f"{analytics_l[0]}{first_m[3]}",
            '[least_analyzed]': f"{analytics_l[1]}{first_m[4]}\n",
            '[most_enabled]': f"{analytics_l[4]}{first_m[7]}",
            '[least_enabled]': f"{analytics_l[5]}{first_m[8]}\n",
            '[most_missing]': f"{analytics_l[6]}{first_m[9]}",
            '[least_missing]': f"{analytics_l[7]}{first_m[10]}\n",
            '[most_fingerprints]': f"{analytics_l[8]}{first_m[11]}",
            '[least_fingerprints]': f"{analytics_l[9]}{first_m[12]}\n",
            '[most_insecure]': f"{analytics_l[10]}{first_m[13]}",
            '[least_insecure]': f"{analytics_l[11]}{first_m[14]}\n",
            '[most_empty]': f"{analytics_l[12]}{first_m[15]}",
            '[least_empty]': f"{analytics_l[13]}{first_m[16]}\n",
            '[most_warnings]': f"{analytics_l[2]}{first_m[5]}",
            '[least_warnings]': f"{analytics_l[3]}{first_m[6]}\n"}


def print_global_metrics(analytics_l, analytics_s, analytics_w,
                         total_a, first_m, second_m, third_m, additional_m):
    basic_m = get_basic_global_metrics(analytics_l, total_a, first_m)
    error_m = get_security_metrics(analytics_s, second_m)
    warning_m = get_warnings_metrics(additional_m, analytics_w)
    averages_m = get_averages_metrics(analytics_w, third_m)
    analysis_year_m = get_date_metrics(additional_m)
    totals_m = {**basic_m, **error_m, **warning_m, **averages_m,
                **analysis_year_m}
    return {get_detail(key, replace=True): value for key, value in
            totals_m.items()}


def csp_analyze_content(csp_header):
    """'Content-Security-Policy' header analysis"""
    csp_deprecated = set()
    csp_dirs_vals = [dir.strip() for dir in csp_header.split(';') if
                     dir.strip()]
    csp_dirs = {dir.split()[0] for dir in csp_dirs_vals}
    for csp_dir in csp_dirs_vals:
        csp_deprecated |= ({value for value in t_csp_dep if value in csp_dir})
    if csp_deprecated:
        csp_print_deprecated(csp_deprecated)
    if "'strict-dynamic'" in csp_header:
        csp_check_ignored(csp_header)
    csp_check_missing(csp_dirs)
    csp_check_additional(csp_dirs_vals)


def csp_check_ignored(csp_header):
    hash_p = bool(re.search(RE_PATTERN[17], csp_header))
    nonce_p = bool(re.search(RE_PATTERN[6], csp_header))
    if not (hash_p or nonce_p):
        i_cnt[0] += 1
        if args.brief:
            print_detail_r('[icsig_d]', is_red=True)
        else:
            print_detail_r('[icsig_d]', is_red=True)
            print_detail('[icsig]', num_lines=2)
    return False


def csp_check_missing(csp_dirs):
    csp_refs = [('[icspmb_h]', '[icspmb]'), ('[icspmc_h]', '[icspmc]'),
                ('[icspmcn_h]', '[icspmcn]'), ('[icspmfo_h]', '[icspmfo]'),
                ('[icspmf_h]', '[icspmf]'), ('[icspmfa_h]', '[icspmfa]'),
                ('[icspmi_h]', '[icspmi]'), ('[icspmo_h]', '[icspmo]'),
                ('[icspmr_h]', '[icspmr]'), ('[icspms_h]', '[icspms]'),
                ('[icspmst_h]', '[icspmst]'), ('[icspmstt_h]', '[icspmstt]'),
                ('[icspmsw_h]', '[icspmsw]')]
    for directive, (csp_ref_brief, csp_ref) in zip(t_csp_miss, csp_refs):
        if directive not in csp_dirs:
            csp_print_missing(csp_ref, csp_ref_brief)


def csp_print_missing(csp_ref, csp_ref_brief):
    if args.brief:
        i_cnt[0] += 1
        print_detail_r(csp_ref_brief, is_red=True)
    elif csp_ref == '[icspmfa]':
        i_cnt[0] += 1
        print_detail_r(csp_ref_brief, is_red=True)
        print_detail(csp_ref, num_lines=4)
    else:
        print_details(csp_ref_brief, csp_ref, 'd', i_cnt)


def csp_check_additional(csp_dirs_vals):
    checks = [(t_csp_broad, csp_check_broad),
              (t_csp_insecs, csp_check_insecure)]
    for match, csp_func in checks:
        if any(val in dir for dir in csp_dirs_vals for val in match):
            csp_func(csp_dirs_vals)
    csp_check_eval(csp_dirs_vals)
    csp_check_inline(csp_dirs_vals)


def csp_check_broad(csp_dirs_vals):
    csp_broad_v = sorted({value for dir_vals in csp_dirs_vals if
                          dir_vals.strip() for value in dir_vals.split()[1:]
                          if f" {value} " in t_csp_broad})
    if not csp_broad_v:
        return
    csp_broad_dirs = {dir_vals.split()[0] for dir_vals in csp_dirs_vals
                      if any(f" {broad_val} " in t_csp_broad for broad_val in
                             dir_vals.split()[1:])}
    csp_print_broad(csp_broad_dirs, csp_broad_v, i_cnt)


def csp_print_broad(csp_broad_dirs, csp_broad_v, i_cnt):
    print_detail_r('[icsw_h]', is_red=True)
    if not args.brief:
        print_detail_l(DIR_MSG[0] if len(csp_broad_dirs) > 1 else DIR_MSG[1])
        print(" " + ", ".join(f"'{dir}'" for dir in sorted(csp_broad_dirs)) +
              ".")
        print_detail_l('[icsw]')
        print(', '.join(f"'{value}'" for value in csp_broad_v))
        print_detail('[icsw_b]', num_lines=1)
    i_cnt[0] += 1


def csp_check_insecure(csp_dirs_vals):
    csp_insec_v = sorted({value for value in t_csp_insecs if
                          any(value in dir for dir in csp_dirs_vals)})
    csp_insec_dirs = {dir_vals.split()[0] for dir_vals in csp_dirs_vals
                      if any(unsafe_val in dir_vals for unsafe_val in
                             t_csp_insecs)}
    csp_print_insecure(csp_insec_v, csp_insec_dirs, i_cnt)


def csp_print_insecure(csp_insec_v, csp_insec_dirs, i_cnt):
    print_detail_r('[icsh_h]', is_red=True)
    if not args.brief:
        csp_values = ', '.join(f"'{value}'" for value in csp_insec_v)
        print_detail_l(DIR_MSG[0] if len(csp_insec_dirs) > 1 else DIR_MSG[1])
        print(" " + ", ".join(f"'{dir}'" for dir in sorted(csp_insec_dirs)) +
              ".")
        print_detail_l('[icsh]')
        print(csp_values)
        print_detail('[icsh_b]', num_lines=2)
    i_cnt[0] += 1


def csp_check_eval(csp_dirs_vals):
    csp_unsafe_dirs = [
        dir_vals.split()[0] if ' ' in dir_vals else dir_vals
        for dir_vals in csp_dirs_vals
        if 'unsafe-eval' in dir_vals and 'wasm-unsafe-eval' not in dir_vals]
    if csp_unsafe_dirs:
        csp_print_unsafe(csp_unsafe_dirs, '[icspe_h]', '[icspev]', 5, i_cnt)


def csp_check_inline(csp_dirs_vals):
    csp_unsafe_dirs = [
        dir_vals.split()[0] if ' ' in dir_vals else dir_vals
        for dir_vals in csp_dirs_vals if 'unsafe-inline' in dir_vals]
    if csp_unsafe_dirs:
        csp_print_unsafe(csp_unsafe_dirs, '[icsp_h]', '[icsp]', 5, i_cnt)


def csp_print_unsafe(csp_unsafe_dirs, detail_t, detail_d, lines_n, i_cnt):
    print_detail_r(detail_t, is_red=True)
    if not args.brief:
        print_detail_l(DIR_MSG[0] if len(csp_unsafe_dirs) > 1 else DIR_MSG[1])
        print(" " + ", ".join(f"'{dir}'" for dir in
                              sorted(set(csp_unsafe_dirs))) + ".")
        print_detail(detail_d, num_lines=lines_n)
    i_cnt[0] += 1


def csp_check_hashes(csp_h):
    csp_unquoted_hashes(csp_h)
    invalid_algos = set()
    csp_hashes = re.findall(RE_PATTERN[17], csp_h)
    for algo, b64hash in csp_hashes:
        try:
            decoded = b64decode(b64hash, validate=True)
            if len(decoded) != HASH_CHARS[algo]:
                invalid_algos.add(algo)
        except Exception:
            invalid_algos.add(algo)
    if invalid_algos:
        print_detail_r('[icshash_h]', is_red=True)
        i_cnt[0] += 1
        if not args.brief:
            print(get_detail('[icshash_f]', replace=True))
            print_detail('[icshashr_f]', num_lines=2)


def csp_unquoted_hashes(csp_h):
    if re.search(RE_PATTERN[18], csp_h):
        print_detail_r('[icshash_h]', is_red=True)
        i_cnt[0] += 1
        if not args.brief:
            print(get_detail('[icshash_f]', replace=True))
            print_detail('[icshashr_f]', num_lines=2)


def csp_check_nonces(csp_h):
    if not re.search(RE_PATTERN[15], csp_h):
        print_details('[icsncei_h]', '[icsncei]', 'd', i_cnt)
        return
    nonce_refs = ('[icsnces_h]', '[icsncesn]', '[icsnces]')
    for nonce in re.findall(RE_PATTERN[6], csp_h):
        if (re.match(RE_PATTERN[12], nonce) and
            csp_hex_nonce(nonce, nonce_refs, i_cnt)) or \
           (re.match(RE_PATTERN[13], nonce) and
           csp_base64_nonce(nonce, nonce_refs, i_cnt)):
            return


def csp_hex_nonce(nonce, nonce_refs, i_cnt):
    return csp_print_nonce(nonce, nonce_refs, i_cnt) \
        if len(nonce) < 32 else False


def csp_base64_nonce(nonce, nonce_refs, i_cnt):
    try:
        return csp_print_nonce(nonce, nonce_refs, i_cnt) if \
            len(b64decode(nonce, validate=True)) < 16 else False
    except Exception:
        return csp_print_nonce(nonce, nonce_refs, i_cnt)


def csp_print_nonce(nonce, nonce_refs, i_cnt):
    print_detail_r(nonce_refs[0], is_red=True)
    if not args.brief:
        print_detail_l(nonce_refs[1])
        print(f"'{nonce}'.")
        print_detail(nonce_refs[2], num_lines=2)
    i_cnt[0] += 1
    return True


def csp_check_ip(csp_h):
    ip_match = re.findall(RE_PATTERN[1], csp_h)
    if ip_match != t_csp_checks[4]:
        print_details('[icsipa_h]', '[icsipa]', 'm', i_cnt)


def csp_print_deprecated(csp_deprecated):
    i_cnt[0] += 1
    print_detail_r('[icsi_d]', is_red=True) if args.brief else \
        csp_print_details(csp_deprecated, '[icsi_d]', '[icsi_d_s]',
                          '[icsi_d_r]')


def csp_print_details(csp_values, csp_title, csp_desc, csp_refs):
    csp_values = ', '.join(f"'{value}'" for value in sorted(csp_values))
    print_detail_r(f'{csp_title}', is_red=True)
    print_detail_l(f'{csp_desc}')
    print(csp_values)
    print_detail(csp_refs, num_lines=3)


def csp_check_unknown(csp_h):
    unknown_dir = []
    csp_dirs = [d.strip() for d in csp_h.split(';') if d.strip()]
    for dir in csp_dirs:
        if match := re.match(RE_PATTERN[19], dir):
            dir_name = match[1]
            if dir_name not in t_csp_dirs + t_csp_dep:
                unknown_dir.append(dir_name)
    if unknown_dir:
        csp_print_unknown(unknown_dir)


def csp_print_unknown(unknown_dir):
    # sourcery skip: use-fstring-for-concatenation
    print_detail_r('[icspiu_h]', is_red=True)
    if not args.brief:
        print_detail_l(DIR_MSG[0] if len(unknown_dir) > 1 else DIR_MSG[1])
        print(" " + ", ".join(f"'{dir}'" for dir in sorted(unknown_dir)) +
              ".")
        print_detail('[icspiu]', num_lines=3)
    i_cnt[0] += 1


def check_unsafe_cookies():  # sourcery skip: use-named-expression
    """'Set-Cookie' header analysis"""
    unsafe_cks = [ck.split('=', 1)[0].strip() for ck in
                  re.split(RE_PATTERN[14], stc_header) if
                  any(val not in ck.lower() for val in t_cookie_sec)]
    if unsafe_cks:
        print_detail_r('[iset_h]', is_red=True)
        if not args.brief:
            print_unsafe_cookies(unsafe_cks)
        i_cnt[0] += 1


def print_unsafe_cookies(unsafe_cks):
    print_detail_l('[icooks_s]' if len(unsafe_cks) > 1 else '[icook_s]')
    print(", ".join(f"'{ck}'" for ck in sorted(unsafe_cks)) + ".")
    print_detail('[iset]', num_lines=2)


def permissions_analyze_content(perm_header, i_cnt):
    """Permissions-Policy' header analysis"""
    if any(value in perm_header for value in t_per_dep):
        permissions_print_deprecated(perm_header)
    if 'none' in perm_header:
        print_details('[ifpoli_h]', '[ifpoli]', 'd', i_cnt)
    if perm_broad_dirs := permissions_check_broad(perm_header):
        permissions_print_broad(perm_broad_dirs, i_cnt)


def permissions_print_deprecated(perm_header):
    print_detail_r('[ifpold_h]', is_red=True)
    if not args.brief:
        matches_perm = [x for x in t_per_dep if x in perm_header]
        print_detail_l('[ifpold_h_s]')
        print(', '.join(f"'{x}'" for x in matches_perm))
        print_detail('[ifpold]')
    i_cnt[0] += 1


def permissions_check_broad(perm_header):
    if sum(dir in perm_header for dir in t_per_ft) < 2:
        return None
    try:
        return [directive.split('=')[0].strip()
                for directive in perm_header.split(',')
                if any(broad in directive.split('=')[1].strip() for broad in
                       t_per_broad)]
    except (IndexError, ValueError):
        print_details('[ifpolf_h]', '[ifpolf]', "d", i_cnt)
        return None


def permissions_print_broad(perm_broad_dirs, i_cnt):
    print_detail_r('[ifpol_h]', is_red=True)
    if not args.brief:
        print_detail_l(DIR_MSG[0] if len(perm_broad_dirs) > 1 else DIR_MSG[1])
        print(" " + ", ".join(f"'{dir}'" for dir in sorted(perm_broad_dirs)) +
              ".")
        print_detail('[ifpol]', num_lines=2)
    i_cnt[0] += 1


def delete_lines(reliable=True, warning=False):
    """Delete printed console lines"""
    if warning:
        sys.stdout.write(DELETED_LINES[:6])
        return
    if not reliable:
        sys.stdout.write(DELETED_LINES)
    sys.stdout.write(DELETED_LINES)


def print_export_path(filename, reliable):
    """Show export path related to -o' option"""
    delete_lines(reliable=False) if reliable else delete_lines()
    if '-c' not in sys.argv:
        print(f"\n {args.output.upper()} {print_detail_s('[report]').lstrip()}\
 '{path.abspath(filename)}'.")


def print_nowarnings():
    """Show a message when no findings exist in analysis section"""
    if not args.output:
        print(f"{STYLE[10]}{get_detail(DIR_MSG[2])}{STYLE[5]}")
    else:
        print_detail(DIR_MSG[2])


def print_header(header):
    """Show header name (generic)"""
    print(f" {header}" if args.output else f"{STYLE[1]} {header}")


def print_fng_header(header):
    """Show header name for fingerprint findings"""
    if args.output:
        print(f" {header}")
    elif '[' in header:
        prefix, _, suffix = header.partition(' [')
        print(f"{STYLE[1]} {prefix}{STYLE[3]}{STYLE[5]} [{suffix}")
    else:
        print(f"{STYLE[1]} {header}")


def print_general_info(reliable, export_filename):
    """Show analysis information in the section '[0. Info]'"""
    if not args.output:
        delete_lines(reliable=False) if reliable else delete_lines()
        print(f"\n{BANNER}\n ({BANNER_VERSION})")
    elif args.output != 'pdf':
        humble_desc = get_detail('[humble_desc]', replace=True)
        print(f"\n\n{humble_desc}\n{BANNER_VERSION}\n")
    print_basic_info(export_filename)
    print_extended_info(args, reliable, status_code)


def print_basic_info(export_filename):
    print(linesep.join(['']*2) if args.output == 'html' or not args.output
          else "")
    print_detail_r('[0section]')
    print_detail_l('[analysis_date]')
    print(f" {current_time}")
    print(f'{URL_STRING[1]}{URL}')
    if args.user_agent not in (None, '', '0'):
        print(f"{get_detail('[ua_custom]', replace=True)} '{args.user_agent}'"
              f"{get_detail('[ua_custom2]', replace=True)}")
    if args.input_file:
        print(f"{get_detail('[input_filename]', replace=True)} \
{args.input_file}")
    if export_filename:
        print(f"{get_detail('[export_filename]', replace=True)} \
{export_filename}")
    validate_file_access(VALIDATE_FILE, context='basic')


def print_extended_info(args, reliable, status_code):
    if args.skip_headers:
        print_skipped_headers(args)
    if args.proxy:
        print_detail_l('[proxy_analysis_note]')
        print(f" {args.proxy}")
    if (status_code is not None and 400 <= status_code <= 451) or reliable or \
       args.redirects or args.skip_headers:
        print_extra_info(reliable)


def print_extra_info(reliable):
    if (status_code is not None and 400 <= status_code <= 451):
        id_mode = f'[http_{status_code}]'
        if detail := print_detail(id_mode, 0):
            print(detail)
        print(f"{URL_LIST[2]}{status_code}")
    if reliable:
        print(get_detail('[unreliable_analysis_note]', replace=True))
    if args.redirects:
        print(get_detail('[analysis_redirects_note]', replace=True))


def print_response_headers():
    """Show response headers relate to '-r' option"""
    print(linesep.join(['']*2))
    print_detail_r('[0headers]')
    if not headers:
        print_nosec_headers(enabled=False)
        print('\n')
        return
    pdf_style = STYLE[6] if args.output == 'pdf' else ""
    for key, value in sorted(headers.items()):
        print(f" {pdf_style}{key}:", value) if args.output else \
            print(f" {STYLE[2]}{key}:", value)
    print('\n')


def get_max_lnlength(section):
    """Calculate spacing for aligned message display"""
    sec_val = []
    max_secl = 0
    for i in section:
        sec_txt = get_detail(i)
        sec_val.append(sec_txt)
        max_secl = max(max_secl, len(sec_txt)+1)
    return max_secl


def get_analytics_length(section):
    basic_l = get_max_lnlength(section) - 1
    section_l = []
    for i in section:
        section_l_item = ' ' * (basic_l - len(get_detail(i)))
        section_l.append(section_l_item)
    return section_l


def print_details(short_d, long_d, id_mode, i_cnt):
    """Format and show localized messages"""
    print_detail_r(short_d, is_red=True)
    if not args.brief:
        print_detail(long_d, 2) if id_mode == 'd' else print_detail(long_d, 3)
    i_cnt[0] += 1
    return i_cnt


def print_detail(id_mode, num_lines=1):
    idx = l10n_main.index(id_mode + '\n')
    print(l10n_main[idx+1], end='')
    for i in range(1, num_lines+1):
        if idx+i+1 < len(l10n_main):
            print(l10n_main[idx+i+1], end='')


def print_detail_l(id_mode, analytics=False, no_headers=False):
    for idmode_ln, idnext_ln in zip(l10n_main, l10n_main[1:]):
        if idmode_ln.startswith(id_mode):
            if no_headers:
                print(idnext_ln, end='')
            elif not analytics:
                print(idnext_ln.replace('\n', ''), end='')
            else:
                return idnext_ln.replace('\n', '').replace(':', '')[1:]


def print_detail_r(id_mode, is_red=False):
    style_str = STYLE[1] if is_red else STYLE[0]
    for idmode_ln, idnext_ln in zip(l10n_main, l10n_main[1:]):
        if idmode_ln.startswith(id_mode):
            if not args.output:
                print(f"{style_str}{idnext_ln}", end='')
            else:
                print(idnext_ln, end='')
            if not is_red:
                print("")


def print_detail_s(id_mode, max_ln=False):
    for idmode_ln, idnext_ln in zip(l10n_main, l10n_main[1:]):
        if idmode_ln.startswith(id_mode):
            return f"\n{idnext_ln.rstrip()}" if max_ln else \
                f"\n{idnext_ln.strip()}"


def get_detail(id_mode, replace=False):
    for i, line in enumerate(l10n_main):
        if line.startswith(id_mode):
            return (l10n_main[i+1].replace('\n', '')) if replace else \
                l10n_main[i+1]


def print_error_detail(id_mode):
    print(f"\n{get_detail(id_mode, replace=True)}")
    sys.exit()


def get_epilog_content(id_mode):
    """Show examples and how to contribute, related to '-h' option"""
    epilog_file_path = path.join(OS_PATH, HUMBLE_DIRS[1], HUMBLE_FILES[5])
    with open(epilog_file_path, 'r', encoding='utf8') as epilog_source:
        epilog_lines = epilog_source.readlines()
        epilog_idx = epilog_lines.index(id_mode + '\n')
    return ''.join(epilog_lines[epilog_idx+1:epilog_idx+SLICE_INT[12]])


def get_fingerprint_headers():
    """Show findings in the section '[3. Fingerprint HTTP Response Headers]'"""
    with open(path.join(OS_PATH, HUMBLE_DIRS[0], HUMBLE_FILES[2]), 'r',
              encoding='utf8') as fng_source:
        l_fng_ex = [line.strip() for line in
                    islice(fng_source, SLICE_INT[0], None) if line.strip()]
        l_fng = [line.split(' (')[0].strip() for line in l_fng_ex]
        titled_fng = [item.title() for item in l_fng]
        return l_fng_ex, l_fng, titled_fng


def print_fingerprint_headers(headers_l, l_fng_ex, titled_fng):
    f_cnt = 0
    sorted_headers = sorted({header.title() for header in headers_l})
    for header in sorted_headers:
        if header in titled_fng:
            idx_fng = titled_fng.index(header)
            get_fingerprint_detail(header, headers, idx_fng, l_fng_ex, args)
            f_cnt += 1
    return f_cnt


def get_fingerprint_detail(header, headers, idx_fng, l_fng_ex, args):
    if not args.brief:
        print_fng_header(l_fng_ex[idx_fng])
        header_value = headers_l.get(header.lower()) if '-if' in sys.argv else\
            headers[header]
        if header_value:
            print(f" {get_detail('[fng_value]', replace=True)} \
'{header_value}'")
        else:
            print(get_detail('[empty_fng]', replace=True))
        print("")
    else:
        print_header(header)


def get_enabled_headers(args, headers_l, t_enabled):
    """Show findings in the section '[1. Enabled HTTP Security Headers]"""
    headers_d = {key.title(): value for key, value in headers_l.items()}
    t_enabled = sorted({header.title() for header in t_enabled})
    enabled_headers = [header for header in t_enabled if header in headers_d]
    for header in enabled_headers:
        exp_s = get_detail('[exp_header]', replace=True) if header.lower() in\
          EXP_HEADERS else ""
        print_enabled_headers(args, exp_s, header, headers_d)
    None if enabled_headers else print_nosec_headers()
    en_cnt = len(enabled_headers)
    print('\n')
    return en_cnt


def print_enabled_headers(args, exp_s, header, headers_d):
    prefix = STYLE[8] if args.output in ('html', 'pdf') else ''
    header_display = f"{prefix}{exp_s}{header}"
    if not args.output:
        header_display = f"{STYLE[7]}{header_display}{STYLE[5]}"[18:]
    output_str = f" {header_display}" if args.brief else f" {header_display}: \
{headers_d[header]}"
    print(output_str)


def print_nosec_headers(enabled=True):
    """Show a message if no header is enabled or if none was received"""
    id_mode = '[no_sec_headers]' if enabled else '[no_enb_headers]'
    if args.output:
        print_detail_l(id_mode, no_headers=True)
    else:
        print_detail_r(id_mode, is_red=True)


def print_missing_headers(args, headers_l, l_detail, l_miss):
    """Show findings in the section '[2. Missing HTTP Security Headers]'"""
    m_cnt = 0
    headers_set = set(headers_l)
    l_miss_set = {header.lower() for header in l_miss}
    skip_headers = [h.lower() for h in (args.skip_headers or [])]
    skip_missing = {header for header in skip_headers if header in l_miss_set}
    merged_set = headers_set | skip_missing
    xfo_skipped = 'x-frame-options' in skip_missing
    m_cnt = check_missing_headers(m_cnt, l_miss, l_detail, merged_set,
                                  xfo_skipped)
    m_cnt = check_frame_options(args, headers_l, l_miss, m_cnt, skip_headers)
    return m_cnt, skip_missing


def check_missing_headers(m_cnt, l_miss, l_detail, merged_set, xfo_skipped):
    for header, detail in zip(l_miss, l_detail):
        lower_header = header.lower()
        if lower_header not in merged_set and not xfo_skipped:
            print_header(
                f"{get_detail('[exp_header]', replace=True)}{header}"
                if lower_header in EXP_HEADERS else header)
            if not args.brief:
                print_detail(detail, 2)
            m_cnt += 1
    return m_cnt


def check_frame_options(args, headers_l, l_miss, m_cnt, skip_headers):
    xfo_needed = ('x-frame-options' not in skip_headers) and \
        ('x-frame-options' not in headers_l)
    fa_needed = 'frame-ancestors' not in \
        headers_l.get('content-security-policy', '')
    if xfo_needed and fa_needed:
        l_miss.append('X-Frame-Options')
        m_cnt += 1
        print_header('X-Frame-Options')
        if not args.brief:
            print_detail('[mxfo]', 2)
    return m_cnt


def print_empty_headers(headers, l_empty):
    """
    Show findings in the section '[5. Empty HTTP Response Headers Values]'"""
    e_cnt = 0
    for key in sorted(headers):
        if not headers[key]:
            l_empty.append(f"{key}")
            print_header(key.title())
            e_cnt += 1
    return e_cnt


def print_browser_compatibility(compat_headers):
    """
    Show references in the section '[6. Browser Compatibility for Enabled HTTP
    Security Headers]'
    """
    style_blanks = "  " if args.output == 'html' else " "
    for key in compat_headers:
        styled_header = key if args.output else f"{STYLE[2]}{key}{STYLE[5]}"
        csp_key = 'contentsecuritypolicy2' if key == 'Content-Security-Policy'\
            else key
        print(f"{style_blanks}{styled_header}{URL_LIST[0]}{csp_key}")


def check_input_traversal(user_input):
    """
    Check user input for path traversal patterns related to '-of' and '-op'
    options
    """
    input_traversal_ptrn = re.compile(RE_PATTERN[2])
    if input_traversal_ptrn.search(user_input):
        print(f"\n{get_detail('[args_input_traversal]', replace=True)}\
: ('{user_input}')")
        sys.exit()


def validate_path(output_path):
    """Validate permissions in the supplied path related to '-op' option"""
    try:
        with open(path.join(output_path, HUMBLE_FILES[1]), 'w'):
            pass
    except OSError as e:
        print(f"\n {get_detail('[args_pathe]', replace=True)} '{output_path}' \
({e.strerror})")
        sys.exit()
    else:
        remove(path.join(output_path, HUMBLE_FILES[1]))


def validate_file_access(target_path, *, context='history'):
    """
    Validate if the analysis history file and temporary export files can be
    created
    """
    try:
        with open(target_path, 'a+', encoding='utf8'):
            pass
    except OSError as e:
        err_type = type(e).__name__
        if context == 'history':
            return False, ("Not available",) * 6
        elif context == 'basic':
            print(f"{get_detail('[analysis_history_note]', replace=True)} \
({err_type})")
            return False, None
        elif context == 'export':
            delete_lines()
            print(f"\n{get_detail('[e_export_analysis]', replace=True)} "
                  f"({err_type}).")
            sys.exit()
    return True, None


def check_output_path(args, output_path):
    """Validations related to the supplied path in ‘-op’ option"""
    check_input_traversal(args.output_path)
    if args.output is None:
        print_error_detail('[args_nooutputfmt]')
    elif path.exists(output_path):
        validate_path(output_path)
    else:
        print(f"\n {get_detail('[args_noexportpath]', replace=True)} \
('{output_path}')")
        sys.exit()


def parse_user_agent(user_agent=False):
    """Select and validate the supplied user agent related to ‘-ua’ option"""
    if not user_agent:
        return get_user_agent('1')
    user_agent_id = sys.argv[sys.argv.index('-ua') + 1].lstrip('-ua')
    if not URL:
        nourl_user_agent(user_agent_id)
    else:
        return get_user_agent(user_agent_id)


def nourl_user_agent(user_agent_id):
    try:
        if user_agent_id == '0':
            return get_user_agent('0')
        print_error_detail('[args_useragent]')
    except ValueError:
        print_error_detail('[ua_invalid]')


def get_user_agent(user_agent_id):
    with open(path.join(OS_PATH, HUMBLE_DIRS[0], HUMBLE_FILES[6]), 'r',
              encoding='utf8') as ua_source:
        user_agents = [line.strip() for line in islice(ua_source, SLICE_INT[1],
                                                       None)]
    if user_agent_id == '0':
        print_user_agents(user_agents)
    for line in user_agents:
        if line.startswith(f"{user_agent_id}.-"):
            return line[4:].strip()
    print_error_detail('[ua_invalid]')
    sys.exit()


def print_user_agents(user_agents):
    print(f"\n{STYLE[0]}{get_detail('[ua_available]', replace=True)}\
{STYLE[4]}{get_detail('[ua_source]', replace=True)}\n")
    for line in user_agents:
        print(f' {line}')
    sys.exit()


def get_insecure_checks():
    """'-s' option: Skips some checks for the indicated headers"""
    headers_name = set()
    with open(path.join(OS_PATH, HUMBLE_DIRS[0], HUMBLE_FILES[7]), 'r') as \
            ins_source:
        insecure_checks = islice(ins_source, SLICE_INT[2], None)
        for line in insecure_checks:
            insecure_header = line.split(':')[0]
            headers_name.add(insecure_header.strip().lower())
    headers_sorted = sorted(headers_name)
    return {key: str(index + 1) for index, key in enumerate(headers_sorted)}


def get_skipped_unsupported_headers(args, insecure_headers):
    insecure_set = {ins_header.strip().lower() for ins_header in
                    args.skip_headers}
    skip_list = [insecure_headers[insecure_header] for insecure_header in
                 insecure_set if insecure_header in insecure_headers]
    unsupported_headers = list(insecure_set - set(insecure_headers.keys()))
    return unsupported_headers, skip_list


def print_skipped_headers(args):  # sourcery skip: use-fstring-for-formatting
    print_detail_l('[analysis_skipped_note]')
    print(" " + ", ".join("'{}'".format(h.title()) for h in
                          sorted(args.skip_headers, key=str.lower)) + ".")


def print_unsupported_headers(unsupported_headers):
    # sourcery skip: use-fstring-for-concatenation
    quoted = ", ".join("'" + h + "'" for h in unsupported_headers)
    print(f"\n {get_detail('[args_skipped_unknown]', replace=True)} \
({quoted})")
    sys.exit()


def check_output_format(args, final_filename, reliable, tmp_filename):
    """'-o' option: Export the analysis to the supplied format"""
    dispatch = {
        "txt": lambda: (
            args.cicd and print_cicd_totals(tmp_filename),
            print_export_path(tmp_filename, reliable),
            "-c" in sys.argv and check_owasp_compliance(tmp_filename),
        ),
        "csv": lambda: generate_csv(final_filename, tmp_filename),
        "json": lambda: (
            generate_json(final_filename, tmp_filename)
            if args.brief else
            generate_json_detailed(final_filename, tmp_filename)
        ),
        "xlsx": lambda: generate_csv(final_filename, tmp_filename,
                                     to_xlsx=True),
        "xml": lambda: generate_xml(final_filename, tmp_filename),
        "html": lambda: export_html_file(final_filename, tmp_filename),
        "pdf": lambda: export_pdf_file(tmp_filename),
    }
    if func := dispatch.get(args.output):
        func()


def print_cicd_totals(tmp_filename):
    """'-cicd' option: Summary-only JSON analysis for CI/CD"""
    try:
        with open(tmp_filename, 'r', encoding='utf-8') as txt_source:
            lines = [line.strip() for line in txt_source if line.strip()]
        (cicd_total_t, cicd_diff_t, cicd_info_t) = get_cicd_labels()
        cicd_info_lines, cicd_total_lines = parse_cicd_sections(cicd_diff_t,
                                                                cicd_total_t,
                                                                lines)
        cicd_info_dict = {
            k.strip(): v.strip()
            for k, v in (line.split(":", 1) for line in cicd_info_lines)
        }
        cicd_output = {cicd_info_t: cicd_info_dict, **cicd_total_lines}
        print(dumps(cicd_output, indent=2, ensure_ascii=False))
        sys.exit()
    except Exception as e:
        print(dumps({get_detail('[cicd_error]', replace=True): str(e)},
                    ensure_ascii=False))
        sys.exit()


def parse_cicd_sections(cicd_diff_t, cicd_total_t, lines):
    cicd_info_start = lines.index(next(line for line in lines if
                                       BOLD_STRINGS[0] in line))
    cicd_info_lines = lines[cicd_info_start + 1:cicd_info_start + 4]
    cicd_totals_start = lines.index(next(line for line in lines if
                                         BOLD_STRINGS[8] in line))
    cicd_totals_lines = lines[cicd_totals_start + 2:-3]
    cicdi_grade_lines = lines[cicd_totals_start + 8]
    line_pattern = re.compile(RE_PATTERN[21])
    cicd_totals_result = parse_cicd_totals(cicd_totals_lines, cicd_total_t,
                                           cicd_diff_t, line_pattern)
    cicd_totals_result[get_detail('[cicd_grade]', replace=True)] = (
        {get_detail('[cicd_grade_note]', replace=True):
         cicdi_grade_lines.split(":", 1)[1].strip()}
    )
    return cicd_info_lines, cicd_totals_result


def parse_cicd_totals(cicd_totals_lines, cicd_total_t, cicd_diff_t, pattern):
    return {
        k: v for line in cicd_totals_lines
        if (processed := parse_cicd_lines(line, pattern, cicd_total_t,
                                          cicd_diff_t))
        for k, v in [processed]}


def get_cicd_labels():
    cidcd_labels = ['[cicd_total]', '[cicd_diff]', '[cicd_info]']
    return tuple(get_detail(label, replace=True) for label in cidcd_labels)


def parse_cicd_lines(line, pattern, cicd_total_t, cicd_diff_t):
    if match := pattern.match(line):
        key = match[1].strip()
        cicd_total_v = int(match[2])
        cicd_diff_v = match[3].strip()
        return key, {cicd_total_t: cicd_total_v, cicd_diff_t: cicd_diff_v}
    return None


def generate_csv(final_filename, temp_filename, to_xlsx=False):
    """'-o csv' option: CSV export of the analysis"""
    with open(temp_filename, 'r', encoding='utf8') as txt_source, \
         open(final_filename, 'w', newline='', encoding='utf8') as csv_final:
        csv_writer = writer(csv_final, quoting=QUOTE_ALL)
        csv_writer.writerow([get_detail('[csv_section]', replace=True),
                             get_detail('[csv_values]', replace=True)])
        csv_writer.writerow([get_detail('[0section]', replace=True),
                             f"{get_detail('[json_gen]', replace=True)}: \
{BANNER_VERSION}"])
        csv_section = [get_detail(f'[{i}]', replace=True) for i in CSV_SECTION]
        parse_csv(csv_section, txt_source.read(), csv_writer)
    if to_xlsx:
        generate_xlsx(final_filename, temp_filename)
    print_export_path(final_filename, reliable)
    remove(temp_filename)
    sys.exit()


def parse_csv(csv_section, csv_source, csv_writer):
    for i in (item for item in csv_section if item in csv_source):
        csv_content = csv_source.split(i)[1].split('[')[0]
        info_list = [line.strip() for line in csv_content.split('\n') if
                     line.strip()]
        for csv_ln in info_list:
            clean_ln = ": ".join([part.strip() for part in csv_ln.split(":",
                                                                        1)])
            csv_writer.writerow([i, clean_ln])


def generate_xlsx(final_filename, temp_filename):
    """'-o xlsx' option: XLSX spreadsheet export of the analysis"""
    # Tiny optimization, lazy-loading third-party xlsxwriter
    from xlsxwriter import Workbook
    workbook = Workbook(final_filename, {'in_memory': True})
    set_xlsx_metadata(workbook)
    set_xlsx_content(final_filename, workbook)
    workbook.close()
    print_export_path(final_filename, reliable)
    remove(temp_filename)
    sys.exit()


def set_xlsx_metadata(workbook):
    workbook.set_properties({
        'author': BANNER_VERSION,
        'category': get_detail(METADATA_S[1], replace=True),
        'keywords': get_detail(METADATA_S[0], replace=True),
        'subject': get_detail(METADATA_S[1], replace=True),
        'title': f"{get_detail('[pdf_meta_title]', replace=True)} {URL}",
        'comments': f"{get_detail('[excel_meta_generated]', replace=True)} \
{BANNER_VERSION}",
    })


def set_xlsx_content(final_filename, workbook):
    worksheet = workbook.add_worksheet(get_detail(METADATA_S[1], replace=True))
    bold_fmt = workbook.add_format({'bold': True, 'text_wrap': True,
                                    'align': 'center', 'valign': 'vcenter'})
    cell_fmt = workbook.add_format({'text_wrap': True, 'valign': 'top'})
    hidden_fmt = workbook.add_format({'font_color': '#FFFFFF',
                                      'text_wrap': True, 'valign': 'top'})
    col_wd = {}
    set_xlsx_format(bold_fmt, cell_fmt, col_wd, final_filename, hidden_fmt,
                    worksheet)
    set_xlsx_width(col_wd, worksheet)
    worksheet.autofilter(0, 0, 0, 1)


def set_xlsx_format(bold_fmt, cell_fmt, col_wd, final_filename, hidden_fmt,
                    worksheet):
    prev_section = None
    with open(final_filename, 'r', encoding='utf-8', newline='') as csv_final:
        for row_index, row_data in enumerate(reader(csv_final)):
            for col_index, cell_value in enumerate(row_data):
                fmt, prev_section = choose_xlsx_format(bold_fmt, cell_fmt,
                                                       cell_value, col_index,
                                                       hidden_fmt, row_index,
                                                       prev_section)
                worksheet.write(row_index, col_index, cell_value, fmt)
                col_wd[col_index] = max(col_wd.get(col_index, 0),
                                        len(cell_value))


def choose_xlsx_format(bold_fmt, cell_fmt, cell_value, col_index, hidden_fmt,
                       row_index, prev_section):
    if row_index == 0 and col_index in (0, 1):
        return bold_fmt, prev_section
    if col_index == 0 and row_index > 0:
        return (hidden_fmt, prev_section) if cell_value == prev_section \
            else (cell_fmt, cell_value)
    return cell_fmt, prev_section


def set_xlsx_width(col_wd, worksheet):
    col_a_width = col_wd.get(0, 0)
    col_b_width = col_wd.get(1, 0) + 2
    adjusted_b_width = max(col_b_width, col_a_width * 2)
    for col_idx, width in col_wd.items():
        if col_idx == 0:
            worksheet.set_column(col_idx, col_idx, col_a_width)
        elif col_idx == 1:
            worksheet.set_column(col_idx, col_idx, min(adjusted_b_width, 100))
        else:
            worksheet.set_column(col_idx, col_idx, min(width + 2, 50))


def generate_json(final_filename, temp_filename):
    """'-o json -b' options: JSON export for a brief analysis"""
    section0, sectionh, section5, section6 = (
        get_detail(f'[{i}]', replace=True) for i in JSON_SECTION)
    with open(temp_filename, 'r', encoding='utf8') as txt_file, \
         open(final_filename, 'w', encoding='utf8') as json_file:
        txt_sections = re.split(RE_PATTERN[5], txt_file.read())[1:]
        data = {}
        parse_json(data, section0, section5, section6, sectionh, txt_sections)
        dump(data, json_file, indent=4, ensure_ascii=False)
    print_export_path(final_filename, reliable)
    remove(temp_filename)
    sys.exit()


def parse_json(data, section0, section5, section6, sectionh, txt_sections):
    for i in range(0, len(txt_sections), 2):
        json_section = f'[{txt_sections[i]}]'
        json_lns = [line.strip() for line in txt_sections[i + 1].split('\n')
                    if line.strip()]
        json_data = write_json(json_lns, json_section, section0, section5,
                               section6, sectionh)
        data[json_section] = json_data


def write_json(json_lns, json_section, section0, section5, section6, sectionh):
    if json_section in (section0, section5, section6, sectionh):
        json_data = {}
        format_json(json_data, json_lns)
        if json_section == section0:
            json_data = {get_detail('[json_gen]', replace=True):
                         BANNER_VERSION, **json_data}
    else:
        json_data = list(json_lns)
    return json_data


def format_json(json_data, json_lns):
    for line in json_lns:
        if ':' in line:
            key, value = (part.strip() for part in line.split(':', 1))
            if key in json_data:
                if isinstance(json_data[key], list):
                    json_data[key].append(value)
                else:
                    json_data[key] = [json_data[key], value]
            else:
                json_data[key] = value
    return json_data


def json_detailed_sources(file_idx, slice_idx):
    """'-o json' option: JSON export for a detailed analysis"""
    file_path = path.join(OS_PATH, HUMBLE_DIRS[0], HUMBLE_FILES[file_idx])
    with open(file_path, 'r', encoding='utf8') as f:
        return {line.strip() for line in islice(f, SLICE_INT[slice_idx],
                                                None) if line.strip()}


def generate_json_detailed(final_filename, temp_filename):
    with open(temp_filename, 'r', encoding='utf8') as txt_file, \
         open(final_filename, 'w', encoding='utf8') as json_file:
        txt_sections = re.split(RE_PATTERN[5], txt_file.read())[1:]
        data = {}
        json_detailed_parse(data, txt_sections)
        dump(data, json_file, indent=4, ensure_ascii=False)
    print_export_path(final_filename, reliable)
    remove(temp_filename)
    sys.exit()


def json_detailed_parse(data, txt_sections):
    params = ['[json_det_fngheader]', '[json_det_details]', '[json_det_refs]']
    details = [get_detail(p, replace=True) for p in params]
    for i in range(0, len(txt_sections), 2):
        section = f'[{txt_sections[i]}]'
        lines = [line.strip() for line in txt_sections[i + 1].split('\n')
                 if line.strip()]
        data[section] = json_detailed_write(
            lines, section, *details
        )


def json_detailed_write(json_lns, json_section, json_miss_h, json_miss_d,
                        json_miss_r):
    json_conditions = {
        BOLD_STRINGS[0]:
            lambda: json_detailed_info(json_lns),
        (f'[{BOLD_STRINGS[1]}', BOLD_STRINGS[9]):
            lambda: json_detailed_response(json_lns),
        BOLD_STRINGS[2]:
            lambda: json_detailed_format(json_lns),
        BOLD_STRINGS[3]:
            lambda: json_detailed_miss(json_lns, l_miss, json_miss_h,
                                       json_miss_d, json_miss_r),
        BOLD_STRINGS[4]:
            lambda: json_detailed_fng(
                json_lns, json_detailed_sources(2, 0)),
        BOLD_STRINGS[5]:
            lambda: json_detailed_ins(
                json_lns, json_detailed_sources(7, 2)),
        BOLD_STRINGS[6]:
            lambda: json_detailed_empty(json_lns),
        BOLD_STRINGS[7]:
            lambda: json_detailed_format(json_lns, is_compat=True,
                                         is_l10n=True),
        BOLD_STRINGS[8]:
            lambda: json_detailed_results(json_lns),
    }
    return next(
        (condition()
         for prefix, condition in json_conditions.items()
         if json_section.startswith(prefix)),
        list(json_lns),
    )


def json_detailed_empty(json_lns):
    desc_key = get_detail('[json_det_empty]', replace=True)
    status_key = get_detail('[json_det_empty_s]', replace=True)
    empty_key = get_detail('[json_det_empty_h]', replace=True)
    lines = [line.strip() for line in json_lns if line.strip()]
    result = {desc_key: lines[0][:-1]}
    if e_cnt == 0:
        result[status_key] = lines[1]
    else:
        result[empty_key] = l_empty
    return result


def json_detailed_info(json_lns):
    info = {get_detail('[json_gen]', replace=True): BANNER_VERSION}
    for line in json_lns:
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip()
        info[key] = value.strip()
    return info


def json_detailed_response(json_lns):
    header_key = get_detail('[json_det_fngheader]', replace=True)
    value_key = get_detail('[json_det_fngval]', replace=True)
    result = []
    for line in json_lns:
        line = line.strip()
        if not line or ':' not in line:
            continue
        header, value = line.split(':', 1)
        result.append({
            header_key: header.strip(),
            value_key: value.strip()
        })
    return result


def json_detailed_format_add(json_lns, header_t, value_t):
    result = []
    for line in map(str.strip, json_lns):
        if not line:
            continue
        if line.startswith("(*)") or ":" in line:
            key, value = line.split(":", 1)
            result.append({header_t: key.strip(), value_t: value.strip()})
        else:
            result.append({header_t: line, value_t: ""})
    return result


def json_detailed_format(json_lns, is_compat=False, is_l10n=False):
    l10n_txt = '[json_det_refs]' if is_l10n else '[json_det_fngval]'
    header_t = get_detail('[json_det_fngheader]', replace=True)
    value_t = get_detail(l10n_txt, replace=True)
    if is_compat:
        value_t = value_t[:-1]
    return json_detailed_format_add(json_lns, header_t, value_t)


def json_detailed_miss_process(line, l_miss, json_miss_h, json_miss_d,
                               json_miss_r, json_det_mref, result, entry,
                               current_header):
    if line in l_miss or line.startswith('(*)'):
        if entry:
            result.append(entry)
        return {json_miss_h: line, json_miss_d: [], json_miss_r: []}, line
    if line.startswith(json_det_mref) and current_header:
        entry[json_miss_r].append(line.replace(json_det_mref, "").strip())
    elif current_header:
        entry[json_miss_d].append(line)
    return entry, current_header


def json_detailed_miss_add(json_lns, l_miss, json_miss_h, json_miss_d,
                           json_miss_r, json_det_mref):
    result, entry, current_header = [], {}, None
    for line in json_lns:
        if line := line.strip():
            entry, current_header = json_detailed_miss_process(
                line, l_miss, json_miss_h, json_miss_d, json_miss_r,
                json_det_mref, result, entry, current_header
            )
    if entry:
        result.append(entry)
    return result


def json_detailed_miss(json_lns, l_miss, json_miss_h, json_miss_d,
                       json_miss_r):
    json_det_mref = PDF_CONDITIONS[0]
    result = json_detailed_miss_add(
        json_lns, l_miss, json_miss_h, json_miss_d, json_miss_r,
        json_det_mref
    )
    for e in result:
        if len(e[json_miss_d]) == 1:
            e[json_miss_d] = e[json_miss_d][0]
    return result


def json_detailed_fng_process(line, fingerprint_set, entry, current_header,
                              fng_header, fng_val):
    line_s = line.strip()
    for f in fingerprint_set:
        if line_s.startswith(f):
            return {fng_header: f}, f
    if current_header and line_s.startswith(fng_val):
        entry[fng_val] = line_s.split(": ", 1)[1].strip("'\" ")
        return entry, current_header
    return entry, current_header


def json_detailed_fng(json_lns, fingerprint_set):
    result, entry, current_header = [], {}, None
    fng_header = get_detail('[json_det_fngheader]', replace=True)
    fng_val = get_detail('[json_det_fngval]', replace=True)
    for line in json_lns:
        new_entry, current_header = json_detailed_fng_process(
            line, fingerprint_set, entry, current_header, fng_header, fng_val)
        if new_entry != entry:
            if entry:
                result.append(entry)
            entry = new_entry
    if entry:
        result.append(entry)
    return result


def json_detailed_ins_append(line, ref_t, ref_o, entry, header, header_t,
                             detail_t, result, is_header):
    if is_header:
        if entry:
            result.append(entry)
        header = line
        entry = {header_t: header, detail_t: [], ref_t: []}
    elif header:
        if line.startswith(ref_o):
            entry[ref_t].append(line[len(ref_o):].strip())
        else:
            entry[detail_t].append(line)
    return entry, header


def json_detailed_ins_headers(line, line_s, checks_list, ref_t):
    header_cond = line.startswith('(*)')
    header_cond2 = not line.startswith(ref_t)
    header_cond3 = any(
        (val and key in line and val in line)
        or (not val and line_s.startswith(key))
        for key, val in checks_list
    )
    return header_cond or (header_cond2 and header_cond3)


def json_detailed_ins_process(json_lns, checks_list, ref_t, ref_o, header_t,
                              detail_t):
    result, entry, header = [], {}, None
    for line in json_lns:
        if line := line.strip():
            line_s = line.strip()
            is_header = json_detailed_ins_headers(
                line, line_s, checks_list, ref_t
            )
            entry, header = json_detailed_ins_append(
                line, ref_t, ref_o, entry, header, header_t,
                detail_t, result, is_header
            )
    if entry:
        result.append(entry)
    return result


def json_detailed_ins(json_lns, insecure_checks):
    header_t, detail_t, ref_t = (get_detail(text, replace=True)
                                 for text in [
        '[json_det_inscheck]', '[json_det_details]', '[json_det_refs]'])
    if args.lang:
        insecure_checks = {check.split(": ")[0] + ":"
                           for check in insecure_checks}
    checks_list = []
    json_detailed_ins_checks(checks_list, insecure_checks)
    return json_detailed_ins_process(
        json_lns, checks_list, ref_t, PDF_CONDITIONS[0], header_t, detail_t
    )


def json_detailed_ins_checks(checks_list, insecure_checks):
    for check in insecure_checks:
        check_s = check.strip()
        if ':' in check_s:
            key, val = check_s.split(':', 1)
            checks_list.append((key.strip(), val.strip()))
        elif '(' in check_s and ')' in check_s:
            key, val = check_s.split('(', 1)
            val = val.rstrip(')')
            checks_list.append((key.strip(), val.strip()))
        else:
            checks_list.append((check_s, None))


def json_detailed_results(json_lns):
    result = {}
    duration_t = get_detail('[analysis_time]', replace=True)
    duration_key = get_detail('[json_det_analysis]', replace=True)
    for line in json_lns:
        line = line.strip()
        if not line:
            continue
        if line.startswith(duration_t.strip()):
            result[duration_key] = line
        elif ':' in line:
            key, value = line.split(':', 1)
            result[key.strip()] = value.strip()
    return result


def export_pdf_file(tmp_filename):
    """'-o pdf' option: PDF export of the analysis"""
    # Important optimization, lazy-loading third-party fpdf2
    from fpdf import FPDF, YPos as ypos  # type: ignore

    class PDF(FPDF):

        def header(self):
            self.set_font('Courier', 'B', 9)
            self.set_y(10)
            self.set_text_color(0, 0, 0)
            self.cell(0, 5, get_detail('[humble_desc]'), new_x="CENTER",
                      new_y="NEXT", align='C')
            self.ln(1)
            self.cell(0, 5, BANNER_VERSION, align='C')
            self.ln(9 if self.page_no() == 1 else 13)

        def footer(self):
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(0, 0, 0)
            self.cell(0, 10, f"{print_detail_s('[pdf_footer]')} \
{self.page_no()}{get_detail('[pdf_footer2]')} {{nb}}", align='C')

    pdf = PDF()
    initialize_pdf(pdf, tmp_filename, ypos)


def initialize_pdf(pdf, tmp_filename, ypos):
    pdf_links = (URL_STRING[1], REF_LINKS[2], REF_LINKS[3], URL_LIST[0],
                 REF_LINKS[4])
    pdf_prefixes = {REF_LINKS[2]: REF_LINKS[0], REF_LINKS[3]: REF_LINKS[1]}
    generate_pdf(pdf, tmp_filename, pdf_links, pdf_prefixes, ypos)


def generate_pdf(pdf, tmp_filename, pdf_links, pdf_prefixes, ypos):
    set_pdf_file(pdf)
    ok_string = get_detail(DIR_MSG[2]).rstrip()
    no_headers = [get_detail(f'[{i}]').strip() for i in ['no_sec_headers',
                                                         'no_enb_headers']]
    set_pdf_content(tmp_filename, ok_string, no_headers, pdf, pdf_links,
                    pdf_prefixes, ypos)
    pdf.output(final_filename)
    print_export_path(final_filename, reliable)
    remove(tmp_filename)
    sys.exit()


def set_pdf_file(pdf):
    pdf.alias_nb_pages()
    set_pdf_metadata(pdf)
    pdf.set_display_mode(zoom=125)
    pdf.add_page()
    pdf.set_font("Courier", size=9)


def set_pdf_metadata(pdf):
    title = f"{get_detail('[pdf_meta_title]', replace=True)} {URL}"
    git_urlc = BANNER_VERSION
    pdf.set_author(git_urlc)
    pdf.set_creation_date = current_time
    pdf.set_creator(git_urlc)
    pdf.set_keywords(get_detail(METADATA_S[0], replace=True))
    pdf.set_lang(get_detail('[pdf_meta_language]'))
    pdf.set_subject(get_detail(METADATA_S[1], replace=True))
    pdf.set_title(title)
    pdf.set_producer(git_urlc)


def set_pdf_content(tmp_filename, ok_string, no_headers, pdf, pdf_links,
                    pdf_prefixes, ypos):
    with open(tmp_filename, 'r', encoding='utf8') as txt_source:
        for line in txt_source:
            if any(no_header in line for no_header in no_headers):
                set_pdf_warnings(line, pdf, ypos)
                continue
            if '[' in line:
                set_pdf_sections(line, pdf)
            if set_pdf_format(line, ok_string, pdf, pdf_links, pdf_prefixes,
                              ypos):
                continue


def set_pdf_format(line, ok_string, pdf, pdf_links, pdf_prefixes, ypos):
    if any(bold_str in line for bold_str in BOLD_STRINGS):
        pdf.set_font(style='B')
    else:
        pdf.set_font(style='')
    next((format_pdf_links(line, string, pdf, pdf_prefixes) for string in
          pdf_links if string in line), None)
    if set_pdf_conditions(line, pdf, ypos):
        return True
    elif ok_string in line:
        set_pdf_nowarnings(line, pdf, ypos)
        return True
    pdf.set_text_color(255, 0, 0)
    if set_pdf_empty(l_empty, line, pdf, ypos):
        return True
    format_pdf_lines(line, pdf, ypos)


def set_pdf_sections(line, pdf):
    for section in PDF_SECTION:
        if line.startswith(section):
            pdf.start_section(get_detail(PDF_SECTION[section]))
            break


def set_pdf_conditions(line, pdf, ypos):
    combined_h = l_miss + l_ins + l_fng + titled_fng
    return (
        all(condition not in line for condition in PDF_CONDITIONS[:3]) and
        (PDF_CONDITIONS[3] in line or any(item in line for item in combined_h))
        and set_pdf_warnings(line, pdf, ypos))


def format_pdf_links(i, pdf_string, pdf, pdf_prefixes):
    pdf_link = set_pdf_links(i, pdf_string)
    if pdf_string in (URL_STRING[1], REF_LINKS[2], REF_LINKS[3]):
        pdf_prefix = pdf_prefixes.get(pdf_string, pdf_string)
        pdf.write(h=6, text=pdf_prefix)
    else:
        pdf.write(h=6, text=i[:i.index(": ")+2])
    pdf.set_text_color(0, 0, 255)
    pdf.cell(w=2000, h=6, text=i[i.index(": ")+2:], align="L", link=pdf_link)


def set_pdf_warnings(line, pdf, ypos):
    if STYLE[8] not in line:
        pdf.set_text_color(255, 0, 0)
        pdf.multi_cell(197, 6, text=line, align='L', new_y=ypos.LAST)
        return True


def set_pdf_nowarnings(line, pdf, ypos):
    pdf.set_text_color(0, 128, 0)
    pdf.multi_cell(197, 6, text=line, align='L', new_y=ypos.LAST)


def set_pdf_empty(l_empty, line, pdf, ypos):
    ln_strip = line.lstrip().lower()
    if any(i in ln_strip for i in l_empty) and ('[' not in ln_strip and ':'
                                                not in ln_strip):
        pdf.set_text_color(255, 0, 0)
        pdf.multi_cell(197, 6, text=line, align='L', new_y=ypos.LAST)
        return True
    return False


def set_pdf_links(i, pdf_string):
    pdf_links_d = {URL_STRING[1]: URL,
                   REF_LINKS[2]: i.partition(REF_LINKS[2])[2].strip(),
                   REF_LINKS[3]: i.partition(REF_LINKS[3])[2].strip(),
                   REF_LINKS[4]: i.partition(REF_LINKS[4])[2].strip(),
                   URL_LIST[0]: i.partition(': ')[2].strip()}
    return pdf_links_d.get(pdf_string)


def format_pdf_lines(line, pdf, ypos):
    if len(line) > 101:
        chunks = [line[i:i + 101] for i in range(0, len(line), 101)]
        set_pdf_chunks(chunks, pdf)
        pdf.ln(h=2)
        return
    if re.search(RE_PATTERN[10], line):
        color_pdf_line(line[19:], PDF_COLORS[0], PDF_COLORS[1], None, None,
                       pdf)
        return
    if re.search(RE_PATTERN[7], line):
        color_pdf_line(line[19:], PDF_COLORS[2], PDF_COLORS[1], None, None,
                       pdf)
        return
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(197, 6, text=line, align='L', new_y=ypos.LAST)


def set_pdf_chunks(chunks, pdf):
    chunk_c = None
    for i, chunk in enumerate(chunks):
        if re.search(RE_PATTERN[10], chunk):
            chunk_c = color_pdf_line(chunk[19:], PDF_COLORS[0], PDF_COLORS[1],
                                     chunks, i, pdf)
        elif re.search(RE_PATTERN[7], chunk):
            chunk_c = color_pdf_line(chunk[19:], PDF_COLORS[2], PDF_COLORS[1],
                                     chunks, i, pdf)
        else:
            format_pdf_chunks(chunk, chunks, chunk_c, i, pdf)


def format_pdf_chunks(chunk, chunks, chunk_c, i, pdf):
    pdf.set_text_color(0, 0, 0)
    if i > 0:
        chunk = f' {chunk}'
    y = pdf.get_y()
    if chunk_c != PDF_COLORS[2]:
        if i == 1 and len(chunks) >= 2:
            y -= 1
        elif len(chunks) == 1:
            y -= 0.5
        pdf.set_y(y)
    pdf.cell(104, 6, text=chunk, align='L')
    pdf.ln(h=6)


def color_pdf_line(line, hcolor, vcolor, chunks, i, pdf):
    colon_idx = line.find(': ')
    ln_final = apply_pdf_color(colon_idx, hcolor, line, vcolor)
    pdf.write_html(ln_final)
    return hcolor if chunks and len(chunks) == 2 and i == 0 else None


def apply_pdf_color(colon_idx, hcolor, line, vcolor):
    if colon_idx == -1:
        return f'{HTML_TAGS[16]}{hcolor}">{line}{HTML_TAGS[17]}'
    return (
        f'{HTML_TAGS[16]}{hcolor}">{line[:colon_idx + 2]}{HTML_TAGS[18]}'
        f'{HTML_TAGS[19]}{vcolor}">{line[colon_idx + 2:]}{HTML_TAGS[17]}'
    )


def export_html_file(final_filename, tmp_filename):
    """'-o html' option: HTML export of the analysis"""
    global inside_section
    inside_section = False
    generate_html()
    clean_html_source(tmp_filename)
    ok_string = get_detail(DIR_MSG[2]).rstrip()
    ko_strings = [get_detail(f'[{i}]').rstrip() for i in ['no_sec_headers',
                                                          'no_enb_headers']]
    with open(tmp_filename, 'r', encoding='utf8') as html_source, \
            open(final_filename, 'a', encoding='utf8') as html_final:
        for ln in html_source:
            format_html_file(html_final, ko_strings, ln, ok_string)
        if inside_section:
            html_final.write(HTML_TAGS[12])
            inside_section = False
        html_final.write(HTML_TAGS[13])
    clean_html_final(final_filename)
    print_export_path(final_filename, reliable)
    remove(tmp_filename)
    sys.exit()


def generate_html():
    copyfile(path.join(OS_PATH, HUMBLE_DIRS[0], HUMBLE_FILES[8]),
             final_filename)
    html_replace = {"html_title": get_detail(METADATA_S[1]),
                    "html_desc": get_detail('[pdf_meta_title]'),
                    "html_keywords": get_detail(METADATA_S[0]),
                    "humble_URL": URL_LIST[4],
                    "humble_local_v": local_version, "URL_analyzed": URL,
                    "html_body": '<body><pre>', "}}": '}', "{{": '}'}
    with open(final_filename, 'r+', encoding='utf8') as html_file:
        temp_html_content = html_file.read()
        replaced_html = temp_html_content.format(**html_replace)
        html_file.seek(0)
        html_file.write(replaced_html)


def clean_html_source(tmp_filename):
    with open(tmp_filename, "r+", encoding="utf8") as html_source:
        html_lines = html_source.readlines()
        initial_ln, prev_blank_ln = False, False
        cleaned_ln = []
        for line in html_lines:
            if not initial_ln and "[0. Info" in line:
                initial_ln = True
            if initial_ln and not line.strip() and prev_blank_ln:
                continue
            prev_blank_ln = initial_ln and not line.strip()
            cleaned_ln.append(line)
        html_source.seek(0)
        html_source.writelines(cleaned_ln)
        html_source.truncate()


def format_html_file(html_final, ko_strings, ln, ok_string):
    ln_formatted = format_html_lines(html_final, ko_strings, ln, ok_string)
    if not ln_formatted:
        format_html_rest(html_final, l_empty, ln)


def format_html_lines(html_final, ko_strings, ln, ok_string):
    lang_slice = SLICE_INT[6] if args.lang else SLICE_INT[7]
    ln_rstrip = ln.rstrip('\n')
    return (format_html_info(html_final, ln_rstrip)
            or format_html_bold(html_final, ln_rstrip)
            or format_html_warnings(html_final, ko_strings, ln_rstrip,
                                    ok_string)
            or format_html_references(html_final, lang_slice, ln_rstrip)
            or format_html_compatibility(html_final, ln_rstrip))


def format_html_info(html_final, ln_rstrip):
    if URL_STRING[0] in ln_rstrip:
        html_final.write(
            f"{HTML_TAGS[1]}{ln_rstrip[:32]}{HTML_TAGS[2]}"
            f"{ln_rstrip[:32]}{HTML_TAGS[0]}{ln_rstrip[32:]}"
        )
        return True
    if URL_STRING[1] in ln_rstrip:
        html_final.write(
            f"{ln_rstrip[:8]}{HTML_TAGS[1]}{ln_rstrip[8:]}"
            f"{HTML_TAGS[2]}{ln_rstrip[8:]}{HTML_TAGS[0]}{HTML_TAGS[11]}"
        )
        return True
    return False


def format_html_warnings(html_final, ko_strings, ln_rstrip, ok_string):
    if ok_string in ln_rstrip:
        html_final.write(f'{HTML_TAGS[6]}{ln_rstrip}{HTML_TAGS[5]}\
{HTML_TAGS[11]}')
        return True
    if any(ko in ln_rstrip for ko in ko_strings):
        html_final.write(f"{HTML_TAGS[3]}{ln_rstrip}{HTML_TAGS[5]}\
                         {HTML_TAGS[11]}")
        return True
    return False


def format_html_references(html_final, lang_slice, ln_rstrip):
    for ref, off in [(REF_LINKS[1], 6), (REF_LINKS[0], 8), (REF_LINKS[4],
                                                            lang_slice)]:
        if ref in ln_rstrip:
            content = ln_rstrip[off:].strip()
            html_final.write(
                f"{ln_rstrip[:off]}{HTML_TAGS[1]}{content}"
                f"{HTML_TAGS[2]}{content}{HTML_TAGS[0]}{HTML_TAGS[11]}"
            )
            return True
    return False


def format_html_compatibility(html_final, ln_rstrip):
    if URL_STRING[2] not in ln_rstrip:
        return False
    prefix, _, link = ln_rstrip.partition(': ')
    html_final.write(
        f"{HTML_TAGS[4]}{prefix[1:]}: {HTML_TAGS[5]}"
        f"{HTML_TAGS[1]}{link}{HTML_TAGS[2]}{link}{HTML_TAGS[0]}\
{HTML_TAGS[11]}")
    return True


def format_html_bold(html_final, ln_rstrip):
    global inside_section
    if any(s in ln_rstrip for s in BOLD_STRINGS):
        if inside_section:
            html_final.write(HTML_TAGS[12])
        html_final.write(f'{HTML_TAGS[7]}{ln_rstrip}{HTML_TAGS[8]}')
        inside_section = True
        return True
    return False


def format_html_headers(ln):
    for header in headers:
        header_str = f"{header}: "
        if header_str in ln:
            header_pos = ln.index(":")
            ln = ln.replace(ln[:header_pos], f"{HTML_TAGS[4]}{ln[:header_pos]}\
{HTML_TAGS[5]}", 1)
            ln = format_html_csp(ln)
    return ln


def format_html_csp(ln):
    csp_value = next((v for k, v in headers.items() if k.lower() ==
                      "content-security-policy"), None)
    if not csp_value:
        return ln
    for directive in t_csp_dirs:
        pattern = RE_PATTERN[16].format(dir=re.escape(directive))
        ln = re.sub(pattern, lambda m: f"{m.group(1)}{HTML_TAGS[14]}\
{m.group(2)}{HTML_TAGS[15]}{m.group(3)}", ln)
    return ln


def format_html_fingerprint(args, ln, l_fng):
    ln_cf = ln.casefold() if args.brief else ln
    for i in l_fng:
        i_match = i.casefold() if args.brief else i
        if i_match in ln_cf and ':' not in ln and HTML_TAGS[9] not in ln and \
           HTML_TAGS[10] not in ln:
            return f"{HTML_TAGS[3]}{ln}{HTML_TAGS[5]}"
    return ln


def format_html_totals(ln, l_total):
    for i in l_total:
        if (not re.search(RE_PATTERN[11], ln)) and (
             (i in ln) and ('"' not in ln) or ('HTTP (' in ln)):
            ln = ln.replace(ln, HTML_TAGS[3] + ln + HTML_TAGS[5])
    return ln


def format_html_empty(ln, ln_rstrip, l_empty):
    ln_strip = ln_rstrip.lstrip().lower()
    for i in l_empty:
        if (i in ln_strip and '[' not in ln_strip and ':' not in ln_strip):
            ln = f"{HTML_TAGS[3]}{ln}{HTML_TAGS[5]}"
    return ln


def format_html_rest(html_final, l_empty, ln):
    l_total = sorted(set(l_miss + l_ins))
    ln, ln_enabled = format_html_enabled(ln, html_final)
    ln_rstrip = ln.rstrip('\n')
    if ln and not ln_enabled:
        ln = format_html_headers(ln)
        ln = format_html_fingerprint(args, ln, sorted(l_fng))
        ln = format_html_totals(ln, l_total)
        ln = format_html_empty(ln, ln_rstrip, l_empty)
        html_final.write(ln)


def format_html_enabled(ln, html_final):
    ln_enabled = STYLE[8] in ln
    if ln_enabled:
        ln = f" {ln[19:].rstrip()}"
        if ':' in ln:
            header, value = map(str.strip, ln.split(":", 1))
            ln = f"{HTML_TAGS[6]} {header}{HTML_TAGS[5]}: {value}"
        else:
            ln = f"{HTML_TAGS[6]} {ln.strip()}{HTML_TAGS[5]}"
        html_final.write(f"{format_html_csp(ln)}{HTML_TAGS[11]}")
    return ln, ln_enabled


def clean_html_final(final_filename):
    with open(final_filename, "r+", encoding="utf8") as html_final:
        html_content = html_final.read()
        html_content = re.sub(RE_PATTERN[22], "", html_content)
        html_content = html_content.replace(RE_PATTERN[23], "")
        html_final.seek(0)
        html_final.write(html_content)
        html_final.truncate()


def generate_xml(final_filename, temp_filename):
    """'-o xml' option: XML export of the analysis"""
    root = ET.Element('analysis', {'version': BANNER_VERSION,
                                   'generated': current_time})
    with open(temp_filename, 'r', encoding='utf8') as txt_source:
        parse_xml(root, None, (line.strip() for line in txt_source))
    xml_decl = '<?xml version="1.0" encoding="utf-8"?>\n'.encode('utf-8')
    xml_content = ET.tostring(root, encoding='utf-8', xml_declaration=False)
    xml_dtd = f'<!DOCTYPE analysis [\n{DTD_CONTENT}]\n>\n'.encode('utf-8')
    with open(final_filename, 'wb') as xml_final:
        xml_final.write(xml_decl + xml_dtd + xml_content)
    print_export_path(final_filename, reliable)
    remove(temp_filename)
    sys.exit()


def parse_xml(root, section, stripped_txt):
    for line in stripped_txt:
        if not line:
            continue
        if line.startswith('['):
            section = ET.SubElement(root, 'section', {'name': line})
            continue
        if section is None:
            continue
        add_xml_item(line, section)
    return section


def add_xml_item(line, section):
    item = ET.SubElement(section, 'item')
    if ': ' in line and all(sub not in line for sub in XML_STRING):
        key, value = line.split(': ', 1)
        item.set('name', key.strip())
        item.text = value.strip()
    else:
        item.text = line


def print_http_exception(exception_id, exception_v):
    """Show the exception received during analysis"""
    delete_lines()
    print("")
    print_detail(exception_id)
    raise SystemExit from exception_v


def check_ru_scope():
    """
    Blocks analysis of Russian domains:
     https://github.com/rfc-st/humble/blob/master/CODE_OF_CONDUCT.md#update-20220326
    """
    try:
        sff = urlparse(URL).netloc.split(':')[0].encode('ascii').decode('idna')
    except UnicodeError:
        sff = urlparse(URL).netloc.split(':')[0]
    if sff.split('.')[-1].upper() in {'RU', 'РФ'}:
        print_detail('[ru_check]', 3)
        sys.exit()


def check_owasp_compliance(tmp_filename):
    """'-c' option: OWASP Secure Headers Project best practices checks"""
    remove(tmp_filename)
    header_list = []
    header_dict = {}
    with open(path.join(OS_PATH, HUMBLE_DIRS[0], HUMBLE_FILES[18]), 'r',
              encoding='utf8') as owasp_file:
        for line in islice(owasp_file, SLICE_INT[8], None):
            line = line.strip()
            header_name, header_val = map(str, line.split(': ', 1))
            header_list.append(header_name.lower())
            header_dict[header_name] = header_val
    print_owasp_findings(header_dict, header_list)


def print_owasp_summary(missing, wrong):
    missing_txt = get_detail('[comp_missing]', replace=True)
    wrong_txt = get_detail('[comp_noncompliant]', replace=True)
    max_len = len(wrong_txt)
    print(linesep.join([''] * 2))
    print(f"{STYLE[0]}{get_detail('[comp_summary]')}")
    print(f" {missing_txt:{max_len}} : {len(missing)}")
    print(f" {wrong_txt:{max_len}} : {len(wrong)}")


def print_owasp_findings(header_dict, header_list):
    print(linesep.join([''] * 2))
    print(f"{STYLE[0]}{get_detail('[comp_analysis]')}")
    print(" ", end='')
    print_detail_l('[analysis_date]')
    print(f" {current_time}")
    print(f' {URL_STRING[1]}{URL}')
    print_detail('[comp_ref]', num_lines=2)
    missing_owasp = print_owasp_missing(header_list)
    wrong_owasp = print_owasp_wrong(header_dict)
    if wrong_owasp:
        print_owasp_rec(wrong_owasp, header_dict)
    print_owasp_summary(missing_owasp, wrong_owasp)
    print("")
    print_detail('[comp_experimental]', 2)


def print_owasp_missing(header_list):
    print(f"\n{STYLE[0]}{get_detail('[comp_rec]')}{STYLE[5]}")
    missing_owasp = [header.title() for header in header_list if header not in
                     headers_l]
    if not missing_owasp:
        print(f"{STYLE[10]}  {get_detail(DIR_MSG[2])}{STYLE[5]}", end="")
        return []
    for header in missing_owasp:
        prefix = "(*) " if header == "Permissions-Policy" else ""
        print(f"{STYLE[1]}  {prefix}{header}{STYLE[5]}")
    return missing_owasp


def print_owasp_wrong(header_dict):
    wrong_owasp = [
        (header.title(), value)
        for header, value in headers_l.items()
        if (owasp_value := header_dict.get(header.title())) and value !=
        owasp_value
    ]
    print(f"\n\n{STYLE[0]}{get_detail('[comp_val]')}{STYLE[5]}")
    if not wrong_owasp:
        print(f"{STYLE[10]} {get_detail(DIR_MSG[2])}{STYLE[5]}", end="")
        return []
    for header, value in sorted(wrong_owasp):
        prefix = "(*) " if header == "Permissions-Policy" else ""
        print(f"{STYLE[1]}  {prefix}{header}{STYLE[4]}: {value}")
    return wrong_owasp


def print_owasp_rec(wrong_owasp, header_dict):
    print(f"\n\n{STYLE[0]}{get_detail('[comp_rec_val]')}{STYLE[5]}")
    for header, _ in sorted(wrong_owasp):
        prefix = "(*) " if header == "Permissions-Policy" else ""
        if rec_val := header_dict.get(header):
            print(f"{STYLE[10]}  {prefix}{header}{STYLE[4]}: {rec_val}")


def analyze_input_file(input_file):
    """'-if' option: Analyze headers from supplied file"""
    if not path.exists(input_file):
        print_error_detail('[args_inputnotfound]')
    input_headers = {}
    try:
        with open(input_file, 'r', encoding='utf8') as input_source:
            for ln in input_source:
                ln = ln.strip()
                if ':' in ln:
                    input_header, input_value = ln.split(':', 1)
                    input_headers[input_header.title()] = input_value.strip()
            if not input_headers:
                print_error_detail('[args_inputlines]')
    except UnicodeDecodeError:
        print_error_detail('[args_inputunicode]')
    return input_headers, False, 200


def get_tmp_file(args, export_date):
    """Create the temporary export file related to '-o' option"""
    file_ext = '.txt' if args.output == 'txt' else 't.txt'
    if args.output_file:
        tmp_file = f'{args.output_file}{file_ext}'
    else:
        url = urlparse(URL)
        humble_str = HUMBLE_DESC[1:7]
        lang = '_es' if args.lang else '_en'
        tmp_file = build_tmp_file(export_date, file_ext, lang, humble_str, url)
    if args.output_path:
        tmp_file = path.join(output_path, tmp_file)
    return tmp_file


def build_tmp_file(export_date, file_ext, lang, humble_str, url):
    # Tiny optimization, lazy-loading third-party tldextract
    import tldextract
    url_str = tldextract.extract(URL)
    url_sub = f"_{url_str.subdomain}." if url_str.subdomain else "_"
    url_prt = f"_{url.port}_" if url.port else "_"
    return (
        f"{humble_str}_{url.scheme}"
        f"{url_sub}{url_str.domain}.{url_str.suffix}"
        f"{url_prt}{export_date}{lang}{file_ext}"
    )


def process_server_error(http_status_code, l10n_id):
    """Show message for specific 5xx server errors during analysis"""
    delete_lines()
    print()
    if http_status_code in CDN_HTTP_CODES:
        if detail := print_detail(l10n_id, 0):
            print(detail)
        elif 500 <= http_status_code <= 511:
            print(URL_LIST[2])
        else:
            print(URL_LIST[1])
    else:
        print_error_detail('[server_serror]')
    sys.exit()


def make_http_request(custom_headers, proxy):  # sourcery skip: extract-method
    """Make the request to the supplied URL"""
    try:
        session = requests.Session()
        session.mount("https://", SSLContextAdapter())
        session.mount("http://", HTTPAdapter())
        # If '-df' parameter is provided ('args.redirects') the exact URL will
        # be analyzed; otherwise the last redirected URL will be analyzed.
        #
        # Yes, certificates and hosts must always be checked/verified on HTTPS
        # connections. However, within the scope of 'humble', I have chosen to
        # disable these checks to allow the analysis of URLs in certain cases
        # (E.g., development environments, hosts with outdated
        # servers/software, self-signed certificates, etc.).
        r = session.get(
            URL,
            allow_redirects=not args.redirects,
            verify=False,
            headers=custom_headers,
            timeout=REQ_TIMEOUT,
            proxies=proxy,
        )
        return r, None, None
    except requests.exceptions.Timeout as e:
        return None, None, e
    except requests.exceptions.SSLError:
        return None, None, None
    except requests.exceptions.RequestException as e:
        return None, None, e
    except Exception as e:
        return None, None, e


def process_requests_exception(exception):
    """
    Show error messages for request timeout and unhandled exceptions during
    analysis.
    """
    if isinstance(exception, requests.exceptions.Timeout):
        delete_lines()
        delete_lines()
        print(f"\n{get_detail('[e_timeout]', replace=True)}")
        sys.exit()
    if exception_id := exception_d.get(type(exception)):
        print_http_exception(exception_id, exception)
    else:
        print_detail_l('[unhandled_exception]')
        print(f" {type(exception).__name__}")


def process_http_error(r, exception_d):
    """Show error messages based on HTTP response code during analysis"""
    if r is None:
        return
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError as err_http:
        status = err_http.response.status_code
        l10n_id = f'[server_{status}]'
        if status in CDN_HTTP_CODES:
            process_server_error(status, l10n_id)
        elif 500 <= status <= 599:
            print_error_detail('[server_5xx]')
    except Exception as e:
        ex = exception_d.get(type(e))
        if ex and (not callable(ex) or ex(e)):
            print_http_exception(ex, e)


def parse_request_headers(request_headers):
    """'-H' option: Add the supplied headers to the request"""
    headers, malformed_headers = process_request_headers(request_headers)
    if malformed_headers:
        delete_lines()
        print("")
        print(
            f"{get_detail('[e_custom_headers]', replace=True)}"
            f"; {', '.join(f'\"{header}\"' for header in malformed_headers)}"
        )
        sys.exit()
    return headers


def process_request_headers(request_headers):
    headers = {}
    malformed_headers = []
    for header in request_headers:
        if not header:
            delete_lines()
            print("")
            print(f"{get_detail('[e_custom_eheaders]', replace=True)}")
            sys.exit()
        if ":" not in header:
            malformed_headers.append(header)
            continue
        key, value = header.split(":", 1)
        key, value = key.strip(), value.strip()
        if not key or not value:
            malformed_headers.append(header)
            continue
        headers[key] = value
    return headers, malformed_headers


def process_http_request(status_code, reliable, body, proxy, custom_headers):
    """Process the request to the supplied URL"""
    result = {}
    done = Event()

    def worker():
        try:
            r, _, exception = make_http_request(custom_headers, proxy)
            result['r'] = r
            result['exception'] = exception
        except Exception as e:
            result['exception'] = e
        finally:
            done.set()

    thread = Thread(target=worker, daemon=True)
    thread.start()
    if not done.wait(timeout=REQ_TIMEOUT - REQ_WARNING):
        print(get_detail('[unreliable_analysis]'))
    if not done.wait(timeout=REQ_TIMEOUT):
        delete_lines()
        delete_lines()
        print(f"\n{get_detail('[e_timeout]', replace=True)}")
        sys.exit()
    r = result.get('r')
    exception = result.get('exception')
    return process_http_response(r, exception, status_code, reliable, body)


def process_http_response(r, exception, status_code, reliable, body):
    # https://requests.readthedocs.io/en/latest/_modules/requests/exceptions/
    if exception:
        process_requests_exception(exception)
        return {}, status_code, reliable, body
    if r is None:
        return {}, status_code, reliable, body
    # https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#5xx_server_errors
    # https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/
    process_http_error(r, exception_d)
    status_code = r.status_code
    headers = CaseInsensitiveDict({
        k: re.sub(RE_PATTERN[20], ' ', v).strip()
        for k, v in r.headers.items()})
    body = r.text
    # https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/http-equiv#content-type
    is_html = False
    ctype = headers.get('content-type', '')
    is_html = ctype.lower().startswith('text/html')
    return headers, status_code, reliable, body, is_html


def custom_help_formatter(prog):
    """Custom help formatter to allow more characters per line"""
    return RawDescriptionHelpFormatter(prog, max_help_position=43)


# Main functionality for argparse
init(autoreset=True)
epilog_content = get_epilog_content('[epilog_content]')

parser = ArgumentParser(formatter_class=custom_help_formatter,
                        description=f"{HUMBLE_DESC} | {URL_LIST[4]} | \
v.{local_version}", epilog=epilog_content)

parser.add_argument("-a", dest='URL_A', action="store_true", help="Shows \
statistics of the performed analysis; if the '-u' parameter is ommited they \
will be global")
parser.add_argument("-b", dest='brief', action="store_true", help="Shows \
overall findings; if omitted detailed ones will be shown")
parser.add_argument("-c", dest='compliance', action="store_true", help="Checks\
 URL response HTTP headers for compliance with OWASP 'Secure Headers Project' \
best practices")
parser.add_argument('-cicd', dest="cicd", action="store_true", help="Shows \
only analysis summary, totals and grade in JSON; suitable for CI/CD")
parser.add_argument("-df", dest='redirects', action="store_true", help="Do not\
 follow redirects; if omitted the last redirection will be the one analyzed")
parser.add_argument("-e", nargs='?', type=str, dest='testssl_path', help="Show\
s only TLS/SSL checks; requires the PATH of testssl (https://testssl.sh/)")
parser.add_argument("-f", nargs='?', type=str, dest='fingerprint_term', help="\
Shows fingerprint statistics; if 'FINGERPRINT_TERM' (E.g., 'Google') is \
omitted the top 20 results will be shown")
parser.add_argument("-g", dest='guides', action="store_true", help="Shows \
guidelines for enabling security HTTP response headers on popular frameworks, \
servers and services")
parser.add_argument("-grd", dest='grades', action="store_true", help="Shows \
the checks to grade an analysis, along with advice for improvement")
parser.add_argument("-H", dest='request_header', type=str, action="append\
", help='Adds REQUEST_HEADER to the request;  must be in double quotes and can\
 be used multiple times, e.g. -H "Host: example.com"')
parser.add_argument("-if", dest='input_file', type=str, help="Analyzes \
'INPUT_FILE': must contain HTTP response headers and values separated by ': ';\
 E.g., 'server: nginx'")
parser.add_argument("-l", dest='lang', choices=['es'], help="Defines the \
language for displaying analysis, errors and messages; if omitted, will be \
shown in English")
parser.add_argument("-lic", dest='license', action="store_true", help="Shows \
the license for 'humble', along with permissions, limitations and conditions")
parser.add_argument("-o", dest='output', choices=['csv', 'html', 'json', 'pdf',
                                                  'txt', 'xlsx', 'xml'],
                    help="Exports analysis to 'humble_scheme_URL_port_yyyymmdd\
_hhmmss_language.ext' file")
parser.add_argument("-of", dest='output_file', type=str, help="Exports \
analysis to 'OUTPUT_FILE'; if omitted the default filename of the parameter \
'-o' will be used")
parser.add_argument("-op", dest='output_path', type=str, help="Exports \
analysis to 'OUTPUT_PATH'; must be absolute. If omitted the PATH of \
'humble.py' will be used")
parser.add_argument('-p', dest="proxy", type=str, help="Use a proxy for the \
analysis. E.g., 'http://127.0.0.1:8080'. If no port is specified '8080' will \
be used")
parser.add_argument("-r", dest='ret', action="store_true", help="Shows HTTP \
response headers and a detailed analysis; '-b' parameter will take priority")
parser.add_argument("-s", dest='skip_headers', nargs='*', type=str, help="S\
kips 'deprecated/insecure' and 'missing' checks for the indicated \
'SKIP_HEADERS' (separated by spaces)")
parser.add_argument('-u', type=str, dest='URL', help="Scheme, host and port to\
 analyze. E.g., https://google.com or https://google.com:443")
parser.add_argument('-ua', type=str, dest='user_agent', help="User-Agent ID \
from 'additional/user_agents.txt' file to use. '0' will show all and '1' is \
the default")
parser.add_argument("-v", "--version", action="store_true", help="Checks for \
updates at https://github.com/rfc-st/humble")

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

# Multilingual messages and Python version checking
l10n_main = get_l10n_content()
check_python_version()

# Functionality for argparse parameters/values
check_updates(local_version) if '-v' in sys.argv else None
print_l10n_file(args, 'grades', slice_ln=True) if '-grd' in sys.argv else None
print_l10n_file(args, 'license') if '-lic' in sys.argv else None

if '-f' in sys.argv:
    fng_statistics_term(args.fingerprint_term) if args.fingerprint_term else \
        fng_statistics_top()

URL = args.URL

if URL is not None:
    check_ru_scope()

if '-cicd' in sys.argv:
    args.output = 'txt'

if '-c' in sys.argv:
    args.brief = False
    args.output = 'txt'
    args.user_agent = '1'

if '-if' in sys.argv:
    if any([args.redirects, args.ret, args.user_agent]):
        print_error_detail('[args_inputfile]')
        sys.exit()
    elif not args.URL:
        print_error_detail('[args_urlinputfile]')
        sys.exit()
    else:
        headers, reliable, status_code = analyze_input_file(args.input_file)

if '-H' in sys.argv and not URL:
    print_error_detail('[e_custom_uheaders]')
    sys.exit()

if '-ua' in sys.argv:
    ua_header = parse_user_agent(user_agent=True)
elif URL:
    ua_header = parse_user_agent()

if '-e' in sys.argv:
    if system().lower() == 'windows':
        print_l10n_file(args, 'testssl', slice_ln=True)
    if (args.testssl_path is None or URL is None):
        print_error_detail('[args_notestssl]')

if args.lang and not URL and not args.URL_A and not args.guides:
    print_error_detail('[args_lang]')

if args.output_file and args.output and URL:
    output_file = args.output_file
    check_input_traversal(args.output_file)
else:
    if args.output_file and (not args.output or not URL):
        print_error_detail('[args_customfile]')

if args.output_path is not None:
    output_path = path.abspath(args.output_path)
    check_output_path(args, output_path)

if any([args.brief, args.output, args.ret, args.redirects,
        args.skip_headers]) and (URL is None or args.guides is None or
                                 args.URL_A is None):
    print_error_detail('[args_several]')

skip_list, unsupported_headers = [], []

if '-s' in sys.argv and len(args.skip_headers) == 0:
    print_error_detail('[args_skipped]')
elif args.skip_headers:
    insecure_headers = get_insecure_checks()
    unsupported_headers, skip_list = \
        get_skipped_unsupported_headers(args, insecure_headers)
    print_unsupported_headers(unsupported_headers) if unsupported_headers else\
        None

if args.guides:
    print_l10n_file(args, 'security_guides', slice_ln=True)

if args.testssl_path:
    testssl_command(path.abspath(args.testssl_path), URL)

if args.URL_A:
    check_analysis(HUMBLE_FILES[0])
    url_analytics() if URL else url_analytics(is_global=True)

start = time()

if not args.URL_A and not args.cicd:
    if not args.compliance:
        detail = '[analysis_output]' if args.output else '[analysis]'
    else:
        detail = '[compliance_output]'
    print("")
    print_detail(detail)

exception_d = {
    requests.exceptions.ChunkedEncodingError: '[e_chunk]',
    requests.exceptions.ConnectionError: '[e_connection]',
    requests.exceptions.ContentDecodingError: '[e_decoding]',
    requests.exceptions.InvalidSchema: '[e_ischema]',
    requests.exceptions.InvalidURL: '[e_url]',
    requests.exceptions.MissingSchema: '[e_mschema]',
    requests.exceptions.SSLError: None,
    requests.exceptions.Timeout: '[e_timeout]',
    requests.exceptions.TooManyRedirects: '[e_redirect]',
}
requests.packages.urllib3.disable_warnings()

headers_l, http_equiv, status_code, reliable, body = {}, None, None, None, None

if '-if' not in sys.argv:
    proxy = None
    if args.proxy and process_proxy_url(args.proxy, 3.0):
        proxy = {"http": args.proxy, "https": args.proxy}
    custom_headers = REQ_HEADERS.copy()
    if '-H' in sys.argv:
        added_custom_headers = parse_request_headers(args.request_header)
        custom_headers.update(added_custom_headers)
    custom_headers['User-Agent'] = ua_header
    (headers, status_code, reliable, body, is_html) = (
        process_http_request(status_code, reliable, body, proxy,
                             custom_headers,
                             )
    )
    if body and is_html:
        http_equiv = re.findall(RE_PATTERN[8], body, re.IGNORECASE)

headers_l = {header.lower(): value for header, value in headers.items()}

# Export filename generation
export_filename = None

if args.output:
    orig_stdout = sys.stdout
    export_date = datetime.now().strftime("%Y%m%d_%H%M%S")
    tmp_filename = get_tmp_file(args, export_date)
    validate_file_access(tmp_filename, context='export')
    tmp_filename_content = open(tmp_filename, 'w', encoding='utf8')
    sys.stdout = tmp_filename_content
    export_slice = SLICE_INT[4] if args.output == 'txt' else SLICE_INT[5]
    export_filename = f"{tmp_filename[:export_slice]}.{args.output}"

# Section '0. Info & HTTP Response Headers'
print_general_info(reliable, export_filename)
print_response_headers() if args.ret else print(linesep.join([''] * 2))

# Section '1. Enabled HTTP Security Headers'
# Checks: /additional/security.txt
print_detail_r('[1enabled]')

with open(path.join(OS_PATH, HUMBLE_DIRS[0], HUMBLE_FILES[17]), 'r',
          encoding='utf8') as sec_f:
    t_ena = tuple(line.strip() for line in islice(sec_f, SLICE_INT[2], None))

en_cnt = get_enabled_headers(args, headers_l, t_ena)

# Section '2. Missing HTTP Security Headers'
# Checks: /additional/missing.txt
print_detail_r('[2missing]')

l_miss = ['Cache-Control', 'Clear-Site-Data', 'Content-Type',
          'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy',
          'Cross-Origin-Resource-Policy', 'Content-Security-Policy',
          'Integrity-Policy', 'NEL', 'Permissions-Policy', 'Referrer-Policy',
          'Strict-Transport-Security', 'X-Content-Type-Options',
          'X-Permitted-Cross-Domain-Policies']

l_detail = ['[mcache]', '[mcsd]', '[mctype]', '[mcoe]', '[mcop]', '[mcor]',
            '[mcsp]', '[mcipol]', '[mnel]', '[mpermission]', '[mreferrer]',
            '[msts]', '[mxcto]', '[mxpcd]', '[mxfo]']

m_cnt, skip_missing = print_missing_headers(args, headers_l, l_detail, l_miss)

if args.brief and m_cnt != 0:
    print("")
if m_cnt == 0:
    print_nowarnings()
print("")

# Section '3. Fingerprint HTTP Response Headers'
# Checks: /additional/fingerprint.txt
print_detail_r('[3fingerprint]')

if not args.brief:
    print_detail('[afgp]')

l_fng_ex, l_fng, titled_fng = get_fingerprint_headers()
f_cnt = print_fingerprint_headers(headers_l, l_fng_ex, titled_fng)

if args.brief and f_cnt != 0:
    print("")
if f_cnt == 0:
    print_nowarnings()
print("")

# Section '4. Deprecated HTTP Response Headers/Protocols and Insecure Values'
# Checks: /additional/insecure.txt
print_detail_r('[4depinsecure]')
i_cnt = [0]

if not args.brief:
    print_detail('[aisc]')

# The headers of 'l_miss' are excluded here, but are included in 'l_total'.
l_ins = ['Accept-CH', 'Accept-CH-Lifetime', 'Accept-Patch',
         'Access-Control-Allow-Credentials', 'Access-Control-Allow-Methods',
         'Access-Control-Allow-Origin', 'Access-Control-Max-Age',
         'Activate-Storage-Access', 'Allow', 'Content-Digest',
         'Content-Disposition', 'Content-DPR', 'Content-Encoding',
         'Content-Security-Policy-Report-Only', 'Content-Type', 'Critical-CH',
         'Digest', 'Document-Isolation-Policy', 'Document-Policy', 'Etag',
         'Expect-CT', 'Expires', 'Feature-Policy',
         'Integrity-Policy-Report-Only', 'Keep-Alive', 'Large-Allocation',
         'Mcp-Session-Id', 'No-Vary-Search', 'Observe-Browsing-Topics',
         'Onion-Location', 'Origin-Agent-Cluster', 'P3P', 'Pragma',
         'Proxy-Authenticate', 'Public-Key-Pins',
         'Public-Key-Pins-Report-Only', 'Report-To', 'Reporting-Endpoints',
         'Repr-Digest', 'Server-Timing', 'Service-Worker-Allowed',
         'Set-Cookie', 'Set-Login', 'SourceMap', 'Speculation-Rules',
         'Strict-Dynamic', 'Supports-Loading-Mode', 'Surrogate-Control',
         'Timing-Allow-Origin', 'Tk', 'Trailer', 'Transfer-Encoding', 'Vary',
         'Want-Digest', 'Want-Content-Digest', 'Want-Repr-Digest', 'Warning',
         'WWW-Authenticate', 'X-Content-Security-Policy',
         'X-Content-Security-Policy-Report-Only', 'X-DNS-Prefetch-Control',
         'X-Download-Options', 'X-Pad', 'X-Pingback', 'X-Robots-Tag',
         'X-Runtime', 'X-SourceMap', 'X-UA-Compatible', 'X-Webkit-CSP',
         'X-Webkit-CSP-Report-Only', 'X-XSS-Protection']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-CH
t_acceptch_dep = ('content-dpr', 'dpr', 'sec-ch-ua-full-version',
                  'viewport-width', 'width')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
t_accecao = ('*', 'null')
t_accecaov = ('.*', '*.')

# https://privacycg.github.io/storage-access-headers/#activate-storage-access-header
# https://developers.google.com/privacy-sandbox/blog/storage-access-api-headers-logic
t_act = ('allowed-origin', 'load', 'retry')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
t_cache = ('no-cache', 'no-store')
t_cachev = ('immutable', 'max-age', 'must-revalidate', 'must-understand',
            'no-cache', 'no-store', 'no-transform', 'private',
            'proxy-revalidate', 'public', 's-maxage', 'stale-if-error',
            'stale-while-revalidate')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data
t_csdata = ('cache', 'clientHints', 'cookies', 'storage', 'executionContexts',
            '*')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Digest
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Repr-Digest
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Want-Content-Digest
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Want-Repr-Digest
t_digest_sec = ('sha-256', 'sha-512')
t_digest_ins = ('adler', 'crc32c', 'md5', 'sha-1', 'unixsum', 'unixcksum')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition
t_contdisp = ('filename', 'filename*')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
t_cencoding = ('br', 'compress', 'dcb', 'dcz', 'deflate', 'gzip', 'x-gzip',
               'zstd')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
# https://www.w3.org/TR/CSP2/ & https://www.w3.org/TR/CSP3/
t_csp_broad = (' *', '* ', ' * ',  ' blob: ', ' data: ', ' ftp: ',
               ' filesystem: ', ' https: ', ' https://* ', ' https://*.* ',
               ' mailto: ', ' mediastream: ', ' schemes: ', ' tel: ', ' wss: ',
               'wss://')
t_csp_equal = ('nonce', 'sha', 'style-src-elem', 'report-to', 'report-uri')
t_csp_dep = ('block-all-mixed-content', 'disown-opener', 'navigate-to',
             'plugin-types', 'prefetch-src', 'referrer', 'report-uri',
             'require-sri-for')
t_csp_dirs = ('base-uri', 'child-src', 'connect-src', 'default-src',
              'fenced-frame-src', 'font-src', 'form-action', 'frame-ancestors',
              'frame-src', 'img-src', 'manifest-src', 'media-src',
              'object-src', 'report-to', 'require-trusted-types-for',
              'sandbox', 'script-src', 'script-src-attr', 'script-src-elem',
              'style-src', 'style-src-attr', 'style-src-elem', 'trusted-types',
              'upgrade-insecure-requests', 'webrtc', 'worker-src')
t_csp_insecs = ('http:', 'ws:')
t_csp_miss = ('base-uri', 'child-src', 'connect-src', 'font-src',
              'form-action', 'frame-ancestors', 'img-src', 'object-src',
              'require-trusted-types-for', 'script-src', 'style-src',
              'trusted-types', 'worker-src')
t_csp_checks = ('upgrade-insecure-requests', 'strict-transport-security',
                'unsafe-hashes', 'nonce-', '127.0.0.1')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
l_csp_ro_dep = ['block-all-mixed-content', 'disown-opener', 'plugin-types',
                'prefetch-src', 'referrer', 'report-uri', 'require-sri-for',
                'sandbox', 'violated-directive']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type
# https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
t_ct_mime = ('application/xhtml+xml', 'text/html')

# https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta#charset
# https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/http-equiv#content-type
t_ct_equiv = ('text/html; charset=utf-8', 'text/html; charset=UTF-8')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy
t_coep = ('credentialless', 'require-corp', 'unsafe-none')

# https://html.spec.whatwg.org/dev/browsers.html#the-coep-headers
t_coepr = ('require-corp', 'unsafe-none')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy
# https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-opener-policies
# https://html.spec.whatwg.org/dev/browsers.html#the-coop-headers
t_coop = ('noopener-allow-popups', 'same-origin', 'same-origin-allow-popups',
          'same-origin-plus-COEP', 'unsafe-none')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy
t_corp = ('cross-origin', 'same-origin', 'same-site')

# https://wicg.github.io/document-isolation-policy/
t_doci = ('isolate-and-credentialless', 'isolate-and-require-corp', 'none')

# https://wicg.github.io/document-policy/
# https://github.com/WICG/document-policy/blob/main/document-policy-explainer.md
# https://github.com/MicrosoftEdge/MSEdgeExplainers/blob/main/PerformanceControlOfEmbeddedContent/explainer.md
t_docp = ('basic', 'bpp', 'document-write', 'early-script', 'escape-in-popups',
          'expect-no-linked-resources', 'frame-loading', 'forms', 'globals',
          'image-compression', 'include-js-call-stacks-in-crash-reports',
          'max-image-bpp', 'modals', 'no-document-write', 'no-scripts',
          'no-unsized-media', 'pointer-lock', 'popups', 'presentation-lock',
          'report-to', 'script', 'scripts', 'unsized-media', 'vertical-scroll',
          'viewport-capture')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires
t_excc = ('max-age', 's-maxage')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy-Report-Only
t_ipol = ('blocked-destinations', 'endpoints')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
# https://cyberwhite.co.uk/http-verbs-and-their-security-risks/
t_methods = ('*', 'CONNECT', 'DEBUG', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH',
             'PUT', 'TRACE', 'TRACK')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types
t_legacy = ('application/javascript', 'application/ecmascript',
            'application/x-ecmascript', 'application/x-javascript',
            'text/ecmascript', 'text/javascript1.0', 'text/javascript1.1',
            'text/javascript1.2', 'text/javascript1.3', 'text/javascript1.4',
            'text/javascript1.5', 'text/jscript', 'text/livescript',
            'text/x-ecmascript', 'text/x-javascript')

# https://w3c.github.io/network-error-logging/#nel-response-header
t_nel_dir = ('failure_fraction', 'include_subdomains', 'max_age', 'report_to',
             'request_headers', 'response_headers', 'success_fraction')
t_nel_req = ('report_to', 'max_age')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/No-Vary-Search
t_nvarysearch = ('except', 'key-order', 'params')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster
l_origcluster = ['?1']

# https://developer.chrome.com/origintrials/
# https://github.com/MicrosoftEdge/MSEdgeExplainers
# https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
t_per_broad = ('*', ' * ')
t_per_dep = ('document-domain', 'window-placement')
t_per_ft = ('accelerometer', 'all-screens-capture', 'ambient-light-sensor',
            'attribution-reporting', 'autofill', 'autoplay', 'battery',
            'bluetooth', 'browsing-topics', 'camera',
            'captured-surface-control', 'ch-ua', 'ch-ua-arch', 'ch-ua-bitness',
            'ch-ua-full-version', 'ch-ua-full-version-list', 'ch-ua-mobile',
            'ch-ua-model', 'ch-ua-platform', 'ch-ua-platform-version',
            'ch-ua-wow64', 'clipboard-read', 'clipboard-write',
            'compute-pressure', 'conversion-measurement',
            'cross-origin-isolated', 'deferred-fetch',
            'deferred-fetch-minimal', 'device-attributes',
            'digital-credentials-create', 'digital-credentials-get',
            'direct-sockets', 'display-capture', 'encrypted-media',
            'execution-while-not-rendered', 'execution-while-out-of-viewport',
            'focus-without-user-activation', 'fullscreen', 'gamepad',
            'geolocation', 'gyroscope', 'hid', 'identity-credentials-get',
            'idle-detection', 'interest-cohort', 'join-ad-interest-group',
            'keyboard-map', 'language-detector', 'language-model',
            'layout-animations', 'local-fonts', 'magnetometer', 'manual-text',
            'media-playback-while-not-visible', 'microphone', 'midi',
            'monetization', 'navigation-override', 'otp-credentials',
            'payment', 'picture-in-picture', 'publickey-credentials-create',
            'publickey-credentials-get', 'rewriter', 'run-ad-auction',
            'screen-wake-lock', 'serial', 'shared-autofill', 'smart-card',
            'speaker-selection', 'storage-access', 'summarizer', 'sync-script',
            'sync-xhr', 'translator', 'trust-token-redemption', 'unload',
            'usb', 'vertical-scroll', 'web-share', 'window-management',
            'writer', 'xr-spatial-tracking')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authenticate
# https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
t_proxy_auth = ('AWS4-HMAC-SHA256', 'Basic', 'Bearer', 'Concealed', 'Digest',
                'DPoP', 'GNAP', 'HOBA', 'Mutual', 'Negotiate', 'OAuth',
                'PrivateToken', 'SCRAM-SHA-1', 'SCRAM-SHA-256', 'vapid')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
# https://www.w3.org/TR/referrer-policy/#information-leakage
t_ref_secure = ('same-origin', 'strict-origin',
                'strict-origin-when-cross-origin', 'no-referrer',
                'no-referrer-when-downgrade')
t_ref_values = ('no-referrer', 'no-referrer-when-downgrade', 'origin',
                'origin-when-cross-origin', 'same-origin', 'strict-origin',
                'strict-origin-when-cross-origin', 'unsafe-url')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Refresh
t_refresh = ('QA==', '@')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
t_cookie_prf = ('__Host-', '__Secure-')
t_cookie_sec = ('httponly', 'secure')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Login
t_setlogin = ('logged-in', 'logged-out')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
t_sts_dir = ('includeSubDomains', 'max-age')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Supports-Loading-Mode
t_support_mode = ('credentialed-prerender', 'fenced-frame')

# https://www.w3.org/TR/edge-arch/
t_surrogate = ('content', 'extension-directive', 'max-age', 'no-store',
               'no-store-remote')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Trailer
t_trailer = ('authorization', 'cache-control', 'content-encoding',
             'content-length', 'content-type', 'content-range', 'host',
             'max-forwards', 'set-cookie', 'te', 'trailer',
             'transfer-encoding')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding
t_transfer = ('chunked', 'compress', 'deflate', 'gzip', 'x-gzip')

# https://getbutterfly.com/security-headers-a-concise-guide/
# https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html
t_permcross = ('all', 'by-content-only', 'by-ftp-only', 'master-only', 'none',
               'none-this-response')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
t_xfo_dir = ('DENY', 'SAMEORIGIN')

# https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag
# https://www.bing.com/webmasters/help/which-robots-metatags-does-bing-support-5198d240
# https://seranking.com/blog/guide-meta-tag-robots-x-robots-tag/
t_robots = ('all', 'archive', 'follow', 'index', 'indexifembedded',
            'max-image-preview', 'max-snippet', 'max-video-preview',
            'noarchive', 'nocache', 'noodp', 'nofollow', 'noimageindex',
            'noindex', 'none', 'nopagereadaloud', 'nositelinkssearchbox',
            'nosnippet', 'notranslate', 'noydir', 'unavailable_after')

unsafe_scheme = True if URL.startswith(HTTP_SCHEMES[0]) else False

if 'accept-ch' in headers_l and '1' not in skip_list:
    acceptch_header = headers_l['accept-ch']
    if unsafe_scheme:
        print_details('[ixach_h]', '[ixach]', 'd', i_cnt)
    if any(value in acceptch_header for value in t_acceptch_dep):
        print_detail_r('[ixachd_h]', is_red=True)
        if not args.brief:
            match_value = [x for x in t_acceptch_dep if x in acceptch_header]
            match_value_str = ', '.join(f"'{x}'" for x in match_value)
            print_detail_l('[ixachd_s]')
            print(match_value_str)
            print_detail('[ixachd]')
        i_cnt[0] += 1

if 'accept-ch-lifetime' in headers_l and '2' not in skip_list:
    print_details('[ixacl_h]', '[ixacld]', 'd', i_cnt)

if 'accept-patch' in headers_l and '3' not in skip_list:
    print_details('[ixacp_h]', '[ixacp]', 'd', i_cnt)

accescred_header = headers_l.get("access-control-allow-credentials", '')
if accescred_header and accescred_header != 'true' and '4' not in skip_list:
    print_details('[icred_h]', '[icred]', 'd', i_cnt)

if 'access-control-allow-methods' in headers_l and '5' not in skip_list:
    methods = headers_l["access-control-allow-methods"]
    if any(method in methods for method in t_methods):
        print_detail_r('[imethods_h]', is_red=True)
        if not args.brief:
            match_method = [x for x in t_methods if x in methods]
            quoted_methods = ", ".join(f"'{m}'" for m in match_method)
            match_method_str = f"{quoted_methods}."
            print_detail_l('[imethods_s]')
            print(match_method_str)
            print_detail('[imethods]')
        i_cnt[0] += 1

accesso_header = headers_l.get("access-control-allow-origin", '')
if accesso_header and accesso_header in t_accecao and not any(
 val in accesso_header for val in t_accecaov) and '6' not in skip_list:
    print_details('[iaccess_h]', '[iaccess]', 'd', i_cnt)

accesma_header = headers_l.get("access-control-max-age", '')
if accesma_header and int(accesma_header) > 86400 and '7' not in skip_list:
    print_details('[iacessma_h]', '[iaccessma]', 'd', i_cnt)

if 'activate-storage-access' in headers_l and '8' not in skip_list:
    act_h = headers_l['activate-storage-access']
    if not any(elem in act_h for elem in t_act):
        print_details('[iact_h]', '[iact]', 'm', i_cnt)
    if ('retry' in act_h) and ('allowed-origin' not in act_h):
        print_details('[iactr_h]', '[iactr]', 'd', i_cnt)

if 'allow' in headers_l and '9' not in skip_list:
    methods = headers_l["allow"]
    if any(method in methods for method in t_methods):
        print_detail_r('[imethods_hh]', is_red=True)
        if not args.brief:
            match_method = [x for x in t_methods if x in methods]
            match_method_str = ', '.join(match_method)
            print_detail_l('[imethods_s]')
            print(match_method_str)
            print_detail('[imethods]')
        i_cnt[0] += 1

cache_header = headers_l.get("cache-control", '')
if cache_header and '10' not in skip_list:
    if not any(elem in cache_header for elem in t_cachev):
        print_details('[icachev_h]', '[icachev]', 'd', i_cnt)
    if not all(elem in cache_header for elem in t_cache):
        print_details('[icache_h]', '[icache]', 'd', i_cnt)

if 'clear-site-data' in headers_l and '11' not in skip_list:
    clsdata_header = headers_l['clear-site-data']
    if unsafe_scheme:
        print_details('[icsd_h]', '[icsd]', 'd', i_cnt)
    if not any(elem in clsdata_header for elem in t_csdata):
        print_details('[icsdn_h]', '[icsdn]', 'd', i_cnt)

contdig_header = headers_l.get('content-digest', '')
if contdig_header and '12' not in skip_list:
    if not any(elem in contdig_header for elem in t_digest_sec):
        print_details('[icontdig_h]', '[icontdig]', 'd', i_cnt)
    if any(elem in contdig_header for elem in t_digest_ins):
        print_details('[icontdigi_h]', '[icontdigi]', 'm', i_cnt)

if 'content-dpr' in headers_l and '13' not in skip_list:
    print_details('[ixcdpr_h]', '[ixcdprd]', 'd', i_cnt)

cdis_header = headers_l.get("content-disposition", '')
if cdis_header and ('14' not in skip_list) and (any(elem in cdis_header for
                                                    elem in t_contdisp)):
    print_details('[ixcdisp_h]', '[ixcdisp]', 'd', i_cnt)

cencod_header = headers_l.get("content-enconding", '')
if cencod_header and not any(elem in cencod_header for elem in t_cencoding) \
     and '15' not in skip_list:
    print_details('[icencod_h]', '[icencod]', 'd', i_cnt)

if 'content-security-policy' in headers_l and '16' not in skip_list:
    csp_h = headers_l['content-security-policy']
    if not any(elem in csp_h for elem in t_csp_dirs):
        print_details('[icsi_h]', '[icsi]', 'd', i_cnt)
    if ('=' in csp_h) and not (any(elem in csp_h for elem in t_csp_equal)):
        print_details('[icsn_h]', '[icsn]', 'd', i_cnt)
    csp_analyze_content(csp_h)
    if t_csp_checks[0] in csp_h and t_csp_checks[1] not in headers:
        print_details('[icspi_h]', '[icspi]', 'm', i_cnt)
    csp_check_unknown(csp_h)
    if t_csp_checks[2] in csp_h:
        print_details('[icsu_h]', '[icsu]', 'd', i_cnt)
    csp_check_hashes(csp_h)
    if t_csp_checks[3] in csp_h:
        csp_check_nonces(csp_h)
    if re.search(RE_PATTERN[1], csp_h):
        csp_check_ip(csp_h)

if 'content-security-policy-report-only' in headers_l and '17' not in \
     skip_list:
    csp_ro_header = headers_l['content-security-policy-report-only']
    if any(elem in csp_ro_header for elem in l_csp_ro_dep):
        print_detail_r('[icsiro_d]', is_red=True)
        if not args.brief:
            matches_csp_ro = [x for x in l_csp_ro_dep if x in csp_ro_header]
            print_detail_l('[icsi_d_s]')
            print(', '.join(f"'{x}'" for x in matches_csp_ro))
            print_detail('[icsiro_d_r]')
        i_cnt[0] += 1
    if 'report-to' not in csp_ro_header:
        print_details('[icsiroi_d]', '[icsiroi]', 'd', i_cnt)

ctype_header = headers_l.get('content-type', '')
if ctype_header and '18' not in skip_list:
    if any(elem in ctype_header for elem in t_legacy):
        print_details('[ictlg_h]', '[ictlg]', 'm', i_cnt)
    if 'html' not in ctype_header:
        print_details('[ictlhtml_h]', '[ictlhtml]', 'd', i_cnt)
    if any(elem in ctype_header for elem in t_ct_mime) and ('charset' not in
                                                            ctype_header):
        print_details('[ictlchar_h]', '[ictlchar]', 'd', i_cnt)

if http_equiv:
    ctype_meta = any('content-type' in name for name, _ in http_equiv)
    if ctype_meta and not any(val in content for val in t_ct_equiv for _,
                              content in http_equiv):
        print_details('[ictlmeta_h]', '[ictlmeta]', 'm', i_cnt)

if 'critical-ch' in headers_l and unsafe_scheme and '19' not in skip_list:
    print_details('[icrch_h]', '[icrch]', 'd', i_cnt)

if 'cross-origin-embedder-policy' in headers_l and '20' not in skip_list:
    coep_h = headers_l['cross-origin-embedder-policy']
    if not any(elem in coep_h for elem in t_coep):
        print_details('[icoep_h]', '[icoep]', 'd', i_cnt)
    if 'credentialless' in coep_h:
        print_details('[icoepu_h]', '[icoepu]', 'd', i_cnt)

if 'cross-origin-embedder-policy-report-only' in headers_l and \
        '21' not in skip_list:
    coepr_h = headers_l['cross-origin-embedder-policy-report-only']
    if not any(elem in coepr_h for elem in t_coepr):
        print_details('[icoepr_h]', '[icoepr]', 'd', i_cnt)

if 'cross-origin-opener-policy' in headers_l and '22' not in skip_list:
    coop_h = headers_l['cross-origin-opener-policy']
    if not any(elem in coop_h for elem in t_coop):
        print_details('[icoop_h]', '[icoop]', 'd', i_cnt)
    if 'unsafe-none' in coop_h:
        print_details('[icoopi_h]', '[icoopi]', 'd', i_cnt)

if 'cross-origin-opener-policy-report-only' in headers_l and \
      '23' not in skip_list:
    coopr_h = headers_l['cross-origin-opener-policy-report-only']
    if not any(elem in coopr_h for elem in t_coop):
        print_details('[icoopr_h]', '[icoopr]', 'd', i_cnt)

if 'cross-origin-resource-policy' in headers_l and '24' not in skip_list:
    corp_h = headers_l['cross-origin-resource-policy']
    if not any(elem in corp_h for elem in t_corp):
        print_details('[icorp_h]', '[icorp]', 'd', i_cnt)

if 'digest' in headers_l and '25' not in skip_list:
    print_details('[idig_h]', '[idig]', 'd', i_cnt)

if 'document-isolation-policy' in headers_l and '26' not in skip_list:
    doci_h = headers_l['document-isolation-policy']
    if not any(elem in doci_h for elem in t_doci):
        print_details('[idocpi_h]', '[idocpi]', 'd', i_cnt)

if 'document-policy' in headers_l and '27' not in skip_list:
    docp_h = headers_l['document-policy']
    if not any(elem in docp_h for elem in t_docp):
        print_details('[idocp_h]', '[idoc]', 'm', i_cnt)

if 'etag' in headers_l and '28' not in skip_list:
    print_details('[ieta_h]', '[ieta]', 'd', i_cnt)

if 'expect-ct' in headers_l and '29' not in skip_list:
    print_details('[iexct_h]', '[iexct]', 'm', i_cnt)

if 'expires' in headers_l and any(elem in headers_l.get('cache-control', '')
                                  for elem in t_excc) and '30' \
                                    not in skip_list:
    print_details('[iexpi_h]', '[iexpi]', 'd', i_cnt)

if 'feature-policy' in headers_l and '31' not in skip_list:
    print_details('[iffea_h]', '[iffea]', 'd', i_cnt)

if unsafe_scheme:
    print_details('[ihttp_h]', '[ihttp]', 'd', i_cnt)

if 'integrity-policy' in headers_l and '33' not in skip_list:
    ipol_header = headers_l['integrity-policy']
    if not any(elem in ipol_header for elem in t_ipol):
        print_details('[ipol_h]', '[ipol]', 'd', i_cnt)

if 'integrity-policy-report-only' in headers_l and '34' not in skip_list:
    ipol_header = headers_l['integrity-policy-report-only-policy']
    if not any(elem in ipol_header for elem in t_ipol):
        print_details('[ipolr_h]', '[ipolr]', 'd', i_cnt)

if ('keep-alive' in headers_l and headers_l['keep-alive'] and
    ('connection' not in headers_l or
     headers_l['connection'] != 'keep-alive')) and '35' not in skip_list:
    print_details('[ickeep_h]', '[ickeep]', 'd', i_cnt)

if 'large-allocation' in headers_l and '36' not in skip_list:
    print_details('[ixlalloc_h]', '[ixallocd]', 'd', i_cnt)

if 'mcp-session-id' in headers and '37' not in skip_list:
    print_details('[imcp_h]', '[imcp]', 'm', i_cnt)

if 'nel' in headers_l and '38' not in skip_list:
    nel_header = headers_l['nel']
    if not any(elem in nel_header for elem in t_nel_dir):
        print_details('[inel_h]', '[inel]', 'd', i_cnt)
    if not all(elem in nel_header for elem in t_nel_req):
        print_details('[inelm_h]', '[inelm]', "d", i_cnt)

if 'no-vary-search' in headers_l and '39' not in skip_list:
    nvarys_header = headers_l['no_vary-search']
    if not any(elem in nvarys_header for elem in t_nvarysearch):
        print_details('[ifnvarys_h]', '[ifnvarys]', 'd', i_cnt)

observe_brows_header = headers_l.get('observe-browsing-topics', '')
if observe_brows_header and '?1' not in observe_brows_header and \
     '40' not in skip_list:
    print_details('[iobsb_h]', '[iobsb]', 'd', i_cnt)

if 'onion-location' in headers_l and '41' not in skip_list:
    print_details('[ionloc_h]', '[ionloc]', 'm', i_cnt)

if 'origin-agent-cluster' in headers_l and '42' not in skip_list:
    origin_cluster_h = headers_l['origin-agent-cluster']
    if not any(elem in origin_cluster_h for elem in l_origcluster):
        print_details('[iorigcluster_h]', '[iorigcluster]', 'd', i_cnt)

if 'p3p' in headers_l and '43' not in skip_list:
    print_details('[ip3p_h]', '[ip3p]', 'd', i_cnt)

if 'permissions-policy' in headers_l and '44' not in skip_list:
    perm_header = headers_l['permissions-policy']
    if not any(elem in perm_header for elem in t_per_ft):
        print_details('[ifpoln_h]', '[ifpoln]', 'm', i_cnt)
    permissions_analyze_content(perm_header, i_cnt)

if 'pragma' in headers_l and '45' not in skip_list:
    print_details('[iprag_h]', '[iprag]', 'd', i_cnt)

if 'proxy-authenticate' in headers_l and '46' not in skip_list:
    prxyauth_h = headers_l['proxy-authenticate']
    if 'basic' in prxyauth_h and unsafe_scheme:
        print_details('[iprxauth_h]', '[ihbas]', 'd', i_cnt)
    if not any(elem in prxyauth_h for elem in t_proxy_auth):
        print_details('[iprxauthn_h]', '[iprxauthn]', 'd', i_cnt)

if 'public-key-pins' in headers_l and '47' not in skip_list:
    print_details('[ipkp_h]', '[ipkp]', 'd', i_cnt)

if 'public-key-pins-report-only' in headers_l and '48' not in skip_list:
    print_details('[ipkpr_h]', '[ipkp]', 'd', i_cnt)

referrer_header = headers_l.get('referrer-policy', '')
if referrer_header and '49' not in skip_list:
    if ',' in referrer_header:
        print_details('[irefd_h]', '[irefd]', 'd', i_cnt)
    if not any(elem in referrer_header for elem in t_ref_secure):
        print_details('[iref_h]', '[iref]', 'd', i_cnt)
    if 'unsafe-url' in referrer_header:
        print_details('[irefi_h]', '[irefi]', 'd', i_cnt)
    if not any(elem in referrer_header for elem in t_ref_values):
        print_details('[irefn_h]', '[irefn]', 'd', i_cnt)

refresh_header = headers_l.get('refresh', '')
if refresh_header and '50' not in skip_list and \
     any(elem in refresh_header for elem in t_refresh):
    print_details('[irefr_h]', '[irefr]', 'd', i_cnt)

if 'report-to' in headers_l and '51' not in skip_list:
    print_details('[irept_h]', '[irept]', 'd', i_cnt)

report_h = headers_l.get('reporting-endpoints', '')
if report_h and '52' not in skip_list and HTTP_SCHEMES[0] in report_h:
    print_details('[irepe_h]', '[irepe]', 'd', i_cnt)

repdig_header = headers_l.get('repr-digest', '')
if repdig_header and '53' not in skip_list:
    if not any(elem in repdig_header for elem in t_digest_sec):
        print_details('[irepdig_h]', '[irepdig]', 'd', i_cnt)
    if any(elem in repdig_header for elem in t_digest_ins):
        print_details('[irepdigi_h]', '[irepdigi]', 'm', i_cnt)

if 'server-timing' in headers_l and '54' not in skip_list:
    print_details('[itim_h]', '[itim]', 'd', i_cnt)

servwall_header = headers_l.get('service-worker-allowed', '')
if servwall_header and '55' not in skip_list and servwall_header == '/':
    print_details('[itwall_h]', '[itwall]', 'm', i_cnt)

stc_header = headers_l.get("set-cookie", '')
if stc_header and '56' not in skip_list:
    if not unsafe_scheme:
        check_unsafe_cookies()
    if unsafe_scheme:
        if 'secure' in stc_header:
            print_details('[iseti_h]', '[iseti]', "d", i_cnt)
        if any(prefix in stc_header for prefix in t_cookie_prf):
            print_details('[ispref_m]', '[ispref]', "d", i_cnt)
    if "samesite=none" in stc_header and "secure" not in stc_header:
        print_details('[iseti_m]', '[isetm]', "d", i_cnt)

setlogin_header = headers_l.get("set-login", '')
if setlogin_header and not any(elem in setlogin_header for elem in t_setlogin)\
     and '57' not in skip_list:
    print_details('[islogin_h]', '[islogin]', 'd', i_cnt)

if 'sourcemap' in headers_l and '58' not in skip_list:
    print_details('[ismap_m]', '[ismap]', 'd', i_cnt)

if 'speculation-rules' in headers_l and '59' not in skip_list:
    print_details('[ispec_m]', '[ispec]', 'm', i_cnt)

if 'strict-dynamic' in headers_l and '60' not in skip_list:
    print_details('[isdyn_h]', '[isdyn]', 'd', i_cnt)

sts_header = headers_l.get('strict-transport-security', '')
if sts_header and '61' not in skip_list:
    try:
        age = int(''.join(filter(str.isdigit, sts_header)))
        if unsafe_scheme:
            print_details('[ihsts_h]', '[ihsts]', 'd', i_cnt)
        if not all(elem in sts_header for elem in t_sts_dir) or age < 31536000:
            print_details('[ists_h]', '[ists]', 'm', i_cnt)
        if 'preload' in sts_header and (t_sts_dir[0] not in sts_header
                                        or age < 31536000):
            print_details('[istsr_h]', '[istsr]', 'd', i_cnt)
        if ',' in sts_header:
            print_details('[istsd_h]', '[istsd]', 'd', i_cnt)
    except ValueError:
        print_details('[ists_h]', '[ists]', 'm', i_cnt)

if 'supports-loading-mode' in headers_l and '62' not in skip_list:
    support_mode_h = headers_l['supports-loading-mode']
    if unsafe_scheme:
        print_details('[islmodei_h]', '[islmodei]', 'd', i_cnt)
    if not any(elem in support_mode_h for elem in t_support_mode):
        print_details('[islmode_h]', '[islmode]', 'd', i_cnt)

if 'surrogate-control' in headers_l and '63' not in skip_list:
    surrogate_mode_h = headers_l['surrogate-control']
    if not any(elem in surrogate_mode_h for elem in t_surrogate):
        print_details('[isurrmode_h]', '[isurrmode]', 'd', i_cnt)

if headers_l.get('timing-allow-origin', '') == '*' and '64' not in skip_list:
    print_details('[itao_h]', '[itao]', 'd', i_cnt)

if 'tk' in headers_l and '65' not in skip_list:
    print_details('[ixtk_h]', '[ixtkd]', 'd', i_cnt)

if 'trailer' in headers_l and '66' not in skip_list:
    trailer_h = headers_l['trailer']
    if any(elem in trailer_h for elem in t_trailer):
        print_detail_r('[itrailer_h]', is_red=True)
        if not args.brief:
            matches_trailer = [x for x in t_trailer if x in trailer_h]
            print_detail_l('[itrailer_d_s]')
            print(', '.join(matches_trailer))
            print_detail('[itrailer_d_r]')
        i_cnt[0] += 1

if 'transfer-encoding' in headers_l and '67' not in skip_list:
    transfer_h = headers_l['transfer-encoding']
    if not any(elem in transfer_h for elem in t_transfer):
        print_details('[ictrf_h]', '[itrf]', 'd', i_cnt)

if 'vary' in headers_l and '68' not in skip_list:
    print_details('[ixvary_h]', '[ixvary]', 'm', i_cnt)

wcondig_header = headers_l.get('want-content-digest', '')
if wcondig_header and '69' not in skip_list:
    if not any(elem in wcondig_header for elem in t_digest_sec):
        print_details('[iwcondig_h]', '[iwcondig]', 'd', i_cnt)
    if any(elem in wcondig_header for elem in t_digest_ins):
        print_details('[iwcondigi_h]', '[iwcondigi]', 'm', i_cnt)

if 'want-digest' in headers_l and '70' not in skip_list:
    print_details('[ixwandig_h]', '[ixwandig]', 'd', i_cnt)

wreprdig_header = headers_l.get('want-repr-digest', '')
if wreprdig_header and '71' not in skip_list:
    if not any(elem in wreprdig_header for elem in t_digest_sec):
        print_details('[iwreprdig_h]', '[iwreprdig]', 'd', i_cnt)
    if any(elem in wreprdig_header for elem in t_digest_ins):
        print_details('[iwreprdigi_h]', '[iwreprdigi]', 'm', i_cnt)

if 'warning' in headers_l and '72' not in skip_list:
    print_details('[ixwar_h]', '[ixward]', 'd', i_cnt)

wwwa_header = headers_l.get('www-authenticate', '')
if wwwa_header and unsafe_scheme and ('basic' in wwwa_header) and '73' not in \
     skip_list:
    print_details('[ihbas_h]', '[ihbas]', 'd', i_cnt)

if 'x-content-security-policy' in headers_l and '74' not in skip_list:
    print_detail_r('[ixcsp_h]', is_red=True)
    i_cnt[0] += 1
    if not args.brief:
        print_detail('[ixcsp]', num_lines=5)

if 'x-content-security-policy-report-only' in headers_l and '75' not in \
     skip_list:
    print_details('[ixcspr_h]', '[ixcspr]', 'd', i_cnt)

if 'x-content-type-options' in headers_l and '76' not in skip_list:
    if ',' in headers_l['x-content-type-options']:
        print_details('[ictpd_h]', '[ictpd]', 'm', i_cnt)
    elif 'nosniff' not in headers_l['x-content-type-options']:
        print_details('[ictp_h]', '[ictp]', 'd', i_cnt)

if headers_l.get('x-dns-prefetch-control', '') == 'on' and '77' not in \
     skip_list:
    print_details('[ixdp_h]', '[ixdp]', 'd', i_cnt)

if 'x-download-options' in headers_l and '78' not in skip_list:
    print_details('[ixdow_h]', '[ixdow]', 'm', i_cnt)

xfo_header = headers_l.get('x-frame-options', '')
if xfo_header and '79' not in skip_list:
    if ',' in xfo_header:
        print_details('[ixfo_h]', '[ixfo]', 'm', i_cnt)
    if 'allow-from' in xfo_header:
        print_details('[ixfod_h]', '[ixfod]', 'm', i_cnt)
    if xfo_header not in t_xfo_dir:
        print_details('[ixfoi_h]', '[ixfodi]', 'm', i_cnt)

if 'x-pad' in headers_l and '80' not in skip_list:
    print_details('[ixpad_h]', '[ixpad]', 'd', i_cnt)

permcross_header = headers_l.get('x-permitted-cross-domain-policies', '')
if permcross_header and '81' not in skip_list:
    if not any(elem in permcross_header for elem in t_permcross):
        print_details('[ixpermcross_h]', '[ixpermcross]', 'm', i_cnt)
    if 'all' in permcross_header:
        print_details('[ixpermcrossu_h]', '[ixpermcrossu]', 'm', i_cnt)
    if ',' in permcross_header:
        print_details('[ixpermcrossd_h]', '[ixpermcrossd]', 'm', i_cnt)

if headers_l.get('x-pingback', '').endswith('xmlrpc.php') and '82' not in \
     skip_list:
    print_details('[ixpb_h]', '[ixpb]', 'd', i_cnt)

robots_header = headers_l.get('x-robots-tag', '')
if robots_header and '83' not in skip_list:
    if not any(elem in robots_header for elem in t_robots):
        print_details('[ixrobv_h]', '[ixrobv]', 'm', i_cnt)
    if 'all' in robots_header:
        print_details('[ixrob_h]', '[ixrob]', 'm', i_cnt)

if 'x-runtime' in headers_l and '84' not in skip_list:
    print_details('[ixrun_h]', '[ixrun]', 'd', i_cnt)

if 'x-sourcemap' in headers_l and '85' not in skip_list:
    print_details('[ixsrc_h]', '[ixsrc]', 'd', i_cnt)

if 'x-ua-compatible' in headers_l and '86' not in skip_list:
    print_details('[ixuacom_h]', '[ixuacom]', 'm', i_cnt)

if http_equiv:
    x_ua_meta = any('x-ua-compatible' in item for item in http_equiv)
    if x_ua_meta and not any('IE=edge' in item for tuple in http_equiv for item
                             in tuple):
        print_details('[ixuameta_h]', '[ixuameta]', 'd', i_cnt)

if 'x-webkit-csp' in headers_l and '87' not in skip_list:
    print_detail_r('[ixwcsp_h]', is_red=True)
    i_cnt[0] += 1
    if not args.brief:
        print_detail('[ixcsp]', num_lines=5)

if 'x-webkit-csp-report-only' in headers_l and '88' not in skip_list:
    print_details('[ixwcspr_h]', '[ixcspr]', 'd', i_cnt)

if 'x-xss-protection' in headers_l and '89' not in skip_list:
    print_detail_r('[ixxpdp_h]', is_red=True)
    i_cnt[0] += 1
    if not args.brief:
        print_detail('[ixxpdp]', num_lines=6)
    if '0' not in headers_l['x-xss-protection']:
        print_detail_r('[ixxp_h]', is_red=True)
        i_cnt[0] += 1
        if not args.brief:
            print_detail('[ixxp]', num_lines=6)
    if ',' in headers_l['x-xss-protection']:
        print_details('[ixxpd_h]', '[ixxpd]', 'd', i_cnt)

if args.brief and i_cnt[0] != 0:
    print("")
if i_cnt[0] == 0:
    print_nowarnings()
print("")

# Section '5. Empty HTTP Response Headers Values'
print_detail_r('[5empty]')
l_empty = []

if not args.brief:
    print_detail('[aemp]')

e_cnt = print_empty_headers(headers, l_empty)

print("") if e_cnt != 0 else print_nowarnings()
print("")

# Section '6. Browser Compatibility for Enabled HTTP Security Headers'
# Ref: https://caniuse.com/
print_detail_r('[6compat]')

t_sec = ('Access-Control-Allow-Credentials', 'Access-Control-Allow-Headers',
         'Access-Control-Allow-Methods', 'Access-Control-Expose-Headers',
         'Access-Control-Max-Age', 'Cache-Control', 'Clear-Site-Data',
         'Content-Disposition', 'Content-Security-Policy',
         'Content-Security-Policy-Report-Only', 'Content-Type', 'Critical-CH',
         'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy',
         'Cross-Origin-Resource-Policy', 'Document-Policy', 'ETag',
         'Expect-CT', 'Feature-Policy', 'Integrity-Policy',
         'Integrity-Policy-Report-Only', 'NEL', 'Observe-Browsing-Topics',
         'Origin-Agent-Cluster', 'Permissions-Policy', 'Pragma',
         'Proxy-Authenticate', 'Referrer-Policy', 'Refresh', 'Report-To',
         'Reporting-Endpoints', 'Server-Timing', 'Service-Worker-Allowed',
         'Set-Cookie', 'Set-Login', 'Speculation-Rules',
         'Strict-Transport-Security', 'Supports-Loading-Mode',
         'Timing-Allow-Origin', 'Trailer', 'Vary', 'WWW-Authenticate',
         'X-Content-Type-Options', 'X-DNS-Prefetch-Control', 'X-Frame-Options',
         'X-XSS-Protection')

compat_headers = sorted(header for header in t_sec if header in headers)

print_browser_compatibility(compat_headers) if compat_headers else \
    print_nosec_headers()

# Summary of the analysis and changes compared to the previous one
print(linesep.join(['']*2))
end = time()
print_detail_r('[7result]')
if '-c' not in sys.argv:
    get_analysis_results()

# Exporting analysis results according to the file type
if args.output:
    final_filename = f"{tmp_filename[:-5]}.{args.output}"
    sys.stdout = orig_stdout
    tmp_filename_content.close()
    check_output_format(args, final_filename, reliable, tmp_filename)
