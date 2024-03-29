#! /usr/bin/env python3

# 'humble' (HTTP Headers Analyzer)
# https://github.com/rfc-st/humble/
#
# MIT License
#
# Copyright (c) 2020-2024 Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)
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

# Advice:
# Use the information provided by 'humble' wisely. There is *far* more merit in
# helping others, learning and teaching than in attacking, harming or taking
# advantage. Do not just be a 'Script kiddie': if this really interests you
# learn, research and become a Security Analyst!.

# Greetings:
# Alba, Aleix, Alejandro (x3), Álvaro, Ana, Carlos (x3), David (x3), Eduardo,
# Eloy, Fernando, Gabriel, Íñigo, Joanna, Juan Carlos, Juán, Julián, Julio,
# Iván, Lourdes, Luis Joaquín, María Antonia, Marta, Miguel, Miguel Angel,
# Montse, Naiara, Pablo, Sergio, Ricardo & Rubén!.

from time import time
from shlex import quote
from datetime import datetime
from urllib.parse import urlparse
from os import linesep, path, remove
from colorama import Fore, Style, init
from requests.adapters import HTTPAdapter
from collections import Counter, defaultdict
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import re
import csv
import ssl
import sys
import json
import shutil
import platform
import requests
import contextlib
import tldextract
import subprocess
import concurrent.futures

BANNER = '''  _                     _     _
 | |__  _   _ _ __ ___ | |__ | | ___
 | '_ \\| | | | '_ ` _ \\| '_ \\| |/ _ \\
 | | | | |_| | | | | | | |_) | |  __/
 |_| |_|\\__,_|_| |_| |_|_.__/|_|\\___|
'''
BOLD = ("[0.", "HTTP R", "[1.", "[2.", "[3.", "[4.", "[5.", "[Cabeceras")
BRIGHT_RED = f"{Style.BRIGHT}{Fore.RED}"
CANIUSE_URL = ': https://caniuse.com/?search='
CLEAN_LINES = '\x1b[1A\x1b[2K\x1b[1A\x1b[2K\x1b[1A\x1b[2K'
CSV_SECTION = ['0section', '0headers', '1missing', '2fingerprint',
               '3depinsecure', '4empty', '5compat']
FORCED_CIPHERS = ":".join(["HIGH", "!DH", "!aNULL"])
GIT_URL = ['https://raw.githubusercontent.com/rfc-st/humble/master/humble.py',
           'https://github.com/rfc-st/humble']
HUM_D = ['additional', 'l10n']
HUM_DESC = "'humble' (HTTP Headers Analyzer)"
HUM_F = ['analysis_h.txt', 'check_path_permissions', 'fingerprint.txt',
         'guides.txt', 'details_es.txt', 'details.txt', 'user_agents.txt',
         'insecure.txt', 'html_template.html']
IP_PATTERN = (r'^(?:\d{1,3}\.){3}\d{1,3}$|'
              r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
LINE_PATTERN = r'\[(.*?)\]'
# https://data.iana.org/TLD/tlds-alpha-by-domain.txt
NON_RU_TLD = ['CYMRU', 'GURU', 'PRU']
PATH_PATTERN = (r'\.\./|/\.\.|\\\.\.|\\\.\\|'
                r'%2e%2e%2f|%252e%252e%252f|%c0%ae%c0%ae%c0%af|'
                r'%uff0e%uff0e%u2215|%uff0e%uff0e%u2216')
REF_ERROR = [' Ref  : https://developers.cloudflare.com/support/\
troubleshooting/cloudflare-errors/troubleshooting-cloudflare-5xx-errors/',
             ' Ref  : https://developer.mozilla.org/en-US/docs/Web/HTTP/Status\
/']
REF_LINKS = [' Ref  : ', ' Ref: ', 'Ref  :', 'Ref: ']
RU_CHECK = ['https://ipapi.co/country_name/', 'RU', 'Russia']
SCHEME = ['http:', 'https:']
URL_S = ' URL  : '

export_date = datetime.now().strftime("%Y%m%d")
now = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
humble_local_v = datetime.strptime('2024-03-29', '%Y-%m-%d').date()


class SSLContextAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        # Yes, certificates and hosts must always be checked/verified on HTTPS
        # connections. However, and within the scope of 'humble', I have
        # chosen to disable these checks so that in certain cases (e.g.
        # development environments, hosts with very old servers/software,
        # self-signed certificates, etc) the URL can still be analyzed.
        context = ssl._create_unverified_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.cert_reqs = ssl.CERT_NONE
        context.set_ciphers(FORCED_CIPHERS)
        kwargs['ssl_context'] = context
        return super(SSLContextAdapter, self).init_poolmanager(*args, **kwargs)


def check_python_version():
    exit(print_detail('[python_version]', 3)) if sys.version_info < (3, 9) \
        else None


def check_humble_updates(humble_local_v):
    try:
        repo_check = requests.get(GIT_URL[0], timeout=10).text
        humble_remote = re.search(r"\d{4}-\d{2}-\d{2}", repo_check).group()
        humble_remote_v = datetime.strptime(humble_remote, '%Y-%m-%d').date()
        if humble_remote_v > humble_local_v:
            print(f"\n{get_detail('[humble_not_recent]')[:-1]}\
                  \n{get_detail('[github_humble]', replace=True)}")
        else:
            print(f"\n {get_detail('[humble_recent]', replace=True)}")
    except requests.exceptions.RequestException:
        print(f"\n{get_detail('[update_error]')}")
    sys.exit()


def fng_statistics_top():
    print(f"\n{Style.BRIGHT}{get_detail('[fng_stats]', replace=True)}\
{Style.RESET_ALL}{get_detail('[fng_source]', replace=True)}\n")
    with open(path.join(HUM_D[0], HUM_F[2]), 'r', encoding='utf8') as fng_f:
        fng_lines = fng_f.readlines()
    fng_statistics_top_groups(fng_lines)
    sys.exit()


def fng_statistics_top_groups(fng_lines):
    fng_top_ptrn = r'\[([^\]]+)\]'
    fng_content = Counter(match.strip() for line in fng_lines for match in
                          re.findall(fng_top_ptrn, line))
    excl_cnt = sum(bool(line.startswith('#')) for line in fng_lines) + 2
    headers_cnt = len(fng_lines) - excl_cnt
    fng_statistics_top_result(fng_content, headers_cnt)


def fng_statistics_top_result(fng_content, headers_cnt):
    max_ln_len = max(len(content) for content, _ in
                     fng_content.most_common(20))
    print(f"{get_detail('[fng_top]', replace=True)} {headers_cnt}\
{get_detail('[fng_top_2]', replace=True)}\n")
    for content, count in fng_content.most_common(20):
        fng_global_pct = round(count / headers_cnt * 100, 2)
        padding_s = ' ' * (max_ln_len - len(content))
        print(f" [{content}]: {padding_s}{fng_global_pct:.2f}% ({count})")


def fng_statistics_term(term):
    print(f"\n{Style.BRIGHT}{get_detail('[fng_stats]', replace=True)}\
{Style.RESET_ALL}{get_detail('[fng_source]', replace=True)}\n")
    with open(path.join(HUM_D[0], HUM_F[2]), 'r', encoding='utf8') as \
            fng_source:
        fng_lines = fng_source.readlines()
    fng_group, term_count = fng_statistics_term_groups(fng_lines, term)
    if not fng_group:
        print(f"{get_detail('[fng_zero]', replace=True)} '{term}'.\n\n\
{get_detail('[fng_zero_2]', replace=True)}.\n")
        sys.exit()
    fng_statistics_term_content(fng_group, term, term_count, fng_lines)


def fng_statistics_term_groups(fng_ln, term):
    fng_group = \
        {match[1].strip()
         for line in fng_ln if (match := re.search(LINE_PATTERN, line)) and
         term.lower() in match[1].lower()}
    term_cnt = sum(bool((match := re.search(LINE_PATTERN, line)) and
                        term.lower() in match[1].lower()) for line in fng_ln)
    return fng_group, term_cnt


def fng_statistics_term_content(fng_group, term, term_count, fng_lines):
    excl_cnt = sum(line.startswith('#') for line in fng_lines) + 2
    headers_cnt = len(fng_lines)-excl_cnt
    fng_pct = round(term_count / headers_cnt * 100, 2)
    print(f"{get_detail('[fng_add]', replace=True)} '{term}': {fng_pct}%\
 ({term_count}{get_detail('[pdf_footer2]', replace=True)} {headers_cnt})")
    fng_statistics_term_sorted(fng_lines, term, fng_group)


def fng_statistics_term_sorted(fng_lines, term, fng_group):
    term_l = term.lower()
    for content in sorted(fng_group):
        print(f"\n [{content}]")
        for line in fng_lines:
            line_l = line.lower()
            if f"[{content.lower()}]" in line_l and term_l in line_l:
                start_index = line.find('[')
                print(f"  {line[:start_index].strip()}")
    sys.exit()


def print_security_guides():
    print_detail('[security_guides]', 1)
    with open(path.join(HUM_D[0], HUM_F[3]), 'r', encoding='utf8') as \
            guides_source:
        for line in guides_source:
            if not line.startswith('#'):
                print(f" {Style.BRIGHT}{line}" if line.startswith('[') else f"\
  {line}", end='')
    sys.exit()


def testssl_command(directory, uri):
    directory = path.abspath(directory)
    testssl_f = path.join(directory, 'testssl.sh')
    if not path.isdir(directory):
        sys.exit(f"\n{get_detail('[notestssl_path]')}")
    if not path.isfile(testssl_f):
        sys.exit(f"\n{get_detail('[notestssl_file]')}")
    else:
        uri_safe = quote(uri)
        # Check './testssl.sh --help' to choose your preferred options
        command = [testssl_f, '-f', '-g', '-p', '-U', '-s', '--hints',
                   uri_safe]
        testssl_analysis(command)
    sys.exit()


def testssl_analysis(command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        while True:
            ln = process.stdout.readline()
            if not ln:
                break
            print(ln, end='')
            if 'Done' in ln:
                process.terminate()
                process.wait()
                sys.exit()
        stdout, stderr = process.communicate()
        print(stdout or '')
        print(stderr or '')
    except subprocess.CalledProcessError as e:
        print(e.stderr)
    except Exception as e:
        print(f"Error running testssl.sh analysis!: {e}")


def get_l10n_details():
    l10n_file_path = path.join(HUM_D[1], HUM_F[4] if args.lang == 'es' else
                               HUM_F[5])
    with open(l10n_file_path, 'r', encoding='utf8') as l10n_source:
        return l10n_source.readlines()


def get_analysis_result():
    print(".:\n")
    print_detail_l('[analysis_time]')
    print(round(end - start, 2), end="")
    print_detail_l('[analysis_time_sec]')
    t_cnt = sum([m_cnt, f_cnt, i_cnt[0], e_cnt])
    current = get_analysis_totals(t_cnt)
    diff = compare_analysis_totals(*current, m_cnt=m_cnt, f_cnt=f_cnt,
                                   i_cnt=i_cnt, e_cnt=e_cnt, t_cnt=t_cnt)
    print("")
    print_analysis_totals(*diff, t_cnt=t_cnt)


def get_analysis_totals(t_cnt):
    with open(HUM_F[0], 'a+', encoding='utf8') as add_analysis, \
         open(HUM_F[0], 'r', encoding='utf8') as all_analysis:
        add_analysis.write(f"{now} ; {URL} ; {m_cnt} ; {f_cnt} ; {i_cnt[0]} ; \
{e_cnt} ; {t_cnt}\n")
        url_ln = [line for line in all_analysis if URL in line]
        return extract_analysis_totals(url_ln) if url_ln else ("First",) * 5


def extract_analysis_totals(url_ln):
    date_var = max(line.split(" ; ")[0] for line in url_ln)
    for line in url_ln:
        if date_var in line:
            *totals, = line.strip().split(' ; ')
            break
    return tuple(totals[2:])


def compare_analysis_totals(*current, m_cnt, f_cnt, i_cnt, e_cnt, t_cnt):
    if current[0] == "First":
        return [get_detail('[first_one]', replace=True)] * 5
    current = [int(val) for val in current]
    totals = [m_cnt - current[0], f_cnt - current[1], i_cnt[0] - current[2],
              e_cnt - current[3], t_cnt - current[4]]
    return [f'+{total}' if total > 0 else str(total) for total in totals]


def print_analysis_totals(*diff, t_cnt):
    literals = ['[missing_cnt]', '[fng_cnt]', '[insecure_cnt]', '[empty_cnt]',
                '[total_cnt]']
    totals = [f"{m_cnt} ({diff[0]})", f"{f_cnt} ({diff[1]})", f"{i_cnt[0]} \
({diff[2]})", f"{e_cnt} ({diff[3]})\n", f"{t_cnt} ({diff[4]})\n"]
    print("")
    for literal, total in zip(literals, totals):
        print(f"{(print_detail_l(literal) or '')[:-1]}{total}")


def analysis_exists(filepath):
    if not path.exists(filepath):
        detail = '[no_analysis]' if args.URL else '[no_global_analysis]'
        print(f"\n{get_detail(detail).strip()}\n")
        sys.exit()


def url_analytics(is_global=False):
    analysis_exists(HUM_F[0])
    with open(HUM_F[0], 'r', encoding='utf8') as c_history:
        analysis_stats = extract_global_metrics(c_history) if is_global else \
            extract_analysis_metrics(c_history)
    stats_s = '[global_stats_analysis]' if is_global else '[stats_analysis]'
    print(f"\n{get_detail(stats_s, replace=True)} {'' if is_global else URL}\
\n")
    for key, value in analysis_stats.items():
        key = f"{Style.BRIGHT}{key}{Style.RESET_ALL}" \
            if (not value or not key.startswith(' ')) else key
        print(f"{key}: {value}")
    sys.exit()


def extract_analysis_metrics(c_history):
    url_ln = [line for line in c_history if URL in line]
    if not url_ln:
        print(f"\n{get_detail('[no_analysis]').strip()}\n")
        sys.exit()
    total_a = len(url_ln)
    first_m = extract_first_metrics(url_ln)
    second_m = [extract_second_metrics(url_ln, i, total_a) for i in
                range(2, 6)]
    third_m = extract_third_metrics(url_ln)
    additional_m = extract_additional_metrics(url_ln)
    fourth_m = extract_highlights(url_ln)
    return print_metrics(total_a, first_m, second_m, third_m, additional_m,
                         fourth_m)


def extract_first_metrics(url_ln):
    first_a = min(f"{line.split(' ; ')[0]}" for line in url_ln)
    latest_a = max(f"{line.split(' ; ')[0]}" for line in url_ln)
    date_w = [(line.split(" ; ")[0],
               int(line.strip().split(" ; ")[-1])) for line in url_ln]
    best_d, best_w = min(date_w, key=lambda x: x[1])
    worst_d, worst_w = max(date_w, key=lambda x: x[1])
    return (first_a, latest_a, best_d, best_w, worst_d, worst_w)


def extract_second_metrics(url_ln, index, total_a):
    metric_c = len([line for line in url_ln if int(line.split(' ; ')[index])
                    == 0])
    return f"{metric_c / total_a:.0%} ({metric_c}\
{get_detail('[pdf_footer2]', replace=True)} {total_a})"


def extract_third_metrics(url_ln):
    fields = [line.strip().split(';') for line in url_ln]
    total_miss, total_fng, total_dep, total_ety = \
        [sum(int(f[i]) for f in fields) for i in range(2, 6)]
    num_a = len(url_ln)
    avg_miss, avg_fng, avg_dep, avg_ety = \
        [t // num_a for t in (total_miss, total_fng, total_dep, total_ety)]
    return (avg_miss, avg_fng, avg_dep, avg_ety)


def extract_additional_metrics(url_ln):
    avg_w = int(sum(int(line.split(' ; ')[-1]) for line in url_ln) /
                len(url_ln))
    year_a, avg_w_y, month_a = extract_date_metrics(url_ln)
    return (avg_w, year_a, avg_w_y, month_a)


def extract_date_metrics(url_ln):
    year_cnt, year_wng = defaultdict(int), defaultdict(int)
    for line in url_ln:
        date_str = line.split(' ; ')[0].split()[0]
        year, _, _ = map(int, date_str.split('/'))
        year_cnt[year] += 1
        year_wng[year] += int(line.split(' ; ')[-1])
    years_str = generate_date_groups(year_cnt, url_ln)
    avg_wng_y = sum(year_wng.values()) // len(year_wng)
    return years_str, avg_wng_y, year_wng


def generate_date_groups(year_cnt, url_ln):
    years_str = []
    for year in sorted(year_cnt.keys()):
        year_str = f" {year}: {year_cnt[year]} \
{get_detail('[analysis_y]').rstrip()}"
        month_cnts = get_month_counts(year, url_ln)
        months_str = '\n'.join([f"   ({count}){month_name.rstrip()}" for
                                month_name, count in month_cnts.items()])
        year_str += f"\n{months_str}\n"
        years_str.append(year_str)
    return '\n'.join(years_str)


def get_month_counts(year, url_ln):
    month_cnts = defaultdict(int)
    for line in url_ln:
        date_str = line.split(' ; ')[0].split()[0]
        line_year, line_month, _ = map(int, date_str.split('/'))
        if line_year == year:
            month_cnts[get_detail(f'[month_{line_month:02d}]')] += 1
    return month_cnts


def extract_highlights(url_ln):
    sections = ['[missing_cnt]', '[fng_cnt]', '[insecure_cnt]', '[empty_cnt]']
    fields_h = [2, 3, 4, 5]
    return [f"{print_detail_l(sections[i], analytics=True)}\n"
            f"  {print_detail_l('[best_analysis]', analytics=True)}: \
{get_highlights(url_ln, fields_h[i], min)}\n"
            f"  {print_detail_l('[worst_analysis]', analytics=True)}: \
{get_highlights(url_ln, fields_h[i], max)}\n"
            for i in range(len(fields_h))]


def get_highlights(url_ln, field_index, func):
    values = [int(line.split(';')[field_index].strip()) for line in url_ln]
    target_value = func(values)
    target_line = next(line for line in url_ln
                       if int(line.split(';')[field_index].strip()) ==
                       target_value)
    return target_line.split(';')[0].strip()


def print_metrics(total_a, first_m, second_m, third_m, additional_m, fourth_m):
    basic_m = get_basic_metrics(total_a, first_m)
    error_m = get_security_metrics(second_m)
    warning_m = get_warnings_metrics(additional_m)
    averages_m = get_averages_metrics(third_m)
    fourth_m = get_highlights_metrics(fourth_m)
    analysis_year_m = get_date_metrics(additional_m)
    totals_m = {**basic_m, **error_m, **warning_m, **averages_m, **fourth_m,
                **analysis_year_m}
    return {get_detail(key, replace=True): value for key, value in
            totals_m.items()}


def get_basic_metrics(total_a, first_m):
    return {'[main]': "", '[total_analysis]': total_a,
            '[first_analysis_a]': first_m[0], '[latest_analysis]': first_m[1],
            '[best_analysis]': f"{first_m[2]} \
{get_detail('[total_warnings]', replace=True)}{first_m[3]})",
            '[worst_analysis]': f"{first_m[4]} \
{get_detail('[total_warnings]', replace=True)}{first_m[5]})\n"}


def get_security_metrics(second_m):
    return {'[analysis_y]': "", '[no_missing]': second_m[0],
            '[no_fingerprint]': second_m[1],
            '[no_ins_deprecated]': second_m[2],
            '[no_empty]': f"{second_m[3]}\n"}


def get_warnings_metrics(additional_m):
    return {'[averages]': "", '[average_warnings]': f"{additional_m[0]}",
            '[average_warnings_year]': f"{additional_m[2]}"}


def get_averages_metrics(third_m):
    return {'[average_miss]': f"{third_m[0]}",
            '[average_fng]': f"{third_m[1]}", '[average_dep]': f"{third_m[2]}",
            '[average_ety]': f"{third_m[3]}\n"}


def get_highlights_metrics(fourth_m):
    return {'[highlights]': "\n" + "\n".join(fourth_m)}


def get_date_metrics(additional_m):
    return {'[analysis_year_month]': f"\n{additional_m[1]}"}


def extract_global_metrics(c_history):
    url_ln = list(c_history)
    if not url_ln:
        print(f"\n{get_detail('[no_global_analysis]').strip()}\n")
        sys.exit()
    total_a = len(url_ln)
    first_m = extract_global_first_metrics(url_ln)
    second_m = [extract_second_metrics(url_ln, i, total_a) for i in
                range(2, 6)]
    third_m = extract_third_metrics(url_ln)
    additional_m = extract_additional_metrics(url_ln)
    return print_global_metrics(total_a, first_m, second_m, third_m,
                                additional_m)


def extract_global_first_metrics(url_ln):
    split_lines = [line.split(' ; ') for line in url_ln]
    url_lines = {}
    for entry in split_lines:
        url = entry[1]
        url_lines[url] = url_lines.get(url, 0) + 1
    return get_global_metrics(url_ln, url_lines)


def get_global_metrics(url_ln, url_lines):
    first_a = min(f"{line.split(' ; ')[0]}" for line in url_ln)
    latest_a = max(f"{line.split(' ; ')[0]}" for line in url_ln)
    unique_u = len({line.split(' ; ')[1] for line in url_ln})
    most_analyzed_u = max(url_lines, key=url_lines.get)
    most_analyzed_c = url_lines[most_analyzed_u]
    most_analyzed_cu = f"({most_analyzed_c}) {most_analyzed_u}"
    least_analyzed_u = min(url_lines, key=url_lines.get)
    least_analyzed_c = url_lines[least_analyzed_u]
    least_analyzed_cu = f"({least_analyzed_c}) {least_analyzed_u}"
    most_warnings, least_warnings = get_global_warnings(url_ln)
    return (first_a, latest_a, unique_u, most_analyzed_cu, least_analyzed_cu,
            most_warnings, least_warnings)


def get_global_warnings(url_ln):
    most_warnings = max(url_ln, key=lambda line: int(line.split(' ; ')[-1]))
    least_warnings = min(url_ln, key=lambda line: int(line.split(' ; ')[-1]))
    most_warnings_c, most_warnings_cu = most_warnings.split(' ; ')[1], \
        str(most_warnings.split(' ; ')[-1]).strip()
    most_warning_p = f"({most_warnings_cu}) {most_warnings_c}"
    least_warnings_c, least_warnings_cu = least_warnings.split(' ; ')[1], \
        str(least_warnings.split(' ; ')[-1]).strip()
    least_warnings_p = f"({least_warnings_cu}) {least_warnings_c}"
    return (most_warning_p, least_warnings_p)


def get_basic_global_metrics(total_a, first_m):
    return {'[main]': "", '[total_analysis]': total_a,
            '[total_global_analysis]': str(first_m[2]),
            '[first_analysis_a]': first_m[0],
            '[latest_analysis]': f"{first_m[1]}\n",
            '[most_analyzed]': first_m[3],
            '[least_analyzed]': f"{first_m[4]}\n",
            '[most_warnings]': first_m[5],
            '[least_warnings]': f"{first_m[6]}\n"}


def print_global_metrics(total_a, first_m, second_m, third_m, additional_m):
    basic_m = get_basic_global_metrics(total_a, first_m)
    error_m = get_security_metrics(second_m)
    warning_m = get_warnings_metrics(additional_m)
    averages_m = get_averages_metrics(third_m)
    analysis_year_m = get_date_metrics(additional_m)
    totals_m = {**basic_m, **error_m, **warning_m, **averages_m,
                **analysis_year_m}
    return {get_detail(key, replace=True): value for key, value in
            totals_m.items()}


def csp_store_values(csp_header, l_csp_broad_s, l_csp_insecure_s, i_cnt):
    csp_broad, csp_deprecated, csp_insecure = (set(), set(), set())
    for directive in csp_header.split(';'):
        csp_dir = directive.strip()
        csp_broad.update(value for value in l_csp_broad_s if f' {value} ' in
                         f' {csp_dir} ')
        csp_deprecated.update(value for value in l_csp_dep if value in csp_dir)
        csp_insecure.update(value for value in l_csp_insecure_s if value in
                            csp_dir)
    csp_check_values(csp_broad, csp_deprecated, csp_insecure, i_cnt)
    return (i_cnt)


def csp_check_values(csp_broad, csp_deprecated, csp_insecure, i_cnt):
    if csp_deprecated:
        print_detail_r('[icsi_d]', is_red=True) if args.brief else \
            csp_print_warnings(csp_deprecated, '[icsi_d]', '[icsi_d_s]',
                               '[icsi_d_r]')
    if csp_insecure:
        print_detail_r('[icsh_h]', is_red=True) if args.brief else \
            csp_print_warnings(csp_insecure, '[icsh_h]', '[icsh]', '[icsh_b]')
        if not args.brief:
            print("")
    if csp_broad:
        print_detail_r('[icsw_h]', is_red=True) if args.brief else \
            csp_print_warnings(csp_broad, '[icsw_h]', '[icsw]', '[icsw_b]')
    i_cnt[0] += sum(bool(csp) for csp in (csp_broad, csp_deprecated,
                                          csp_insecure))
    return (i_cnt)


def csp_print_warnings(csp_values, csp_title, csp_desc, csp_refs):
    csp_values = ' '.join(f"'{value}'" for value in csp_values)
    print_detail_r(f'{csp_title}', is_red=True)
    print_detail_l(f'{csp_desc}')
    print(csp_values)
    print_detail(f'{csp_refs}')


def clean_shell_lines(reliable=True):
    if not reliable:
        sys.stdout.write(CLEAN_LINES)
    sys.stdout.write(CLEAN_LINES)


def print_export_path(filename, reliable):
    clean_shell_lines(reliable=False) if reliable else clean_shell_lines()
    print("")
    print_detail_l('[report]')
    print(path.abspath(filename))


def print_nowarnings():
    print_detail('[no_warnings]')


def print_header(header):
    print(f" {header}" if args.output else f"{BRIGHT_RED} {header}")


def print_fng_header(header):
    prefix, _, suffix = [x.strip() for x in header.partition(' [')]
    if args.output:
        print(f" {header}")
    elif '[' in header:
        print(f"{BRIGHT_RED} {prefix}{Style.NORMAL}{Fore.RESET} [{suffix}")
    else:
        print(f"{BRIGHT_RED} {header}")


def print_general_info(reliable):
    if not args.output:
        clean_shell_lines(reliable=False) if reliable else clean_shell_lines()
        print("")
        print(BANNER)
        print(f" ({GIT_URL[1]} | v.{humble_local_v})")
    elif args.output != 'pdf':
        print("")
        print(f"\n{HUM_DESC}\n{GIT_URL[1]} | v.{humble_local_v}\n")
    print_basic_info()
    # Exporting a detailed analysis to CSV/JSON is complicated for now.
    if args.output in ('csv', 'json'):
        print(get_detail('[limited_analysis_note]', replace=True))
    if (status_code is not None and 400 <= status_code <= 451) or reliable or \
       args.redirects or skipped_headers:
        print_extra_info(reliable)


def print_basic_info():
    print(linesep.join(['']*2) if args.output == 'html' or not args.output
          else "")
    print_detail_r('[0section]')
    print_detail_l('[analysis_date]')
    print(f" {now}")
    print(f'{URL_S}{URL}')


def print_extra_info(reliable):
    if (status_code is not None and 400 <= status_code <= 451):
        id_mode = f"[http_{status_code}]"
        if detail := print_detail(id_mode, 0):
            print(detail)
        print(f"{REF_ERROR[1]}{status_code}")
    if reliable:
        print(get_detail('[unreliable_analysis_note]', replace=True))
    if args.redirects:
        print(get_detail('[analysis_redirects_note]', replace=True))
    if skipped_headers:
        print_skipped_headers(skipped_headers)


def print_response_headers():
    print(linesep.join(['']*2))
    print_detail_r('[0headers]')
    for key, value in sorted(headers.items()):
        print(f" {key}:", value) if args.output else print(f" {Fore.CYAN}\
{key}:", value)
    print('\n')


def print_details(short_d, long_d, id_mode, i_cnt):
    print_detail_r(short_d, is_red=True)
    if not args.brief:
        print_detail(long_d, 2) if id_mode == 'd' else print_detail(long_d, 3)
    i_cnt[0] += 1
    return i_cnt


def print_detail(id_mode, num_lines=1):
    idx = l10n_details.index(id_mode + '\n')
    print(l10n_details[idx+1], end='')
    for i in range(1, num_lines+1):
        if idx+i+1 < len(l10n_details):
            print(l10n_details[idx+i+1], end='')


def print_detail_l(id_mode, analytics=False):
    for i, line in enumerate(l10n_details):
        if line.startswith(id_mode):
            if not analytics:
                print(l10n_details[i+1].replace('\n', ''), end='')
            else:
                return l10n_details[i+1].replace('\n', '').replace(':', '')[1:]


def print_detail_r(id_mode, is_red=False):
    style_str = BRIGHT_RED if is_red else Style.BRIGHT
    for i, line in enumerate(l10n_details):
        if line.startswith(id_mode):
            if not args.output:
                print(f"{style_str}{l10n_details[i+1]}", end='')
            else:
                print(l10n_details[i+1], end='')
            if not is_red:
                print("")


def get_detail(id_mode, replace=False):
    for i, line in enumerate(l10n_details):
        if line.startswith(id_mode):
            return (l10n_details[i+1].replace('\n', '')) if replace else \
                l10n_details[i+1]


def get_epilog_detail(id_mode):
    epi_file_path = path.join(HUM_D[1], HUM_F[5])
    with open(epi_file_path, 'r', encoding='utf8') as epi_source:
        epi_lines = epi_source.readlines()
        epi_idx = epi_lines.index(id_mode + '\n')
        return ''.join(epi_lines[epi_idx+1:epi_idx+12])


def print_fingerprint_headers(headers, l_fng, l_fng_ex):
    f_cnt = 0
    match_h = sorted([header for header in headers if any(elem.lower()
                     in headers for elem in l_fng)])
    l_fng = [x.title() for x in l_fng]
    match_h = [x.title() for x in match_h]
    for header in match_h:
        if header in l_fng:
            get_fingerprint_detail(header, headers, l_fng, l_fng_ex, args)
            f_cnt += 1
    return f_cnt


def get_fingerprint_detail(header, headers, l_fng, l_fng_ex, args):
    if not args.brief:
        index_fng = l_fng.index(header)
        print_fng_header(l_fng_ex[index_fng])
        if not headers[header]:
            print(get_detail('[empty_fng]', replace=True))
        else:
            print(f" {headers[header]}")
        print("")
    else:
        print_header(header)


def print_empty_headers(headers, l_empty):
    e_cnt = 0
    for key in sorted(headers):
        if not headers[key]:
            l_empty.append(f"_{key}")
            print_header(key)
            e_cnt += 1
    return e_cnt


def print_browser_compatibility(browser_compat_header):
    for key in browser_compat_header:
        output_string = "  " if args.output == 'html' else " "
        key_string = key if args.output else f"{Fore.CYAN}{key}{Fore.RESET}"
        print(f"{output_string}{key_string}{CANIUSE_URL}\
{key.replace('Content-Security-Policy', 'contentsecuritypolicy2')}")


def check_path_traversal(path):
    path_traversal_ptrn = re.compile(PATH_PATTERN)
    if path_traversal_ptrn.search(path):
        print(f"\n{get_detail('[args_path_traversal]', replace=True)} \
('{path}')")
        sys.exit()


def check_path_permissions(output_path):
    try:
        open(path.join(output_path, HUM_F[1]), 'w')
    except PermissionError:
        parser.error(f"{get_detail('[args_nowr]', replace=True)}\
'{output_path}'")
    else:
        remove(path.join(output_path, HUM_F[1]))


def check_output_path(args, output_path):
    check_path_traversal(args.output_path)
    if args.output is None:
        parser.error(get_detail('[args_nooutputfmt]'))
    elif path.exists(output_path):
        check_path_permissions(output_path)
    else:
        parser.error(f"{get_detail('[args_noexportpath]', replace=True)}\
('{output_path}')")


def parse_user_agent(user_agent=False):
    if not user_agent:
        return {'User-Agent': get_user_agent('1')}
    ua_id = sys.argv[sys.argv.index('-ua') + 1].lstrip('-ua')
    if not args.URL:
        try:
            if int(ua_id) != 0:
                parser.error(get_detail('[args_useragent]'))
            else:
                return {'User-Agent': get_user_agent('0')}
        except ValueError:
            print(f'\n {get_detail("[ua_invalid]", replace=True)}')
            sys.exit()
    if args.URL:
        return {'User-Agent': get_user_agent(ua_id)}


def get_user_agent(ua_param):
    with open(path.join(HUM_D[0], HUM_F[6]), 'r', encoding='utf-8') as \
            ua_source:
        ua_lines = [line.strip() for line in ua_source.readlines() if not
                    line.startswith('#')]
    if ua_param == str(0):
        print_user_agents(ua_lines)
    for line in ua_lines:
        if line.startswith(f"{ua_param}.-"):
            return line[len(f"{ua_param}.-"):].strip()
    print(f'\n {get_detail("[ua_invalid]", replace=True)}')
    sys.exit()


def print_user_agents(ua_lines):
    print(f"\n{Style.BRIGHT}{get_detail('[ua_available]', replace=True)}\
{Style.RESET_ALL}{get_detail('[ua_source]', replace=True)}")
    for line in ua_lines:
        print(f' {line}')
    sys.exit()


def get_insecure_checks():
    insecure_header_set = set()
    with open(path.join(HUM_D[0], HUM_F[7]), "r") as ins_source:
        for line in ins_source:
            if line and not line.startswith('#'):
                header = line.split(':')[0]
                insecure_header_set.add(header.strip().lower())
    header_list = sorted(insecure_header_set)
    return {key: str(index) for index, key in enumerate(header_list)}


def get_skipped_unsupported_headers(args, header_dict):
    skipped_headers, unsupported_headers = [], []
    skipped_headers_v = set()
    for header_name in args.skipped_headers:
        header_name = header_name.strip().lower()
        if header_name in header_dict:
            skipped_headers.append((header_name, header_dict[header_name]))
            skipped_headers_v.add(header_dict[header_name])
        else:
            unsupported_headers.append(header_name)
    return skipped_headers, unsupported_headers, skipped_headers_v


def print_skipped_headers(skipped_headers):
    skipped_headers_full = ' '.join(header[0] for header in skipped_headers)
    quoted_headers = [f"'{header}'" for header in skipped_headers_full.split()]
    final_headers = ', '.join(quoted_headers) if len(quoted_headers) > 1 else \
        quoted_headers[0]
    print_detail_l("[analysis_skipped_note]")
    print(f" {final_headers}")


def print_unsupported_headers(unsupported_headers):
    unsupported_headers_str = ' '.join(unsupported_headers)
    print("")
    print_detail_l("[args_skipped_unknown]")
    print(unsupported_headers_str)
    sys.exit()


def generate_csv(temp_filename, final_filename):
    with open(temp_filename, 'r', encoding='utf-8') as txt_source, \
         open(final_filename, 'w', newline='', encoding='utf-8') as csv_final:
        csv_source = txt_source.read()
        csv_writer = csv.writer(csv_final, quoting=csv.QUOTE_ALL)
        csv_section = [get_detail(f'[{i}]', replace=True) for i in CSV_SECTION]
        csv_writer.writerow([get_detail(f'[{i}]', replace=True) for i in
                             ['csv_section', 'csv_values']])
        parse_csv(csv_writer, csv_source, csv_section)
    print_export_path(final_filename, reliable)
    remove(temp_filename)


def parse_csv(csv_writer, csv_source, csv_section):
    for i in csv_section:
        if i in csv_source:
            csv_content = csv_source.split(i)[1].split('[')[0]
            info_list = [line.strip() for line in csv_content.split('\n') if
                         line.strip()]
            exclude_ln = False
            for csv_ln in info_list:
                if csv_ln.startswith('.:'):
                    exclude_ln = True
                    break
                if not exclude_ln:
                    csv_writer.writerow([i.strip('[]'), csv_ln])


def generate_json(temp_filename, final_filename):
    section0, sectionh, section5 = [get_detail(f'[{i}]', replace=True) for i
                                    in ['0section', '0headers', '5compat']]
    with (open(temp_filename, 'r', encoding='utf8') as txt_source,
          open(final_filename, 'w', encoding='utf8') as json_final):
        txt_content = txt_source.read()
        txt_sections = re.split(r'\[(.*?)\]\n', txt_content)[1:]
        data = {}
        parse_json_sections(txt_sections, data, section0, sectionh, section5)
        json_data = json.dumps(data, indent=4, ensure_ascii=False)
        json_final.write(json_data)
    print_export_path(final_filename, reliable)
    remove(temp_filename)


def parse_json_sections(txt_sections, data, section0, sectionh, section5):
    for i in range(0, len(txt_sections), 2):
        json_section = f"[{txt_sections[i]}]"
        json_content = txt_sections[i + 1].strip()
        if json_section == section5:
            json_content = json_content.split('.:')[0].strip()
        json_lns = json_content.split('\n')
        json_data = write_json_sections(section0, sectionh, section5,
                                        json_section, json_lns)
        data[json_section] = json_data


def write_json_sections(section0, sectionh, section5, json_section, json_lns):
    if json_section in (section0, sectionh, section5):
        json_data = {}
        for line in json_lns:
            if ':' in line:
                key, value = line.split(':', 1)
                json_data[key.strip()] = value.strip()
            else:
                json_data[line.strip()] = ""
    else:
        json_data = [line.strip() for line in json_lns if line.strip()]
    return json_data


def generate_pdf(temp_filename, pdf):
    set_pdf_structure()
    with open(temp_filename, "r", encoding='utf8') as txt_source:
        links_strings = (URL_S, REF_LINKS[2], REF_LINKS[3], CANIUSE_URL)
        for i in txt_source:
            if '[' in i:
                set_pdf_sections(i)
            pdf.set_font(style='B' if any(s in i for s in BOLD) else '')
            for string in links_strings:
                if string in i:
                    set_pdf_links(i, string)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(197, 2.6, text=i, align='L')
    pdf.output(final_filename)
    print_export_path(final_filename, reliable)
    remove(temp_filename)


def set_pdf_structure():
    pdf.alias_nb_pages()
    set_pdf_metadata()
    pdf.set_display_mode(zoom=125)
    pdf.add_page()
    pdf.set_font("Courier", size=9)


def set_pdf_metadata():
    title = f"{get_detail('[pdf_meta_title]', replace=True)} {URL}"
    git_urlc = f"{GIT_URL[1]} | v.{humble_local_v}"
    pdf.set_author(git_urlc)
    pdf.set_creation_date = now
    pdf.set_creator(git_urlc)
    pdf.set_keywords(get_detail('[pdf_meta_keywords]', replace=True))
    pdf.set_lang(get_detail('[pdf_meta_language]'))
    pdf.set_subject(get_detail('[pdf_meta_subject]', replace=True))
    pdf.set_title(title)
    pdf.set_producer(git_urlc)


def set_pdf_sections(i):
    section_dict = {'[0.': '[0section_s]', '[HTTP R': '[0headers_s]',
                    '[1.': '[1missing_s]', '[2.': '[2fingerprint_s]',
                    '[3.': '[3depinsecure_s]', '[4.': '[4empty_s]',
                    '[5.': '[5compat_s]', '[Cabeceras': '[0headers_s]'}
    if match := next((x for x in section_dict if i.startswith(x)), None):
        pdf.start_section(get_detail(section_dict[match]))


def set_pdf_links(i, pdfstring):
    link_prefixes = {REF_LINKS[2]: REF_LINKS[0], REF_LINKS[3]: REF_LINKS[1]}
    links_d = {URL_S: URL, REF_LINKS[2]: i.partition(REF_LINKS[2])[2].strip(),
               REF_LINKS[3]: i.partition(REF_LINKS[3])[2].strip(),
               CANIUSE_URL: i.partition(': ')[2].strip()}
    link_final = links_d.get(pdfstring)
    if pdfstring in (URL_S, REF_LINKS[2], REF_LINKS[3]):
        prefix = link_prefixes.get(pdfstring, pdfstring)
        pdf.write(h=3, text=prefix)
    else:
        pdf.write(h=3, text=i[:i.index(": ")+2])
    pdf.set_text_color(0, 0, 255)
    pdf.cell(w=2000, h=3, text=i[i.index(": ")+2:], align="L", link=link_final)


def generate_html():
    shutil.copyfile(path.join(HUM_D[0], HUM_F[8]), final_filename)
    html_replace = {"html_title": get_detail('[pdf_meta_subject]'),
                    "html_desc": get_detail('[pdf_meta_title]'),
                    "html_keywords": get_detail('[pdf_meta_keywords]'),
                    "humble_URL": GIT_URL[1], "humble_local_v": humble_local_v,
                    "URL_analyzed": URL, "html_body": '<body><pre>', "}}": '}',
                    "{{": '}'}
    with open(final_filename, "r+", encoding='utf8') as html_file:
        temp_html_content = html_file.read()
        replaced_html = temp_html_content.format(**html_replace)
        html_file.seek(0)
        html_file.write(replaced_html)


def format_html_info(condition, ln, sub_d):
    if condition == 'rfc-st':
        html_final.write(f"{sub_d['ahref_s']}{ln[:32]}\
{sub_d['close_t']}{ln[:32]}{sub_d['ahref_f']}{ln[32:]}")
    else:
        html_final.write(f"{ln[:8]}{sub_d['ahref_s']}{ln[8:]}\
{sub_d['close_t']}{ln[8:]}{sub_d['ahref_f']}<br>")


def format_html_okko(condition, ln, sub_d):
    if condition == ok_string:
        html_final.write(f'<span class="ok">{ln}{sub_d["span_f"]}<br>')
    else:
        html_final.write(f"{sub_d['span_ko']}{ln}{sub_d['span_f']}<br>")


def format_html_refs(condition, ln, sub_d):
    if condition == REF_LINKS[1]:
        html_final.write(f"{ln[:6]}{sub_d['ahref_s']}{ln[6:]}\
{sub_d['close_t']}{ln[6:]}{sub_d['ahref_f']}<br>")
    else:
        html_final.write(f"{ln[:6]}{sub_d['ahref_s']}{ln[8:]}\
{sub_d['close_t']}{ln[6:]}{sub_d['ahref_f']}<br>")


def format_html_caniuse(ln, sub_d):
    ln = f"{sub_d['span_h']}{ln[1:ln.index(': ')]}: {sub_d['span_f']}\
{sub_d['ahref_s']}{ln[ln.index(SCHEME[1]):]}{sub_d['close_t']}\
{ln[ln.index(SCHEME[1]):]}{sub_d['ahref_f']}<br>"
    html_final.write(ln)


def format_html_bold(ln):
    html_final.write(f'<strong>{ln}</strong><br>')


def print_http_exception(id_exception, exception_v):
    clean_shell_lines()
    print("")
    print_detail(id_exception)
    raise SystemExit from exception_v


def print_ru_message():
    with contextlib.suppress(requests.exceptions.RequestException):
        requests.packages.urllib3.disable_warnings()
        sffx = tldextract.extract(URL).suffix[-2:].upper()
        cnty = requests.get(RU_CHECK[0], verify=False, timeout=5).text.strip()
        if (sffx == RU_CHECK[1] and sffx not in NON_RU_TLD) or cnty ==\
           RU_CHECK[2]:
            print_detail('[ru_analysis_message]', 3)
            sys.exit()


def analysis_filename(args, export_date, file_ext):
    url_str = tldextract.extract(args.URL)
    url_sch = urlparse(args.URL).scheme
    url_sub = f"_{url_str.subdomain}." if url_str.subdomain else '_'
    url_dom = f"{url_str.domain}."
    url_tld = url_str.suffix
    url_prt = f"_{urlparse(args.URL).port}_" if urlparse(args.URL).port is not\
        None else '_'
    return f"{url_sch}{url_sub}{url_dom}{url_tld}{url_prt}{export_date}\
{file_ext}"


def handle_server_error(http_code, id_mode):
    clean_shell_lines()
    print()
    if (500 <= http_code <= 511) or (520 <= http_code <= 530):
        if detail := print_detail(id_mode, 0):
            print(detail)
        else:
            print((REF_ERROR[1] if (500 <= http_code <= 511) else
                   REF_ERROR[0]) + str(http_code))
    # For 5xx HTTP codes not in the ranges (500-511) or (520-530)
    else:
        print_detail('[server_serror]', 1)
    sys.exit()


def make_http_request():
    try:
        start_time = time()
        uri_safe = quote(URL)
        session = requests.Session()
        session.mount("https://", SSLContextAdapter())
        session.mount("http://", HTTPAdapter())
        # If '-df' param is provided ('args.redirects') the exact URL will be
        # analyzed; otherwise the last redirected URL will be analyzed.
        #
        # Yes, certificates must always be checked/verified by default on
        # HTTPS connections. However, and within the scope of 'humble', I have
        # chosen to disable these checks so that in certain cases (e.g.
        # development environments, hosts with very old servers/software,
        # self-signed certificates, etc) the URL can still be analyzed.
        r = session.get(uri_safe, allow_redirects=not args.redirects,
                        verify=False, headers=ua_header, timeout=15)
        elapsed_time = time() - start_time
        return r, elapsed_time, None
    except requests.exceptions.SSLError:
        pass
    except requests.exceptions.RequestException as e:
        return None, 0.0, e


def wait_http_request(future):
    with contextlib.suppress(concurrent.futures.TimeoutError):
        future.result(timeout=5)


def handle_http_exception(r, exception_d):
    if r is None:
        return
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError as err_http:
        http_code = err_http.response.status_code
        id_mode = f"[server_{http_code}]"
        if str(http_code).startswith('5'):
            handle_server_error(http_code, id_mode)
    except tuple(exception_d.keys()) as e:
        ex = exception_d.get(type(e))
        if ex and (not callable(ex) or ex(e)):
            print_http_exception(ex, e)
    except requests.exceptions.RequestException as e:
        raise SystemExit from e


def manage_http_request():
    headers = {}
    status_c = None
    reliable = None
    request_time = 0.0
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future = executor.submit(make_http_request)
        wait_http_request(future)
        if not future.done():
            print(get_detail('[unreliable_analysis]'))
            reliable = 'No'
        r, request_time, exception = future.result()
        if exception:
            exception_type = type(exception)
            if exception_type in exception_d:
                error_string = exception_d[exception_type]
                print_http_exception(error_string, exception)
            else:
                print(f"Unhandled exception type: {exception_type}")
            return headers, status_c, reliable, request_time
        handle_http_exception(r, exception_d)
        if r is not None:
            status_c = r.status_code
            headers = r.headers
    return headers, status_c, reliable, request_time


def custom_help_formatter(prog):
    return RawDescriptionHelpFormatter(prog, max_help_position=30)


init(autoreset=True)
epi_text = get_epilog_detail('[epilog_content]')

parser = ArgumentParser(formatter_class=custom_help_formatter,
                        description=f"{HUM_DESC} | {GIT_URL[1]} | \
v.{humble_local_v}", epilog=epi_text)

parser.add_argument("-a", dest='URL_A', action="store_true", help="Shows \
statistics of the performed analysis (will be global if '-u' is omitted)")
parser.add_argument("-b", dest='brief', action="store_true", help="Shows \
overall findings (if omitted, details will be shown)")
parser.add_argument("-df", dest='redirects', action="store_true", help="Do not\
 follow redirects (if omitted, the last redirection will be the one analyzed)")
parser.add_argument("-e", nargs='?', type=str, dest='path', help="Shows \
TLS/SSL checks (requires the PATH of https://testssl.sh/ and Linux/Unix OS)")
parser.add_argument("-f", nargs='?', type=str, dest='term', help="Shows \
fingerprint statistics (will be the Top 20 if \"TERM\", e.g. \"Google\", is \
omitted)")
parser.add_argument("-g", dest='guides', action="store_true", help="Shows \
guidelines for enabling security HTTP response headers on popular servers/\
services")
parser.add_argument("-l", dest='lang', choices=['es'], help="The language for \
displaying analysis, errors and messages (if omitted it will be in English)")
parser.add_argument("-o", dest='output', choices=['csv', 'html', 'json', 'pdf',
                                                  'txt'], help="Exports \
analysis to 'scheme_host_port_yyyymmdd.ext' file (csv/json files will contain \
a brief analysis)")
parser.add_argument("-op", dest='output_path', type=str, help="Exports \
analysis to OUTPUT_PATH (if omitted, the PATH of 'humble.py' will be used)")
parser.add_argument("-r", dest='ret', action="store_true", help="Shows HTTP \
response headers and a detailed analysis ('-b' parameter will take priority)")
parser.add_argument("-s", dest='skipped_headers', nargs='*', type=str,
                    help="Skip analysis of specified HTTP response headers, \
separated by spaces")
parser.add_argument('-u', type=str, dest='URL', help="Scheme, host and port to\
 analyze. E.g. https://google.com")
parser.add_argument('-ua', type=str, dest='user_agent', help="User-Agent ID \
from 'additional/user_agents.txt' to use. '0' will show all and '1' is the \
default.")
parser.add_argument("-v", "--version", action="store_true", help="Checks for \
updates at https://github.com/rfc-st/humble")

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
l10n_details = get_l10n_details()
check_python_version()

# Checking parameters and their values
if args.version:
    check_humble_updates(humble_local_v)

if '-f' in sys.argv:
    fng_statistics_term(args.term) if args.term else fng_statistics_top()

if '-ua' in sys.argv:
    ua_header = parse_user_agent(user_agent=True)
elif args.URL:
    ua_header = parse_user_agent(user_agent=False)

if '-e' in sys.argv:
    if platform.system().lower() == 'windows':
        print_detail('[windows_ssltls]', 28)
        sys.exit()
    if (args.path is None or args.URL is None):
        parser.error(get_detail('[args_notestssl]'))

if args.lang and not (args.URL or args.URL_A) and not args.guides:
    parser.error(get_detail('[args_lang]'))

if args.output_path is not None:
    output_path = path.abspath(args.output_path)
    check_output_path(args, output_path)

if any([args.brief, args.output, args.ret, args.redirects,
        args.skipped_headers]) and (args.URL is None or args.guides is None
                                    or args.URL_A is None):
    parser.error(get_detail('[args_several]'))

if args.output in ['csv', 'json'] and not args.brief:
    parser.error(get_detail('[args_csv_json]'))

skipped_headers, skipped_headers_v, unsupported_headers = [], [], []

if '-s' in sys.argv and len(args.skipped_headers) == 0:
    parser.error(get_detail('[args_skipped]'))
elif args.skipped_headers:
    header_dict = get_insecure_checks()
    skipped_headers, unsupported_headers, skipped_headers_v = \
        get_skipped_unsupported_headers(args, header_dict)
    if unsupported_headers:
        print_unsupported_headers(unsupported_headers)

URL = args.URL

if args.guides or args.path or args.URL_A:
    if args.guides:
        print_security_guides()
    elif args.path:
        testssl_command(args.path, args.URL)
    elif args.URL_A:
        url_analytics() if args.URL else url_analytics(is_global=True)

start = time()
print_ru_message()

if not args.URL_A:
    detail = '[analysis_output]' if args.output else '[analysis]'
    print("")
    print_detail(detail)

exception_d = {
    requests.exceptions.ConnectionError: '[e_404]',
    requests.exceptions.InvalidSchema: '[e_schema]',
    requests.exceptions.InvalidURL: '[e_invalid]',
    requests.exceptions.MissingSchema: '[e_schema]',
    requests.exceptions.SSLError: None,
    requests.exceptions.Timeout: '[e_timeout]',
}
requests.packages.urllib3.disable_warnings()

headers, status_code, reliable, request_time = manage_http_request()

# File name with analysis results
if args.output:
    orig_stdout = sys.stdout
    file_ext = ".txt" if args.output == 'txt' else "t.txt"
    temp_filename = analysis_filename(args, export_date, file_ext)
    if args.output_path:
        temp_filename = path.join(output_path, temp_filename)
    temp_filename_content = open(temp_filename, 'w', encoding='utf8')
    sys.stdout = temp_filename_content

# Section '0. Info & HTTP Response Headers'
print_general_info(reliable)
print_response_headers() if args.ret else print(linesep.join([''] * 2))

# Section '1. Missing HTTP Security Headers'
print_detail_r('[1missing]')
m_cnt = 0

l_miss = ['Cache-Control', 'Clear-Site-Data', 'Content-Type',
          'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy',
          'Cross-Origin-Resource-Policy', 'Content-Security-Policy', 'NEL',
          'Permissions-Policy', 'Referrer-Policy', 'Strict-Transport-Security',
          'X-Content-Type-Options', 'X-Permitted-Cross-Domain-Policies']

l_detail = ['[mcache]', '[mcsd]', '[mctype]', '[mcoe]', '[mcop]', '[mcor]',
            '[mcsp]', '[mnel]', '[mpermission]', '[mreferrer]', '[msts]',
            '[mxcto]', '[mxpcd]', '[mxfo]']

missing_headers_lower = {k.lower(): v for k, v in headers.items()}

for i, key in enumerate(l_miss):
    if key.lower() not in missing_headers_lower:
        print_header(key)
        if not args.brief:
            print_detail(l_detail[i], 2)
        m_cnt += 1

if not (headers.get('X-Frame-Options') or 'frame-ancestors' in
        headers.get('Content-Security-Policy', '')):
    print_header('X-Frame-Options')
    if not args.brief:
        print_detail("[mxfo]", 2)
    m_cnt += 1

if not any(elem.lower() in headers for elem in l_miss):
    print_header('X-Frame-Options')
    if not args.brief:
        print_detail("[mxfo]", 2)
    m_cnt += 1

l_miss.append('X-Frame-Options')

if args.brief and m_cnt != 0:
    print("")

if m_cnt == 0:
    print_nowarnings()

print("")

# Section '2. Fingerprint HTTP Response Headers'
# (Source: /additional/fingerprint.txt)
print_detail_r('[2fingerprint]')

if not args.brief:
    print_detail("[afgp]")

l_fng, l_fng_ex = [], []

with open(path.join(HUM_D[0], HUM_F[2]), 'r', encoding='utf8') as fng_source:
    for line in fng_source:
        fng_stripped_ln = line.strip()
        if fng_stripped_ln and not line.startswith('#'):
            l_fng.append(line.partition(' [')[0].strip())
            l_fng_ex.append(line.strip())

f_cnt = print_fingerprint_headers(headers, l_fng, l_fng_ex)

if args.brief and f_cnt != 0:
    print("")

if f_cnt == 0:
    print_nowarnings()

print("")

# Section '3. Deprecated HTTP Response Headers/Protocols and Insecure Values'
# (Source: /additional/insecure.txt)
print_detail_r('[3depinsecure]')
i_cnt = [0]

if not args.brief:
    print_detail("[aisc]")

l_ins = ['Accept-CH', 'Accept-CH-Lifetime', 'Access-Control-Allow-Credentials',
         'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin',
         'Access-Control-Max-Age', 'Allow', 'Content-DPR', 'Content-Encoding',
         'Content-Security-Policy-Report-Only', 'Content-Type', 'Critical-CH',
         'Digest', 'Etag', 'Expect-CT', 'Expires', 'Feature-Policy',
         'Keep-Alive', 'Large-Allocation', 'No-Vary-Search',
         'Observe-Browsing-Topics', 'Onion-Location', 'Origin-Agent-Cluster',
         'P3P', 'Pragma', 'Proxy-Authenticate', 'Public-Key-Pins',
         'Public-Key-Pins-Report-Only', 'Set-Cookie', 'Server-Timing',
         'SourceMap', 'Strict-Dynamic', 'Supports-Loading-Mode',
         'Surrogate-Control', 'Timing-Allow-Origin', 'Tk', 'Trailer',
         'Transfer-Encoding', 'Vary', 'WWW-Authenticate', 'Warning',
         'X-Content-Security-Policy', 'X-Content-Security-Policy-Report-Only',
         'X-DNS-Prefetch-Control', 'X-Download-Options', 'X-Pad',
         'X-Permitted-Cross-Domain-Policies', 'X-Pingback', 'X-Robots-Tag',
         'X-Runtime', 'X-SourceMap', 'X-UA-Compatible', 'X-Webkit-CSP',
         'X-Webkit-CSP-Report-Only', 'X-XSS-Protection']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-CH
l_acceptch_dep = ['content-dpr', 'dpr', 'sec-ch-ua-full-version',
                  'viewport-width', 'width']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
l_cache = ['no-cache', 'no-store', 'must-revalidate']

l_cachev = ['immutable', 'max-age', 'must-revalidate', 'must-understand',
            'no-cache', 'no-store', 'no-transform', 'private',
            'proxy-revalidate', 'public', 's-maxage', 'stale-if-error',
            'stale-while-revalidate']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data
l_csdata = ['cache', 'clientHints', 'cookies', 'storage', 'executionContexts',
            '*']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
l_cencoding = ['br', 'compress', 'deflate', 'gzip', 'x-gzip', 'zstd']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
# https://www.w3.org/TR/CSP2/
# https://www.w3.org/TR/CSP3/
l_csp_broad = ['*',  'blob:', 'data:', 'ftp:', 'filesystem:', 'https:',
               'https://*', 'https://*.*', 'schemes:', 'wss:', 'wss://']

l_csp_equal = ['nonce', 'sha', 'style-src-elem', 'report-to', 'report-uri']

l_csp_dep = ['block-all-mixed-content', 'disown-opener', 'plugin-types',
             'prefetch-src', 'referrer', 'report-uri', 'require-sri-for']

l_csp_dirs = ['base-uri', 'child-src', 'connect-src', 'default-src',
              'fenced-frame-src', 'font-src', 'form-action', 'frame-ancestors',
              'frame-src', 'img-src', 'manifest-src', 'media-src',
              'navigate-to', 'object-src', 'report-to',
              'require-trusted-types-for', 'sandbox', 'script-src',
              'script-src-attr', 'script-src-elem', 'style-src',
              'style-src-attr', 'style-src-elem', 'trusted-types',
              'upgrade-insecure-requests', 'webrtc', 'worker-src']

l_csp_insecs = ['http:', 'ws:']

l_csp_insecv = ['unsafe-eval', 'unsafe-inline']

l_csp_ro_dep = ['violated-directive']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy
l_coep = ['credentialless', 'require-corp', 'unsafe-none']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy
l_coop = ['same-origin', 'same-origin-allow-popups', 'unsafe-none']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy
l_corp = ['cross-origin', 'same-origin', 'same-site']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires
l_excc = ['max-age', 's-maxage']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
# https://cyberwhite.co.uk/http-verbs-and-their-security-risks/
l_methods = ['*', 'CONNECT', 'DEBUG', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH',
             'PUT', 'TRACE', 'TRACK']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types
l_legacy = ['application/javascript', 'application/ecmascript',
            'application/x-ecmascript', 'application/x-javascript',
            'text/ecmascript', 'text/javascript1.0', 'text/javascript1.1',
            'text/javascript1.2', 'text/javascript1.3', 'text/javascript1.4',
            'text/javascript1.5', 'text/jscript', 'text/livescript',
            'text/x-ecmascript', 'text/x-javascript']

# https://w3c.github.io/network-error-logging/#nel-response-header
l_nel_dir = ['failure_fraction', 'include_subdomains', 'max_age', 'report_to',
             'request_headers', 'response_headers', 'success_fraction']

l_nel_req = ['report_to', 'max_age']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/No-Vary-Search
l_nvarysearch = ['except', 'key-order', 'params']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster
l_origcluster = ['?0', '?1']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
# https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md
l_per_dep = ['document-domain', 'window-placement']

l_per_feat = ['accelerometer', 'ambient-light-sensor', 'autoplay', 'battery',
              'bluetooth', 'browsing-topics', 'camera', 'ch-ua', 'ch-ua-arch',
              'ch-ua-bitness', 'ch-ua-full-version', 'ch-ua-full-version-list',
              'ch-ua-mobile', 'ch-ua-model', 'ch-ua-platform',
              'ch-ua-platform-version', 'ch-ua-wow64', 'clipboard-read',
              'clipboard-write', 'conversion-measurement',
              'cross-origin-isolated', 'display-capture', 'encrypted-media',
              'execution-while-not-rendered',
              'execution-while-out-of-viewport',
              'focus-without-user-activation', 'fullscreen', 'gamepad',
              'geolocation', 'gyroscope', 'hid', 'identity-credentials-get',
              'idle-detection', 'interest-cohort', 'join-ad-interest-group',
              'keyboard-map', 'layout-animations', 'local-fonts',
              'magnetometer', 'microphone', 'midi', 'navigation-override',
              'otp-credentials', 'payment', 'picture-in-picture',
              'publickey-credentials-create', 'publickey-credentials-get',
              'run-ad-auction', 'screen-wake-lock', 'serial',
              'shared-autofill', 'speaker-selection', 'storage-access',
              'sync-script', 'sync-xhr', 'trust-token-redemption', 'unload',
              'usb', 'vertical-scroll', 'web-share', 'window-management',
              'xr-spatial-tracking']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
l_ref_secure = ['strict-origin', 'strict-origin-when-cross-origin',
                'no-referrer-when-downgrade', 'no-referrer']

l_ref_values = ['no-referrer', 'no-referrer-when-downgrade', 'origin',
                'origin-when-cross-origin', 'same-origin', 'strict-origin',
                'strict-origin-when-cross-origin', 'unsafe-url']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
l_cookie_prf = ['__Host-', '__Secure-']

l_cookie_sec = ['httponly', 'secure']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Login
l_setlogin = ['logged-in', 'logged-out']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
l_sts_dir = ['includesubdomains', 'max-age']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Supports-Loading-Mode
l_support_mode = ['credentialed-prerender', 'fenced-frame']

# https://www.w3.org/TR/edge-arch/
l_surrogate = ['content', 'extension-directive', 'max-age', 'no-store',
               'no-store-remote']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Trailer
l_trailer = ['authorization', 'cache-control', 'content-encoding',
             'content-length', 'content-type', 'content-range', 'host',
             'max-forwards', 'set-cookie', 'te', 'trailer',
             'transfer-encoding']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding
l_transfer = ['chunked', 'compress', 'deflate', 'gzip', 'x-gzip']

# https://getbutterfly.com/security-headers-a-concise-guide/
# https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/xdomain.html
l_permcross = ['all', 'by-content-only', 'by-ftp-only', 'master-only', 'none',
               'none-this-response']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
l_xfo_dir = ['deny', 'sameorigin']

# https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag
# https://www.bing.com/webmasters/help/which-robots-metatags-does-bing-support-5198d240
# https://seranking.com/blog/guide-meta-tag-robots-x-robots-tag/
l_robots = ['all', 'archive', 'follow', 'index', 'indexifembedded',
            'max-image-preview', 'max-snippet', 'max-video-preview',
            'noarchive', 'nocache', 'noodp', 'nofollow', 'noimageindex',
            'noindex', 'none', 'nopagereadaloud', 'nositelinkssearchbox',
            'nosnippet', 'notranslate', 'noydir', 'unavailable_after']

unsafe_scheme = True if URL.startswith(SCHEME[0]) else False

if 'Accept-CH' in headers and '1' not in skipped_headers_v:
    acceptch_header = headers['Accept-CH'].lower()
    if unsafe_scheme:
        print_details('[ixach_h]', '[ixach]', 'd', i_cnt)
    if any(value in acceptch_header for value in l_acceptch_dep):
        print_detail_r('[ixachd_h]', is_red=True)
        if not args.brief:
            match_value = [x for x in l_acceptch_dep if x in acceptch_header]
            match_value_str = ', '.join(match_value)
            print_detail_l("[ixachd_s]")
            print(match_value_str)
            print_detail('[ixachd]')
        i_cnt[0] += 1

if 'Accept-CH-Lifetime' in headers and '2' not in skipped_headers_v:
    print_details('[ixacl_h]', '[ixacld]', 'd', i_cnt)

accescred_header = headers.get("Access-Control-Allow-Credentials", '').lower()
if accescred_header and accescred_header != 'true' and '3' not in \
     skipped_headers_v:
    print_details('[icred_h]', '[icred]', 'd', i_cnt)

if 'Access-Control-Allow-Methods' in headers and '4' not in skipped_headers_v:
    methods = headers["Access-Control-Allow-Methods"]
    if any(method in methods for method in l_methods):
        print_detail_r('[imethods_h]', is_red=True)
        if not args.brief:
            match_method = [x for x in l_methods if x in methods]
            match_method_str = ', '.join(match_method)
            print_detail_l("[imethods_s]")
            print(match_method_str)
            print_detail("[imethods]")
        i_cnt[0] += 1

accesso_header = headers.get("Access-Control-Allow-Origin", '').lower()
if accesso_header and ((accesso_header in ['*', 'null']) and
                       (not any(val in accesso_header for
                                val in ['.*', '*.']))) and '5' not in \
                                    skipped_headers_v:
    print_details('[iaccess_h]', '[iaccess]', 'd', i_cnt)

accesma_header = headers.get("Access-Control-Max-Age", '')
if accesma_header and int(accesma_header) > 86400 and '6' not in \
     skipped_headers_v:
    print_details('[iacessma_h]', '[iaccessma]', 'd', i_cnt)

if 'Allow' in headers and '7' not in skipped_headers_v:
    methods = headers["Allow"]
    if any(method in methods for method in l_methods):
        print_detail_r('[imethods_hh]', is_red=True)
        if not args.brief:
            match_method = [x for x in l_methods if x in methods]
            match_method_str = ', '.join(match_method)
            print_detail_l("[imethods_s]")
            print(match_method_str)
            print_detail("[imethods]")
        i_cnt[0] += 1

cache_header = headers.get("Cache-Control", '').lower()
if cache_header and not any(elem in cache_header for elem in l_cachev) and \
     '8' not in skipped_headers_v:
    print_details('[icachev_h]', '[icachev]', 'd', i_cnt)
if cache_header and not all(elem in cache_header for elem in l_cache) and \
     '8' not in skipped_headers_v:
    print_details('[icache_h]', '[icache]', 'd', i_cnt)

if 'Clear-Site-Data' in headers and '9' not in skipped_headers_v:
    clsdata_header = headers['Clear-Site-Data'].lower()
    if unsafe_scheme:
        print_details('[icsd_h]', '[icsd]', 'd', i_cnt)
    if not any(elem in clsdata_header for elem in l_csdata):
        print_details('[icsdn_h]', '[icsdn]', 'd', i_cnt)

if 'Content-DPR' in headers and '10' not in skipped_headers_v:
    print_details('[ixcdpr_h]', '[ixcdprd]', 'd', i_cnt)

cencod_header = headers.get("Content-Encoding", '').lower()
if cencod_header and not any(elem in cencod_header for elem in l_cencoding) \
     and '11' not in skipped_headers_v:
    print_details('[icencod_h]', '[icencod]', 'd', i_cnt)

if 'Content-Security-Policy' in headers and '12' not in skipped_headers_v:
    csp_h = headers['Content-Security-Policy'].lower()
    if not any(elem in csp_h for elem in l_csp_dirs):
        print_details('[icsi_h]', '[icsi]', 'd', i_cnt)
    if ('=' in csp_h) and not (any(elem in csp_h for elem in l_csp_equal)):
        print_details('[icsn_h]', '[icsn]', 'd', i_cnt)
    csp_store_values(csp_h, l_csp_broad, l_csp_insecs, i_cnt)
    if any(elem in csp_h for elem in l_csp_insecv):
        print_details('[icsp_h]', '[icsp]', 'm', i_cnt)
    if 'upgrade-insecure-requests' in csp_h and \
       'strict-transport-security' not in headers:
        print_details('[icspi_h]', '[icspi]', 'm', i_cnt)
    if 'unsafe-hashes' in csp_h:
        print_details('[icsu_h]', '[icsu]', 'd', i_cnt)
    if "'nonce-" in csp_h:
        nonces_csp = re.findall(r"'nonce-([^']+)'", csp_h)
        for nonce_csp in nonces_csp:
            if len(nonce_csp) < 32:
                print_details('[icsnces_h]', '[icsnces]', 'd', i_cnt)
                break
    ip_mtch = re.findall(IP_PATTERN, csp_h)
    if ip_mtch != ['127.0.0.1']:
        for match in ip_mtch:
            if re.match(IP_PATTERN, match):
                print_details('[icsipa_h]', '[icsipa]', 'm', i_cnt)
                break

csp_ro_header = headers.get('Content-Security-Policy-Report-Only', '').lower()
if csp_ro_header and any(elem in csp_ro_header for elem in l_csp_ro_dep) and \
     '13' not in skipped_headers_v:
    print_detail_r('[icsiro_d]', is_red=True)
    if not args.brief:
        matches_csp_ro = [x for x in l_csp_ro_dep if x in csp_ro_header]
        print_detail_l("[icsi_d_s]")
        print(', '.join(matches_csp_ro))
        print_detail("[icsiro_d_r]")
    i_cnt[0] += 1

ctype_header = headers.get('Content-Type', '').lower()
if ctype_header and '14' not in skipped_headers_v:
    if any(elem in ctype_header for elem in l_legacy):
        print_details('[ictlg_h]', '[ictlg]', 'm', i_cnt)
    if 'html' not in ctype_header:
        print_details('[ictlhtml_h]', '[ictlhtml]', 'd', i_cnt)

if 'Critical-CH' in headers and unsafe_scheme and '15' not in \
     skipped_headers_v:
    print_details('[icrch_h]', '[icrch]', 'd', i_cnt)

if 'Cross-Origin-Embedder-Policy' in headers and '16' not in skipped_headers_v:
    coep_h = headers['Cross-Origin-Embedder-Policy'].lower()
    if not any(elem in coep_h for elem in l_coep):
        print_details('[icoep_h]', '[icoep]', 'd', i_cnt)

if 'Cross-Origin-Opener-Policy' in headers and '17' not in skipped_headers_v:
    coop_h = headers['Cross-Origin-Opener-Policy'].lower()
    if not any(elem in coop_h for elem in l_coop):
        print_details('[icoop_h]', '[icoop]', 'd', i_cnt)

if 'Cross-Origin-Resource-Policy' in headers and '18' not in skipped_headers_v:
    corp_h = headers['Cross-Origin-Resource-Policy'].lower()
    if not any(elem in corp_h for elem in l_corp):
        print_details('[icorp_h]', '[icorp]', 'd', i_cnt)

if 'Digest' in headers and '19' not in skipped_headers_v:
    print_details('[idig_h]', '[idig]', 'd', i_cnt)

if 'Etag' in headers and '20' not in skipped_headers_v:
    print_details('[ieta_h]', '[ieta]', 'd', i_cnt)

if 'Expect-CT' in headers and '21' not in skipped_headers_v:
    print_details('[iexct_h]', '[iexct]', 'm', i_cnt)

if 'Expires' in headers and any(elem in headers.get('Cache-Control', '') for
                                elem in l_excc) and '22' not in \
                                    skipped_headers_v:
    print_details('[iexpi_h]', '[iexpi]', 'd', i_cnt)

if 'Feature-Policy' in headers and '23' not in skipped_headers_v:
    print_details('[iffea_h]', '[iffea]', 'd', i_cnt)

if unsafe_scheme:
    print_details('[ihttp_h]', '[ihttp]', 'd', i_cnt)

if ('Keep-Alive' in headers and headers['Keep-Alive'] and
    ('Connection' not in headers or
     headers['Connection'].lower() != 'keep-alive')) and '25' not in \
        skipped_headers_v:
    print_details('[ickeep_h]', '[ickeep]', 'd', i_cnt)

if 'Large-Allocation' in headers and '26' not in skipped_headers_v:
    print_details('[ixlalloc_h]', '[ixallocd]', 'd', i_cnt)

if 'NEL' in headers and '27' not in skipped_headers_v:
    nel_header = headers['NEL'].lower()
    if not any(elem in nel_header for elem in l_nel_dir):
        print_details('[inel_h]', '[inel]', 'd', i_cnt)
    if not all(elem in nel_header for elem in l_nel_req):
        print_details("[inelm_h]", "[inelm]", "d", i_cnt)

if 'No-Vary-Search' in headers and '28' not in skipped_headers_v:
    nvarys_header = headers['No-Vary-Search'].lower()
    if not any(elem in nvarys_header for elem in l_nvarysearch):
        print_details('[ifnvarys_h]', '[ifnvarys]', 'd', i_cnt)

observe_brows_header = headers.get('Observe-Browsing-Topics', '').lower()
if observe_brows_header and '?1' not in observe_brows_header and \
     '29' not in skipped_headers_v:
    print_details('[iobsb_h]', '[iobsb]', 'd', i_cnt)

if 'Onion-Location' in headers and '30' not in skipped_headers_v:
    print_details('[ionloc_h]', '[ionloc]', 'm', i_cnt)

if 'Origin-Agent-Cluster' in headers and '31' not in skipped_headers_v:
    origin_cluster_h = headers['Origin-Agent-Cluster'].lower()
    if not any(elem in origin_cluster_h for elem in l_origcluster):
        print_details('[iorigcluster_h]', '[iorigcluster]', 'd', i_cnt)

if 'P3P' in headers and '32' not in skipped_headers_v:
    print_details('[ip3p_h]', '[ip3p]', 'd', i_cnt)

if 'Permissions-Policy' in headers and '33' not in skipped_headers_v:
    perm_header = headers['Permissions-Policy'].lower()
    if not any(elem in perm_header for elem in l_per_feat):
        print_details('[ifpoln_h]', '[ifpoln]', 'm', i_cnt)
    if '*' in perm_header:
        print_details('[ifpol_h]', '[ifpol]', 'd', i_cnt)
    if 'none' in perm_header:
        print_details('[ifpoli_h]', '[ifpoli]', 'd', i_cnt)
    if any(elem in perm_header for elem in l_per_dep):
        print_detail_r('[ifpold_h]', is_red=True)
        if not args.brief:
            matches_perm = [x for x in l_per_dep if x in perm_header]
            print_detail_l("[ifpold_h_s]")
            print(', '.join(matches_perm))
            print_detail("[ifpold]")
        i_cnt[0] += 1

if 'Pragma' in headers and '34' not in skipped_headers_v:
    print_details('[iprag_h]', '[iprag]', 'd', i_cnt)

if 'Proxy-Authenticate' in headers and '35' not in skipped_headers_v:
    prxyauth_h = headers['Proxy-Authenticate'].lower()
    if 'basic' in prxyauth_h and unsafe_scheme:
        print_details('[iprxauth_h]', '[ihbas]', 'd', i_cnt)

if 'Public-Key-Pins' in headers and '36' not in skipped_headers_v:
    print_details('[ipkp_h]', '[ipkp]', 'd', i_cnt)

if 'Public-Key-Pins-Report-Only' in headers and '37' not in skipped_headers_v:
    print_details('[ipkpr_h]', '[ipkp]', 'd', i_cnt)

referrer_header = headers.get('Referrer-Policy', '').lower()
if referrer_header and '38' not in skipped_headers_v:
    if not any(elem in referrer_header for elem in l_ref_secure):
        print_details('[iref_h]', '[iref]', 'm', i_cnt)
    if 'unsafe-url' in referrer_header:
        print_details('[irefi_h]', '[irefi]', 'd', i_cnt)
    if not any(elem in referrer_header for elem in l_ref_values):
        print_details('[irefn_h]', '[irefn]', 'd', i_cnt)

if 'Server-Timing' in headers and '39' not in skipped_headers_v:
    print_details('[itim_h]', '[itim]', 'd', i_cnt)

stc_header = headers.get("Set-Cookie", '').lower()
if stc_header and '40' not in skipped_headers_v:
    if not unsafe_scheme and not all(elem in stc_header for elem in
                                     l_cookie_sec):
        print_details("[iset_h]", "[iset]", "d", i_cnt)
    if unsafe_scheme:
        if 'secure' in stc_header:
            print_details("[iseti_h]", "[iseti]", "d", i_cnt)
        if any(prefix in stc_header for prefix in l_cookie_prf):
            print_details("[ispref_m]", "[ispref]", "d", i_cnt)
    if "samesite=none" in stc_header and "secure" not in stc_header:
        print_details("[iseti_m]", "[isetm]", "d", i_cnt)

setlogin_header = headers.get("Set-Login", '').lower()
if setlogin_header and not any(elem in setlogin_header for elem in l_setlogin)\
     and '41' not in skipped_headers_v:
    print_details('[islogin_h]', '[islogin]', 'd', i_cnt)

if 'SourceMap' in headers and '42' not in skipped_headers_v:
    print_details('[ismap_m]', '[ismap]', 'd', i_cnt)

if 'Strict-Dynamic' in headers and '43' not in skipped_headers_v:
    print_details('[isdyn_h]', '[isdyn]', 'd', i_cnt)

sts_header = headers.get('Strict-Transport-Security', '').lower()
if sts_header and not unsafe_scheme and '44' not in skipped_headers_v:
    try:
        age = int(''.join(filter(str.isdigit, sts_header)))
        if not all(elem in sts_header for elem in l_sts_dir) or age < 31536000:
            print_details('[ists_h]', '[ists]', 'm', i_cnt)
        if ',' in sts_header:
            print_details('[istsd_h]', '[istsd]', 'd', i_cnt)
    except ValueError:
        print_details('[ists_h]', '[ists]', 'm', i_cnt)

if 'Supports-Loading-Mode' in headers and '45' not in skipped_headers_v:
    support_mode_h = headers['Supports-Loading-Mode'].lower()
    if not any(elem in support_mode_h for elem in l_support_mode):
        print_details('[islmode_h]', '[islmode]', 'd', i_cnt)

if sts_header and unsafe_scheme:
    print_details('[ihsts_h]', '[ihsts]', 'd', i_cnt)

if 'Surrogate-Control' in headers and '46' not in skipped_headers_v:
    surrogate_mode_h = headers['Surrogate-Control'].lower()
    if not any(elem in surrogate_mode_h for elem in l_surrogate):
        print_details('[isurrmode_h]', '[isurrmode]', 'd', i_cnt)

if headers.get('Timing-Allow-Origin', '') == '*' and '47' not in \
     skipped_headers_v:
    print_details('[itao_h]', '[itao]', 'd', i_cnt)

if 'Tk' in headers and '48' not in skipped_headers_v:
    print_details('[ixtk_h]', '[ixtkd]', 'd', i_cnt)

if 'Trailer' in headers and '49' not in skipped_headers_v:
    trailer_h = headers['Trailer'].lower()
    if any(elem in trailer_h for elem in l_trailer):
        print_detail_r('[itrailer_h]', is_red=True)
        if not args.brief:
            matches_trailer = [x for x in l_trailer if x in trailer_h]
            print_detail_l("[itrailer_d_s]")
            print(', '.join(matches_trailer))
            print_detail("[itrailer_d_r]")
        i_cnt[0] += 1

if 'Transfer-Encoding' in headers and '50' not in skipped_headers_v:
    transfer_h = headers['Transfer-Encoding'].lower()
    if not any(elem in transfer_h for elem in l_transfer):
        print_details('[ictrf_h]', '[itrf]', 'd', i_cnt)

if 'Vary' in headers and '51' not in skipped_headers_v:
    print_details('[ixvary_h]', '[ixvary]', 'm', i_cnt)

wwwa_header = headers.get('WWW-Authenticate', '').lower()
if wwwa_header and unsafe_scheme and ('basic' in wwwa_header) and '52' not in \
     skipped_headers_v:
    print_details('[ihbas_h]', '[ihbas]', 'd', i_cnt)

if 'Warning' in headers and '53' not in skipped_headers_v:
    print_details('[ixwar_h]', '[ixward]', 'd', i_cnt)

if 'X-Content-Security-Policy' in headers and '54' not in skipped_headers_v:
    print_details('[ixcsp_h]', '[ixcsp]', 'd', i_cnt)

if 'X-Content-Security-Policy-Report-Only' in headers and '55' not in \
     skipped_headers_v:
    print_details('[ixcspr_h]', '[ixcspr]', 'd', i_cnt)

if 'X-Content-Type-Options' in headers and '56' not in skipped_headers_v:
    if ',' in headers['X-Content-Type-Options']:
        print_details('[ictpd_h]', '[ictpd]', 'd', i_cnt)
    elif 'nosniff' not in headers['X-Content-Type-Options']:
        print_details('[ictp_h]', '[ictp]', 'd', i_cnt)

if headers.get('X-DNS-Prefetch-Control', '') == 'on' and '57' not in \
     skipped_headers_v:
    print_details('[ixdp_h]', '[ixdp]', 'd', i_cnt)

if 'X-Download-Options' in headers and '58' not in skipped_headers_v:
    print_details('[ixdow_h]', '[ixdow]', 'm', i_cnt)

xfo_header = headers.get('X-Frame-Options', '').lower()
if xfo_header and '59' not in skipped_headers_v:
    if ',' in xfo_header:
        print_details('[ixfo_h]', '[ixfo]', 'm', i_cnt)
    if 'allow-from' in xfo_header:
        print_details('[ixfod_h]', '[ixfod]', 'm', i_cnt)
    if xfo_header not in l_xfo_dir:
        print_details('[ixfoi_h]', '[ixfodi]', 'm', i_cnt)

if 'X-Pad' in headers and '60' not in skipped_headers_v:
    print_details('[ixpad_h]', '[ixpad]', 'd', i_cnt)

permcross_header = headers.get('X-Permitted-Cross-Domain-Policies', '').lower()
if permcross_header and '61' not in skipped_headers_v:
    if not any(elem in permcross_header for elem in l_permcross):
        print_details('[ixpermcross_h]', '[ixpermcross]', 'm', i_cnt)
    if 'all' in permcross_header:
        print_details('[ixpermcrossu_h]', '[ixcd]', 'm', i_cnt)
    if ',' in permcross_header:
        print_details('[ixpermcrossd_h]', '[ixpermcrossd]', 'm', i_cnt)

if headers.get('X-Pingback', '').endswith('xmlrpc.php') and '62' not in \
     skipped_headers_v:
    print_details('[ixpb_h]', '[ixpb]', 'd', i_cnt)

robots_header = headers.get('X-Robots-Tag', '').lower()
if robots_header and '63' not in skipped_headers_v:
    if not any(elem in robots_header for elem in l_robots):
        print_details('[ixrobv_h]', '[ixrobv]', 'm', i_cnt)
    if 'all' in robots_header:
        print_details('[ixrob_h]', '[ixrob]', 'm', i_cnt)

if 'X-Runtime' in headers and '64' not in skipped_headers_v:
    print_details('[ixrun_h]', '[ixrun]', 'd', i_cnt)

if 'X-SourceMap' in headers and '65' not in skipped_headers_v:
    print_details('[ixsrc_h]', '[ixsrc]', 'd', i_cnt)

if 'X-UA-Compatible' in headers and '66' not in skipped_headers_v:
    print_details('[ixuacom_h]', '[ixuacom]', 'm', i_cnt)

if 'X-Webkit-CSP' in headers and '67' not in skipped_headers_v:
    print_details('[ixwcsp_h]', '[ixcsp]', 'd', i_cnt)

if 'X-Webkit-CSP-Report-Only' in headers and '68' not in skipped_headers_v:
    print_details('[ixwcspr_h]', '[ixcspr]', 'd', i_cnt)

if 'X-XSS-Protection' in headers and '69' not in skipped_headers_v:
    print_details('[ixxpdp_h]', '[ixxpdp]', 'm', i_cnt)
    if '0' not in headers["X-XSS-Protection"]:
        print_details('[ixxp_h]', '[ixxp]', 'd', i_cnt)
    if ',' in headers['X-XSS-Protection']:
        print_details('[ixxpd_h]', '[ixxpd]', 'd', i_cnt)

if args.brief and i_cnt[0] != 0:
    print("")

if i_cnt[0] == 0:
    print_nowarnings()

print("")

# Section '4. Empty HTTP Response Headers Values'
print_detail_r('[4empty]')
l_empty = []

if not args.brief:
    print_detail("[aemp]")

e_cnt = print_empty_headers(headers, l_empty)

print("") if e_cnt != 0 else print_nowarnings()
print("")

# Section '5. Browser Compatibility for Enabled HTTP Security Headers'
print_detail_r('[5compat]')

l_sec = ['Access-Control-Allow-Credentials', 'Access-Control-Allow-Methods',
         'Access-Control-Max-Age', 'Cache-Control', 'Clear-Site-Data',
         'Content-Security-Policy', 'Content-Security-Policy-Report-Only',
         'Content-Type', 'Critical-CH', 'Cross-Origin-Embedder-Policy',
         'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy',
         'Document-Policy', 'ETag', 'Feature-Policy', 'NEL',
         'Observe-Browsing-Topics', 'Origin-Agent-Cluster',
         'Permissions-Policy', 'Proxy-Authenticate', 'Referrer-Policy',
         'Server-Timing', 'Set-Cookie', 'Set-Login',
         'Strict-Transport-Security', 'Supports-Loading-Mode',
         'Timing-Allow-Origin', 'Trailer', 'Vary', 'WWW-Authenticate',
         'X-Content-Type-Options', 'X-DNS-Prefetch-Control',
         'X-Frame-Options', 'X-XSS-Protection']

browser_compat_header = [header for header in l_sec if header in headers]
if browser_compat_header:
    print_browser_compatibility(browser_compat_header)
else:
    print_detail_l("[no_sec_headers]") if args.output else \
        print_detail_r("[no_sec_headers]", is_red=True)

print(linesep.join(['']*2))
end = time()
get_analysis_result()

# For exporting analyses
if args.output:
    final_filename = f"{temp_filename[:-5]}.{args.output}"
    sys.stdout = orig_stdout
    temp_filename_content.close()
if args.output == 'txt':
    print_export_path(temp_filename, reliable)
elif args.output == 'csv':
    generate_csv(temp_filename, final_filename)
elif args.output == 'json':
    generate_json(temp_filename, final_filename)
elif args.output == 'pdf':
    # Lazy import of the dependency and logic associated with fpdf2, to
    # slightly improve analysis times that do not require exporting to PDF.
    from fpdf import FPDF

    class PDF(FPDF):

        def header(self):
            self.set_font('Courier', 'B', 9)
            self.set_y(15)
            self.set_text_color(0, 0, 0)
            self.cell(0, 5, get_detail('[pdf_title]'), new_x="CENTER",
                      new_y="NEXT", align='C')
            self.ln(1)
            self.cell(0, 5, f"{GIT_URL[1]} | v.{humble_local_v}", align='C')
            self.ln(9 if self.page_no() == 1 else 13)

        def footer(self):
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(0, 0, 0)
            self.cell(0, 10, get_detail('[pdf_footer]') + str(self.page_no()) +
                      get_detail('[pdf_footer2]') + ' {nb}', align='C')
    pdf = PDF()
    generate_pdf(temp_filename, pdf)
elif args.output == 'html':
    generate_html()

    l_final = sorted(l_miss + l_ins)
    l_fng_final = sorted(l_fng)
    l_fng_final_case = [x.casefold() for x in l_fng_final]

    ok_string, ko_string = [get_detail(f'[{i}]') for i
                            in ['no_warnings', 'no_sec_headers']]

    sub_d = {'ahref_f': '</a>', 'ahref_s': '<a href="', 'close_t': '">',
             'span_ko': '<span class="ko">', 'span_h': '<span class="header">',
             'span_f': '</span>'}

    with open(temp_filename, 'r', encoding='utf8') as html_source, \
            open(final_filename, 'a', encoding='utf8') as html_final:

        for ln in html_source:
            ln_stripped = ln.rstrip('\n')
            if 'rfc-st' in ln or URL_S in ln:
                condition = 'rfc-st' if 'rfc-st' in ln else URL_S
                format_html_info(condition, ln_stripped, sub_d)
            elif any(s in ln for s in BOLD):
                format_html_bold(ln_stripped)
            elif ok_string in ln or ko_string in ln:
                condition = ok_string if ok_string in ln else ko_string
                format_html_okko(condition, ln_stripped, sub_d)
            elif REF_LINKS[1] in ln or REF_LINKS[0] in ln:
                condition = REF_LINKS[1] if REF_LINKS[1] in ln else \
                            REF_LINKS[0]
                format_html_refs(condition, ln_stripped, sub_d)
            elif 'caniuse' in ln:
                format_html_caniuse(ln_stripped, sub_d)
            else:
                for i in headers:
                    if (str(i + ": ") in ln) and ('Date:   ' not in ln):
                        ln = ln.replace(ln[0: ln.index(":")], sub_d['span_h'] +
                                        ln[0: ln.index(":")] + sub_d['span_f'])
                for i in l_fng_final:
                    if i in ln and not args.brief:
                        try:
                            idx = ln.index(' [')
                        except ValueError:
                            continue
                        if 'class="ko"' not in ln:
                            ln = f"{sub_d['span_ko']}{ln[:idx]}\
{sub_d['span_f']}{ln[idx:]}"
                for i in l_fng_final_case:
                    if args.brief and i in ln.casefold() and ':' not in \
                     ln.casefold() and 'class="ko"' not in ln:
                        ln = f"{sub_d['span_ko']}{ln}{sub_d['span_f']}"
                for i in l_final:
                    if (i in ln) and ('"' not in ln) or ('HTTP (' in ln):
                        ln = ln.replace(ln, sub_d['span_ko'] +
                                        ln + sub_d['span_f'])
                for i in l_empty:
                    if i[1:] in ln and '[' not in ln:
                        ln = f"{sub_d['span_ko']}{ln}{sub_d['span_f']}"
                html_final.write(ln)
        html_final.write('</pre></body></html>')

    print_export_path(final_filename, reliable)
    remove(temp_filename)
