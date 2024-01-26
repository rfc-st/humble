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

# ADVICE:
# Use the information provided by this humble program wisely. There is *far*
# more merit in teaching, learning and helping others than in harming,
# attacking or taking advantage. Don't just be a 'Script kiddie': if this
# really interests you learn, research and become a Security Analyst!.

# GREETINGS:
# Alba, Aleix, Alejandro (x3), Álvaro, Ana, Carlos (x3), David (x3), Eduardo,
# Eloy, Fernando, Gabriel, Íñigo, Joanna, Juan Carlos, Juán, Julián, Julio,
# Iván, Lourdes, Luis Joaquín, María Antonia, Marta, Miguel, Miguel Angel,
# Montse, Naiara, Pablo, Sergio, Ricardo & Rubén!.

from fpdf import FPDF
from time import time
from shlex import quote
from datetime import datetime
from urllib.parse import urlparse
from os import linesep, path, remove
from colorama import Fore, Style, init
from collections import Counter, defaultdict
from argparse import ArgumentParser, HelpFormatter
from requests.adapters import HTTPAdapter
import re
import csv
import ssl
import sys
import json
import platform
import requests
import contextlib
import tldextract
import subprocess
import concurrent.futures

BOLD_S = ("[0.", "HTTP R", "[1.", "[2.", "[3.", "[4.", "[5.", "[Cabeceras")
BRI_R = f"{Style.BRIGHT}{Fore.RED}"
CAN_S = ': https://caniuse.com/?search='
CDN_E = [520, 521, 522, 523, 524, 525, 526, 527, 530]
CLE_O = '\x1b[1A\x1b[2K\x1b[1A\x1b[2K\x1b[1A\x1b[2K'
CLI_E = [400, 401, 402, 403, 405, 406, 409, 410, 411, 412, 413, 414, 415, 416,
         417, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451]
CSV_ID = ['0section', '0headers', '1missing', '2fingerprint', '3depinsecure',
          '4empty', '5compat']
FORCED_CIPHERS = ":".join(["HIGH", "!DH", "!aNULL"])
GIT_H = "https://raw.githubusercontent.com/rfc-st/humble/master/humble.py"
GIT_U = "https://github.com/rfc-st/humble"
HUM_D = ['additional', 'l10n']
HUM_F = ['analysis_h.txt', 'check_path_permissions', 'fingerprint.txt',
         'guides.txt', 'details_es.txt', 'details.txt', 'user_agents.txt']
INS_S = 'http:'
IP_PTRN = (r'^(?:\d{1,3}\.){3}\d{1,3}$|'
           r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
# https://data.iana.org/TLD/tlds-alpha-by-domain.txt
NON_RU_TLD = ['CYMRU', 'GURU', 'PRU']
PAT_LN = r'\[(.*?)\]'
PATH_PTRN = (r'\.\./|/\.\.|\\\.\.|\\\.\\|'
             r'%2e%2e%2f|%252e%252e%252f|%c0%ae%c0%ae%c0%af|'
             r'%uff0e%uff0e%u2215|%uff0e%uff0e%u2216')
PRG_N = "'humble' (HTTP Headers Analyzer)"
REF_1 = ' Ref  : '
REF_2 = ' Ref: '
REF_CDN_E = ' Ref  : https://developers.cloudflare.com/support/\
troubleshooting/cloudflare-errors/troubleshooting-cloudflare-5xx-errors/'
REF_SRV_E = ' Ref  : https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/'
REF_E = 'Ref  :'
REF_S = 'Ref: '
RU_I = ['https://ipapi.co/country_name/', 'RU', 'Russia']
SRV_E = [500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511]
SEC_S = "https://"
URL_S = ' URL  : '

export_date = datetime.now().strftime("%Y%m%d")
now = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
version = datetime.strptime('2024-01-26', '%Y-%m-%d').date()


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


class PDF(FPDF):

    def header(self):
        self.set_font('Courier', 'B', 9)
        self.set_y(15)
        pdf.set_text_color(0, 0, 0)
        self.cell(0, 5, get_detail('[pdf_title]'), new_x="CENTER",
                  new_y="NEXT", align='C')
        self.ln(1)
        self.cell(0, 5, f"{GIT_U} | v.{version}", align='C')
        self.ln(9) if self.page_no() == 1 else self.ln(13)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(0, 0, 0)
        self.cell(0, 10, get_detail('[pdf_footer]') + ' ' +
                  str(self.page_no()) + get_detail('[pdf_footer2') +
                  ' {nb}', align='C')


def check_python_version():
    exit(print_detail('[python_version]', 3)) if sys.version_info < (3, 9) \
        else None


def check_humble_updates(version):
    try:
        response_t = requests.get(GIT_H, timeout=10).text
        remote_v = re.search(r"\d{4}-\d{2}-\d{2}", response_t).group()
        remote_v_date = datetime.strptime(remote_v, '%Y-%m-%d').date()
        if remote_v_date > version:
            print(f"\n v.{version}{get_detail('[not_latest]')[:-1]}{remote_v})\
                  \n{get_detail('[github_humble]')}")
        else:
            print(f"\n v.{version}{get_detail('[latest]')}")
    except requests.exceptions.RequestException:
        print(f"\n{get_detail('[update_error]')}")


def fng_analytics_global():
    print(f"\n{Style.BRIGHT}{get_detail('[fng_stats]', replace=True)}\
{Style.RESET_ALL}{get_detail('[fng_source]', replace=True)}\n")
    with open(path.join(HUM_D[0], HUM_F[2]), 'r', encoding='utf8') as fng_f:
        fng_lines = fng_f.readlines()
    fng_analytics_global_groups(fng_lines)


def fng_analytics_global_groups(fng_lines):
    pttn_fng_global = r'\[([^\]]+)\]'
    content_fng = Counter(match.strip() for line in fng_lines for match in
                          re.findall(pttn_fng_global, line))
    excl_ln = sum(bool(line.startswith('#')) for line in fng_lines) + 2
    len_fng = len(fng_lines) - excl_ln
    fng_analytics_global_print(content_fng, len_fng)


def fng_analytics_global_print(content_fng, len_fng):
    max_ln_len = max(len(content) for content, _ in
                     content_fng.most_common(20))
    print(f"{get_detail('[fng_top]', replace=True)} {len_fng}\
{get_detail('[fng_top_2]', replace=True)}\n")
    for content, count in content_fng.most_common(20):
        pct_fng_global = round(count / len_fng * 100, 2)
        padding_s = ' ' * (max_ln_len - len(content))
        print(f" [{content}]: {padding_s}{pct_fng_global:.2f}% ({count})")


def fng_analytics(term):
    print(f"\n{Style.BRIGHT}{get_detail('[fng_stats]', replace=True)}\
{Style.RESET_ALL}{get_detail('[fng_source]', replace=True)}\n")
    with open(path.join(HUM_D[0], HUM_F[2]), 'r', encoding='utf8') as \
            fng_source:
        fng_lines = fng_source.readlines()
    fng_group, term_count = fng_analytics_groups(fng_lines, term)
    fng_analytics_content(fng_group, term, term_count, fng_lines)


def fng_analytics_groups(fng_ln, term):
    fng_group = \
        {match[1].strip()
         for line in fng_ln if (match := re.search(PAT_LN, line)) and
         term.lower() in match[1].lower()}
    term_cnt = sum(bool((match := re.search(PAT_LN, line)) and term.lower() in
                        match[1].lower()) for line in fng_ln)
    return fng_group, term_cnt


def fng_analytics_content(fng_group, term, term_count, fng_lines):
    if not fng_group:
        print(f"{get_detail('[fng_zero]', replace=True)} '{term}'.\n\n\
{get_detail('[fng_zero_2]', replace=True)}.\n")
    else:
        excl_ln = sum(bool(line.startswith('#')) for line in fng_lines) + 2
        fng_ln = len(fng_lines)-excl_ln
        pct_fng = round(term_count / fng_ln * 100, 2)
        print(f"{get_detail('[fng_add]', replace=True)} '{term}': {pct_fng}%\
 ({term_count}{get_detail('[pdf_footer2]', replace=True)} {fng_ln})")
        fng_analytics_sorted(fng_lines, term, fng_group)


def fng_analytics_sorted(fng_lines, term, fng_group):
    term_l = term.lower()
    for content in sorted(fng_group):
        print(f"\n [{content}]")
        for line in fng_lines:
            line_l = line.lower()
            if term_l in line_l and content in line:
                start_index = line.find('[')
                print(f"  {line[:start_index].strip()}")


def print_security_guides():
    print_detail('[security_guides]', 1)
    with open(path.join(HUM_D[0], HUM_F[3]), 'r', encoding='utf8') as \
            guides_source:
        for line in guides_source:
            if not line.startswith('#'):
                print(f" {Style.BRIGHT}{line}" if line.startswith('[') else f"\
  {line}", end='')


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
    print(".:")
    print("")
    print_detail_l('[analysis_time]')
    print(round(end - start, 2), end="")
    print_detail_l('[analysis_time_sec]')
    t_cnt = sum([m_cnt, f_cnt, i_cnt[0], e_cnt])
    mh_cnt, fh_cnt, ih_cnt, eh_cnt, th_cnt = get_analysis_totals(t_cnt)
    mhr_cnt, fhr_cnt, ihr_cnt, ehr_cnt, \
        thr_cnt = compare_analysis_totals(mh_cnt, m_cnt, fh_cnt, f_cnt, ih_cnt,
                                          i_cnt, eh_cnt, e_cnt, th_cnt, t_cnt)
    print("")
    print_analysis_totals(mhr_cnt, fhr_cnt, ihr_cnt, ehr_cnt, t_cnt, thr_cnt)


def get_analysis_totals(t_cnt):
    with open(HUM_F[0], 'a+', encoding='utf8') as a_history, \
         open(HUM_F[0], 'r', encoding='utf8') as c_history:
        a_history.write(f"{now} ; {URL} ; {m_cnt} ; {f_cnt} ; {i_cnt[0]} ; \
{e_cnt} ; {t_cnt}\n")
        url_ln = [line for line in c_history if URL in line]
        if not url_ln:
            return ("First",) * 5
        mh_cnt, fh_cnt, ih_cnt, eh_cnt, th_cnt = \
            extract_analysis_totals(url_ln)
        return mh_cnt, fh_cnt, ih_cnt, eh_cnt, th_cnt


def extract_analysis_totals(url_ln):
    date_var = max(line.split(" ; ")[0] for line in url_ln)
    for line in url_ln:
        if date_var in line:
            _, _, mh_cnt, fh_cnt, ih_cnt, eh_cnt, th_cnt = \
                line.strip().split(' ; ')
            break
    return mh_cnt, fh_cnt, ih_cnt, eh_cnt, th_cnt


def compare_analysis_totals(mh_cnt, m_cnt, fh_cnt, f_cnt, ih_cnt, i_cnt,
                            eh_cnt, e_cnt, th_cnt, t_cnt):
    if mh_cnt == "First":
        return [get_detail('[first_one]', replace=True)] * 5
    totals = [m_cnt - int(mh_cnt), f_cnt - int(fh_cnt), i_cnt[0] - int(ih_cnt),
              e_cnt - int(eh_cnt), t_cnt - int(th_cnt)]
    return [f'+{total}' if total > 0 else str(total) for total in totals]


def print_analysis_totals(mhr_cnt, fhr_cnt, ihr_cnt, ehr_cnt, t_cnt, thr_cnt):
    literals = ['[missing_cnt]', '[fng_cnt]', '[insecure_cnt]', '[empty_cnt]',
                '[total_cnt]']
    totals = [f"{m_cnt} ({mhr_cnt})", f"{f_cnt} ({fhr_cnt})", f"{i_cnt[0]} \
({ihr_cnt})", f"{e_cnt} ({ehr_cnt})\n", f"{t_cnt} ({thr_cnt})\n"]
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
    year_cnt = defaultdict(int)
    year_wng = defaultdict(int)
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
    url_lines = {}
    for line in url_ln:
        url = line.split(' ; ')[1]
        if url in url_lines:
            url_lines[url] += 1
        else:
            url_lines[url] = 1
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


def csp_full_analysis(csp_header):
    # TO-DO: detailed directives/values analysis, based on W3C CSP Level 2 & 3:
    #
    # 0.- Source values.
    #
    # 1.- Fetch directives: default-src, child-src, connect-src, font-src,
    # frame-src, img-src, manifest-src, media-src, object-src, prefetch-src,
    # script-src, script-src-elem, script-src-attr, style-src, style-src-elem,
    # style-src-attr, worker-src.
    #
    # 2.- Document directives: base-uri, sandbox.
    #
    # 3.- Navigation directives: form-action, frame-ancestors.
    #
    # Perhaps with a new file, 'csp_analysis.py', which will contain a class
    # (to be imported into 'humble.py') consisting of a function for each CSP
    # directive (in charge of all security validations like permissive sources,
    # unsafe values, incorrect values, absence of the directive itself, etc)
    # and a function that aggregates the results of those analyses and returns
    # it to 'humble.py' for text formatting, printing, etc.
    #
    # The following code is only a test.
    csp_output = []
    for directive in csp_header.split(';'):
        dir_csp = directive.strip().split(' ', 1)
        if dir_name := dir_csp[0]:
            csp_output.extend([f" {Style.BRIGHT}{dir_name}{Style.RESET_ALL}"])
            if len(dir_csp) > 1 and dir_csp[1]:
                csp_output.append(f" {dir_csp[1]}")
            csp_output.append("")
    return '\n'.join(csp_output)


def clean_shell_output(reliable=True):
    # Kudos to Aniket Navlur!!!: https://stackoverflow.com/a/52590238
    if not reliable:
        sys.stdout.write(CLE_O)
    sys.stdout.write(CLE_O)


def print_export_path(filename, reliable):
    clean_shell_output(reliable=False) if reliable else clean_shell_output()
    print("")
    print_detail_l('[report]')
    print(path.abspath(filename))


def print_nowarnings():
    print_detail('[no_warnings]')


def print_header(header):
    print(f" {header}" if args.output else f"{BRI_R} {header}")


def print_fng_header(header):
    prefix, _, suffix = [x.strip() for x in header.partition(' [')]
    if args.output:
        print(f" {header}")
    elif '[' in header:
        print(f"{BRI_R} {prefix}{Style.NORMAL}{Fore.RESET} [{suffix}")
    else:
        print(f"{BRI_R} {header}")


def print_analysis_info(reliable):
    if not args.output:
        clean_shell_output(reliable=False) if reliable else \
            clean_shell_output()
        print("")
        banner = '''  _                     _     _
 | |__  _   _ _ __ ___ | |__ | | ___
 | '_ \\| | | | '_ ` _ \\| '_ \\| |/ _ \\
 | | | | |_| | | | | | | |_) | |  __/
 |_| |_|\\__,_|_| |_| |_|_.__/|_|\\___|
'''
        print(banner)
        print(f" ({GIT_U} | v.{version})")
    elif args.output != 'pdf':
        print("")
        print(f"\n{PRG_N}\n{GIT_U} | v.{version}\n")
    print(linesep.join(['']*2) if args.output == 'html' or not args.output
          else "")
    print_detail_r('[0section]')
    print_detail_l('[analysis_date]')
    print(f" {now}")
    print(f'{URL_S}{URL}')
    if status_code in CLI_E or reliable or args.redirects:
        print_extra_info(reliable)


def print_extra_info(reliable):
    if status_code in CLI_E:
        id_mode = f"[http_{status_code}]"
        if detail := print_detail(id_mode, 0):
            print(detail)
        print(f"{REF_SRV_E}{status_code}")
    if reliable:
        print(get_detail('[unreliable_analysis_note]', replace=True))
    if args.redirects:
        print(get_detail('[analysis_redirects]', replace=True))


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
    style_str = BRI_R if is_red else Style.BRIGHT
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


def get_fingerprint_headers(headers, l_fng, l_fng_ex):
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


def check_path_traversal(path):
    path_traversal_ptrn = re.compile(PATH_PTRN)
    if path_traversal_ptrn.search(path):
        print(f"\n{get_detail('[args_path_traversal]', replace=True)} \
('{path}')")
        sys.exit()


def check_path_permissions(path_safe):
    try:
        open(path.join(path_safe, HUM_F[1]), 'w')
    except PermissionError:
        parser.error(f"{get_detail('[args_nowr]', replace=True)}'{path_safe}'")
    else:
        remove(path.join(path_safe, HUM_F[1]))


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


def generate_csv(name_e, name_p):
    with open(name_e, 'r', encoding='utf-8') as txt_source, \
         open(name_p, 'w', newline='', encoding='utf-8') as csv_final:
        csv_source = txt_source.read()
        csv_writer = csv.writer(csv_final, quoting=csv.QUOTE_ALL)
        csv_section = [get_detail(f'[{i}]', replace=True) for i in CSV_ID]
        csv_writer.writerow([get_detail(f'[{i}]', replace=True) for i in
                             ['csv_section', 'csv_values']])
        parse_csv(csv_writer, csv_source, csv_section)
    print_export_path(name_p, reliable)
    remove(name_e)


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


def generate_json(name_e, name_p):
    section0, sectionh, section5 = [get_detail(f'[{i}]', replace=True) for i
                                    in ['0section', '0headers', '5compat']]
    with (open(name_e, 'r', encoding='utf8') as txt_source,
          open(name_p, 'w', encoding='utf8') as json_final):
        txt_content = txt_source.read()
        txt_sections = re.split(r'\[(.*?)\]\n', txt_content)[1:]
        data = {}
        parse_json_sections(txt_sections, data, section0, sectionh, section5)
        json_data = json.dumps(data, indent=4, ensure_ascii=False)
        json_final.write(json_data)
    print_export_path(name_p, reliable)
    remove(name_e)


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


def generate_pdf(name_e, pdf):
    set_pdf_structure()
    with open(name_e, "r", encoding='utf8') as txt_source:
        links_strings = (URL_S, REF_E, REF_S, CAN_S)
        for i in txt_source:
            if '[' in i:
                set_pdf_sections(i)
            pdf.set_font(style='B' if any(s in i for s in BOLD_S) else '')
            for string in links_strings:
                if string in i:
                    set_pdf_links(i, string)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(197, 2.6, text=i, align='L')
    pdf.output(name_p)
    print_export_path(name_p, reliable)
    remove(name_e)


def set_pdf_structure():
    pdf.alias_nb_pages()
    set_pdf_metadata()
    pdf.set_display_mode(zoom=125)
    pdf.add_page()
    pdf.set_font("Courier", size=9)


def set_pdf_metadata():
    title = f"{get_detail('[pdf_meta_title]', replace=True)} {URL}"
    git_urlc = f"{GIT_U} | v.{version}"
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
    link_prefixes = {REF_E: REF_1, REF_S: REF_2}
    links_d = {URL_S: URL, REF_E: i.partition(REF_E)[2].strip(),
               REF_S: i.partition(REF_S)[2].strip(),
               CAN_S: i.partition(': ')[2].strip()}
    link_final = links_d.get(pdfstring)
    if pdfstring in (URL_S, REF_E, REF_S):
        prefix = link_prefixes.get(pdfstring, pdfstring)
        pdf.write(h=3, text=prefix)
    else:
        pdf.write(h=3, text=i[:i.index(": ")+2])
    pdf.set_text_color(0, 0, 255)
    pdf.cell(w=2000, h=3, text=i[i.index(": ")+2:], align="L", link=link_final)


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
    if condition == REF_2:
        html_final.write(f"{ln[:6]}{sub_d['ahref_s']}{ln[6:]}\
{sub_d['close_t']}{ln[6:]}{sub_d['ahref_f']}<br>")
    else:
        html_final.write(f"{ln[:6]}{sub_d['ahref_s']}{ln[8:]}\
{sub_d['close_t']}{ln[6:]}{sub_d['ahref_f']}<br>")


def format_html_caniuse(ln, sub_d):
    ln = f"{sub_d['span_h']}{ln[1:ln.index(': ')]}: {sub_d['span_f']}\
{sub_d['ahref_s']}{ln[ln.index(SEC_S):]}{sub_d['close_t']}\
{ln[ln.index(SEC_S):]}{sub_d['ahref_f']}<br>"
    html_final.write(ln)


def format_html_bold(ln):
    html_final.write(f'<strong>{ln}</strong><br>')


def print_http_exception(id_exception, exception_v):
    clean_shell_output()
    print("")
    print_detail(id_exception)
    raise SystemExit from exception_v


def print_ru_message():
    with contextlib.suppress(requests.exceptions.RequestException):
        requests.packages.urllib3.disable_warnings()
        sffx = tldextract.extract(URL).suffix[-2:].upper()
        cnty = requests.get(RU_I[0], verify=False, timeout=5).text.strip()
        if (sffx == RU_I[1] and sffx not in NON_RU_TLD) or cnty == RU_I[2]:
            print_detail('[ru_analysis_message]', 3)
            sys.exit()


def handle_http_error(http_code, id_mode):
    if str(http_code).startswith('5'):
        clean_shell_output()
        print()
        if http_code in SRV_E or http_code in CDN_E:
            if detail := print_detail(id_mode, 0):
                print(detail)
            else:
                print((REF_SRV_E if http_code in SRV_E else REF_CDN_E) +
                      str(http_code))
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
        handle_http_error(http_code, id_mode)
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
    return HelpFormatter(prog, max_help_position=30)


init(autoreset=True)

parser = ArgumentParser(formatter_class=custom_help_formatter,
                        description=f"{PRG_N} | {GIT_U} | v.{version}")

parser.add_argument("-a", dest='URL_A', action="store_true", help="show \
statistics of the performed analysis (will be global if '-u' is omitted)")
parser.add_argument("-b", dest='brief', action="store_true", help="show a \
brief analysis (if omitted, a detailed one will be shown)")
parser.add_argument("-df", dest='redirects', action="store_true", help="do not\
 follow redirects (if omitted, the last redirection will be the one analyzed)")
parser.add_argument("-e", nargs='?', type=str, dest='path', help="show TLS/SSL\
 checks (requires the PATH of https://testssl.sh/ and Linux/Unix OS)")
parser.add_argument("-f", nargs='?', type=str, dest='term', help="show \
fingerprint statistics (will be the Top 20 if \"TERM\", e.g. \"Google\", is \
omitted)")
parser.add_argument("-g", dest='guides', action="store_true", help="show \
guidelines for securing popular web servers/services")
parser.add_argument("-l", dest='lang', choices=['es'], help="the language for \
displaying analyses, errors and messages (if omitted it will be in English)")
parser.add_argument("-o", dest='output', choices=['csv', 'html', 'json', 'pdf',
                                                  'txt'], help="save analysis \
to 'scheme_host_port_yyyymmdd.ext' file (csv/json files will contain a brief \
analysis)")
parser.add_argument("-op", dest='output_path', type=str, help="save analysis \
to OUTPUT_PATH (if omitted, the PATH of 'humble.py' will be used)")
parser.add_argument("-r", dest='ret', action="store_true", help="show HTTP \
response headers and a detailed analysis ('-b' parameter will take priority)")
parser.add_argument('-u', type=str, dest='URL', help="scheme, host and port to\
 analyze. E.g. https://google.com")
parser.add_argument('-ua', type=str, dest='user_agent', help="User-Agent ID \
from 'additional/user_agents.txt' to use. '0' will show all and '1' is the \
default.")
parser.add_argument("-v", "--version", action="store_true", help="check for \
updates at https://github.com/rfc-st/humble")

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
l10n_details = get_l10n_details()
check_python_version()

if args.version:
    check_humble_updates(version)
    sys.exit()

if '-f' in sys.argv:
    fng_analytics(args.term) if args.term else fng_analytics_global()
    sys.exit()

if '-ua' in sys.argv and not args.URL:
    parser.error(get_detail('[args_useragent]'))
    sys.exit()
elif '-ua' in sys.argv and args.URL:
    ua_index = sys.argv.index('-ua')
    ua_id = sys.argv[ua_index + 1].lstrip('-ua') if ua_index + 1 < \
        len(sys.argv) else None
    ua_header = {'User-Agent': get_user_agent(ua_id)}
elif args.URL:
    ua_header = {'User-Agent': get_user_agent('1')}

if '-e' in sys.argv:
    if platform.system().lower() == 'windows':
        print_detail('[windows_ssltls]', 28)
        sys.exit()
    if (args.path is None or args.URL is None):
        parser.error(get_detail('[args_notestssl]'))

if args.lang and not (args.URL or args.URL_A) and not args.guides:
    parser.error(get_detail('[args_lang]'))

if args.output_path is not None:
    check_path_traversal(args.output_path)
    path_safe = path.abspath(args.output_path)
    if args.output is None:
        parser.error(get_detail('[args_nooutputfmt]'))
    else:
        if path.exists(path_safe):
            check_path_permissions(path_safe)
        else:
            parser.error(f"{get_detail('[args_noexportpath]', replace=True)}\
('{path_safe}')")

if any([args.brief, args.output, args.ret, args.redirects]) \
        and (args.URL is None or args.guides is None or args.URL_A is None):
    parser.error(get_detail('[args_several]'))

# Exporting a detailed analysis to CSV/JSON is tricky, too much effort.
if args.output in ['csv', 'json'] and not args.brief:
    parser.error(get_detail('[args_csv_json]'))

URL = args.URL

if args.guides or args.path or args.URL_A:
    if args.guides:
        print_security_guides()
    elif args.path:
        testssl_command(args.path, args.URL)
    elif args.URL_A:
        url_analytics() if args.URL else url_analytics(is_global=True)
    sys.exit()

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

# Export analysis
ext = ".txt" if args.output == 'txt' else "t.txt"

if args.output:
    orig_stdout = sys.stdout
    url_obj = tldextract.extract(URL)
    url_sch = urlparse(URL).scheme
    url_sub = f"_{url_obj.subdomain}." if url_obj.subdomain else '_'
    url_dom = f"{url_obj.domain}."
    url_tld = url_obj.suffix
    url_prt = f"_{urlparse(URL).port}_" if urlparse(URL).port is not None \
        else '_'
    name_e = f"{url_sch}{url_sub}{url_dom}{url_tld}{url_prt}{export_date}{ext}"
    if args.output_path:
        name_e = path.join(path_safe, name_e)
    f = open(name_e, 'w', encoding='utf8')
    sys.stdout = f

print_analysis_info(reliable)
print_response_headers() if args.ret else print(linesep.join([''] * 2))

# 1. Missing HTTP Security Headers
m_cnt = 0

print_detail_r('[1missing]')

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

# 2. Fingerprinting through Headers/Values
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

f_cnt = get_fingerprint_headers(headers, l_fng, l_fng_ex)

if args.brief and f_cnt != 0:
    print("")

if f_cnt == 0:
    print_nowarnings()

print("")

# 3. Deprecated HTTP Headers/Protocols and Insecure values
i_cnt = [0]

print_detail_r('[3depinsecure]')

if not args.brief:
    print_detail("[aisc]")

l_ins = ['Accept-CH', 'Accept-CH-Lifetime', 'Access-Control-Allow-Methods',
         'Access-Control-Allow-Origin', 'Allow', 'Content-DPR', 'Content-Type',
         'Digest', 'Etag', 'Expect-CT', 'Expires', 'Feature-Policy',
         'Large-Allocation', 'Onion-Location', 'P3P', 'Pragma',
         'Public-Key-Pins', 'Public-Key-Pins-Report-Only', 'Set-Cookie',
         'Server-Timing', 'SourceMap', 'Strict-Dynamic', 'Surrogate-Control',
         'Timing-Allow-Origin', 'Tk', 'Warning', 'X-Content-Security-Policy',
         'X-Content-Security-Policy-Report-Only', 'X-DNS-Prefetch-Control',
         'X-Download-Options', 'X-Pad', 'X-Permitted-Cross-Domain-Policies',
         'X-Pingback', 'X-Runtime', 'X-SourceMap', 'X-UA-Compatible',
         'X-Webkit-CSP', 'X-Webkit-CSP-Report-Only', 'X-XSS-Protection']

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
l_cencoding = ['br', 'compress', 'deflate', 'gzip', 'x-gzip']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
# https://www.w3.org/TR/CSP2/
# https://www.w3.org/TR/CSP3/
l_csp_broad = ['*',  'blob:', 'data:', 'ftp:', 'filesystem:', 'https:',
               'https://*', 'https://*.*', 'schemes:', 'wss:', 'wss://']

l_csp_equal = ['nonce', 'sha', 'style-src-elem', 'report-to', 'report-uri']

l_csp_dep = ['block-all-mixed-content', 'disown-opener', 'plugin-types',
             'prefetch-src', 'referrer', 'report-uri', 'require-sri-for']

l_csp_dirs = ['base-uri', 'child-src', 'connect-src', 'default-src',
              'font-src', 'form-action', 'frame-ancestors', 'frame-src',
              'img-src', 'manifest-src', 'media-src', 'navigate-to',
              'object-src', 'report-to', 'require-trusted-types-for',
              'sandbox', 'script-src', 'script-src-elem', 'script-src-attr',
              'style-src', 'style-src-elem', 'style-src-attr', 'trusted-types',
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

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
l_sts_dir = ['includesubdomains', 'max-age']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Supports-Loading-Mode
l_support_mode = ['credentialed-prerender']

# https://www.w3.org/TR/edge-arch/
l_surrogate = ['content', 'extension-directive', 'max-age', 'no-store',
               'no-store-remote']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Trailer
l_trailer = ['authorization', 'cache-control', 'content-encoding',
             'content-length', 'content-type', 'content-range', 'host',
             'max-forwards', 'set-cookie', 'te', 'trailer',
             'transfer-encoding']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding
l_transfer = ['chunked', 'compress', 'deflate', 'gzip']

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

if 'Accept-CH' in headers:
    acceptch_header = headers['Accept-CH'].lower()
    if URL.startswith(INS_S):
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

if 'Accept-CH-Lifetime' in headers:
    print_details('[ixacl_h]', '[ixacld]', 'd', i_cnt)

accescred_header = headers.get("Access-Control-Allow-Credentials", '').lower()
if accescred_header and accescred_header != 'true':
    print_details('[icred_h]', '[icred]', 'd', i_cnt)

if 'Access-Control-Allow-Methods' in headers:
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
                                val in ['.*', '*.']))):
    print_details('[iaccess_h]', '[iaccess]', 'd', i_cnt)

accesma_header = headers.get("Access-Control-Max-Age", '')
if accesma_header and int(accesma_header) > 86400:
    print_details('[iacessma_h]', '[iaccessma]', 'd', i_cnt)

if 'Allow' in headers:
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
if cache_header and not any(elem in cache_header for elem in l_cachev):
    print_details('[icachev_h]', '[icachev]', 'd', i_cnt)
if cache_header and not all(elem in cache_header for elem in l_cache):
    print_details('[icache_h]', '[icache]', 'd', i_cnt)

if 'Clear-Site-Data' in headers:
    clsdata_header = headers['Clear-Site-Data'].lower()
    if URL.startswith(INS_S):
        print_details('[icsd_h]', '[icsd]', 'd', i_cnt)
    if not any(elem in clsdata_header for elem in l_csdata):
        print_details('[icsdn_h]', '[icsdn]', 'd', i_cnt)

cencod_header = headers.get("Content-Encoding", '').lower()
if cencod_header and not any(elem in cencod_header for elem in l_cencoding):
    print_details('[icencod_h]', '[icencod]', 'd', i_cnt)

if 'Content-DPR' in headers:
    print_details('[ixcdpr_h]', '[ixcdprd]', 'd', i_cnt)

if 'Content-Security-Policy' in headers:
    csp_h = headers['Content-Security-Policy'].lower()
    if not any(elem in csp_h for elem in l_csp_dirs):
        print_details('[icsi_h]', '[icsi]', 'd', i_cnt)
    if ('=' in csp_h) and not (any(elem in csp_h for elem in l_csp_equal)):
        print_details('[icsn_h]', '[icsn]', 'd', i_cnt)
    csp_store_values(csp_h, l_csp_broad, l_csp_insecs, i_cnt)
    if any(elem in csp_h for elem in l_csp_insecv):
        print_details('[icsp_h]', '[icsp]', 'm', i_cnt)
    if 'unsafe-hashes' in csp_h:
        print_details('[icsu_h]', '[icsu]', 'd', i_cnt)
    if "'nonce-" in csp_h:
        nonces_csp = re.findall(r"'nonce-([^']+)'", csp_h)
        for nonce_csp in nonces_csp:
            if len(nonce_csp) < 32:
                print_details('[icsnces_h]', '[icsnces]', 'd', i_cnt)
                break
    ip_mtch = re.findall(IP_PTRN, csp_h)
    if ip_mtch != ['127.0.0.1']:
        for match in ip_mtch:
            if re.match(IP_PTRN, match):
                print_details('[icsipa_h]', '[icsipa]', 'm', i_cnt)
                break

csp_ro_header = headers.get('Content-Security-Policy-Report-Only', '').lower()
if csp_ro_header and any(elem in csp_ro_header for elem in l_csp_ro_dep):
    print_detail_r('[icsiro_d]', is_red=True)
    if not args.brief:
        matches_csp_ro = [x for x in l_csp_ro_dep if x in csp_ro_header]
        print_detail_l("[icsi_d_s]")
        print(', '.join(matches_csp_ro))
        print_detail("[icsiro_d_r]")
    i_cnt[0] += 1

ctype_header = headers.get('Content-Type', '').lower()
if ctype_header:
    if any(elem in ctype_header for elem in l_legacy):
        print_details('[ictlg_h]', '[ictlg]', 'm', i_cnt)
    if 'html' not in ctype_header:
        print_details('[ictlhtml_h]', '[ictlhtml]', 'd', i_cnt)

if 'Critical-CH' in headers and URL.startswith(INS_S):
    print_details('[icrch_h]', '[icrch]', 'd', i_cnt)

if 'Cross-Origin-Embedder-Policy' in headers:
    coep_h = headers['Cross-Origin-Embedder-Policy'].lower()
    if not any(elem in coep_h for elem in l_coep):
        print_details('[icoep_h]', '[icoep]', 'd', i_cnt)

if 'Cross-Origin-Opener-Policy' in headers:
    coop_h = headers['Cross-Origin-Opener-Policy'].lower()
    if not any(elem in coop_h for elem in l_coop):
        print_details('[icoop_h]', '[icoop]', 'd', i_cnt)

if 'Cross-Origin-Resource-Policy' in headers:
    corp_h = headers['Cross-Origin-Resource-Policy'].lower()
    if not any(elem in corp_h for elem in l_corp):
        print_details('[icorp_h]', '[icorp]', 'd', i_cnt)

if 'Digest' in headers:
    print_details('[idig_h]', '[idig]', 'd', i_cnt)

if 'Etag' in headers:
    print_details('[ieta_h]', '[ieta]', 'd', i_cnt)

if 'Expect-CT' in headers:
    print_details('[iexct_h]', '[iexct]', 'm', i_cnt)

if 'Expires' in headers and any(elem in headers.get('Cache-Control', '') for
                                elem in l_excc):
    print_details('[iexpi_h]', '[iexpi]', 'd', i_cnt)

if 'Feature-Policy' in headers:
    print_details('[iffea_h]', '[iffea]', 'd', i_cnt)

if URL.startswith(INS_S):
    print_details('[ihttp_h]', '[ihttp]', 'd', i_cnt)

if ('Keep-Alive' in headers and headers['Keep-Alive'] and
    ('Connection' not in headers or
     headers['Connection'].lower() != 'keep-alive')):
    print_details('[ickeep_h]', '[ickeep]', 'd', i_cnt)

if 'Large-Allocation' in headers:
    print_details('[ixlalloc_h]', '[ixallocd]', 'd', i_cnt)

if 'Onion-Location' in headers:
    print_details('[ionloc_h]', '[ionloc]', 'm', i_cnt)

if 'Origin-Agent-Cluster' in headers:
    origin_cluster_h = headers['Origin-Agent-Cluster'].lower()
    if not any(elem in origin_cluster_h for elem in l_origcluster):
        print_details('[iorigcluster_h]', '[iorigcluster]', 'd', i_cnt)

if 'P3P' in headers:
    print_details('[ip3p_h]', '[ip3p]', 'd', i_cnt)

if 'Permissions-Policy' in headers:
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

if 'Pragma' in headers:
    print_details('[iprag_h]', '[iprag]', 'd', i_cnt)

if 'Proxy-Authenticate' in headers:
    prxyauth_h = headers['Proxy-Authenticate'].lower()
    if 'basic' in prxyauth_h and URL.startswith(INS_S):
        print_details('[iprxauth_h]', '[ihbas]', 'd', i_cnt)

if 'Public-Key-Pins' in headers:
    print_details('[ipkp_h]', '[ipkp]', 'd', i_cnt)

if 'Public-Key-Pins-Report-Only' in headers:
    print_details('[ipkpr_h]', '[ipkp]', 'd', i_cnt)

referrer_header = headers.get('Referrer-Policy', '').lower()
if referrer_header:
    if not any(elem in referrer_header for elem in l_ref_secure):
        print_details('[iref_h]', '[iref]', 'm', i_cnt)
    if 'unsafe-url' in referrer_header:
        print_details('[irefi_h]', '[irefi]', 'd', i_cnt)
    if not any(elem in referrer_header for elem in l_ref_values):
        print_details('[irefn_h]', '[irefn]', 'd', i_cnt)

if 'Server-Timing' in headers:
    print_details('[itim_h]', '[itim]', 'd', i_cnt)

stc_header = headers.get("Set-Cookie", '').lower()
if stc_header:
    if not (URL.startswith(INS_S)) and not all(elem in stc_header for elem in
                                               l_cookie_sec):
        print_details("[iset_h]", "[iset]", "d", i_cnt)
    if URL.startswith(INS_S):
        if 'secure' in stc_header:
            print_details("[iseti_h]", "[iseti]", "d", i_cnt)
        if any(prefix in stc_header for prefix in l_cookie_prf):
            print_details("[ispref_m]", "[ispref]", "d", i_cnt)
    if "samesite=none" in stc_header and "secure" not in stc_header:
        print_details("[iseti_m]", "[isetm]", "d", i_cnt)

if 'SourceMap' in headers:
    print_details('[ismap_m]', '[ismap]', 'd', i_cnt)

if 'Strict-Dynamic' in headers:
    print_details('[isdyn_h]', '[isdyn]', 'd', i_cnt)

sts_header = headers.get('Strict-Transport-Security', '').lower()
if (sts_header) and not (URL.startswith(INS_S)):
    try:
        age = int(''.join(filter(str.isdigit, sts_header)))
        if not all(elem in sts_header for elem in l_sts_dir) or age < 31536000:
            print_details('[ists_h]', '[ists]', 'm', i_cnt)
        if ',' in sts_header:
            print_details('[istsd_h]', '[istsd]', 'd', i_cnt)
    except ValueError:
        print_details('[ists_h]', '[ists]', 'm', i_cnt)

if 'Supports-Loading-Mode' in headers:
    support_mode_h = headers['Supports-Loading-Mode'].lower()
    if not any(elem in support_mode_h for elem in l_support_mode):
        print_details('[islmode_h]', '[islmode]', 'd', i_cnt)

if (sts_header) and (URL.startswith(INS_S)):
    print_details('[ihsts_h]', '[ihsts]', 'd', i_cnt)

if 'Surrogate-Control' in headers:
    surrogate_mode_h = headers['Surrogate-Control'].lower()
    if not any(elem in surrogate_mode_h for elem in l_surrogate):
        print_details('[isurrmode_h]', '[isurrmode]', 'd', i_cnt)

if headers.get('Timing-Allow-Origin', '') == '*':
    print_details('[itao_h]', '[itao]', 'd', i_cnt)

if 'Tk' in headers:
    print_details('[ixtk_h]', '[ixtkd]', 'd', i_cnt)

if 'Trailer' in headers:
    trailer_h = headers['Trailer'].lower()
    if any(elem in trailer_h for elem in l_trailer):
        print_detail_r('[itrailer_h]', is_red=True)
        if not args.brief:
            matches_trailer = [x for x in l_trailer if x in trailer_h]
            print_detail_l("[itrailer_d_s]")
            print(', '.join(matches_trailer))
            print_detail("[itrailer_d_r]")
        i_cnt[0] += 1

if 'Transfer-Encoding' in headers:
    transfer_h = headers['Transfer-Encoding'].lower()
    if not any(elem in transfer_h for elem in l_transfer):
        print_details('[ictrf_h]', '[itrf]', 'd', i_cnt)

if 'Warning' in headers:
    print_details('[ixwar_h]', '[ixward]', 'd', i_cnt)

wwwa_header = headers.get('WWW-Authenticate', '').lower()
if (wwwa_header) and (URL.startswith(INS_S)) and ('basic' in wwwa_header):
    print_details('[ihbas_h]', '[ihbas]', 'd', i_cnt)

if 'X-Content-Security-Policy' in headers:
    print_details('[ixcsp_h]', '[ixcsp]', 'd', i_cnt)

if 'X-Content-Security-Policy-Report-Only' in headers:
    print_details('[ixcspr_h]', '[ixcspr]', 'd', i_cnt)

if 'X-Content-Type-Options' in headers:
    if ',' in headers['X-Content-Type-Options']:
        print_details('[ictpd_h]', '[ictpd]', 'd', i_cnt)
    elif 'nosniff' not in headers['X-Content-Type-Options']:
        print_details('[ictp_h]', '[ictp]', 'd', i_cnt)

if headers.get('X-DNS-Prefetch-Control', '') == 'on':
    print_details('[ixdp_h]', '[ixdp]', 'd', i_cnt)

if 'X-Download-Options' in headers:
    print_details('[ixdow_h]', '[ixdow]', 'm', i_cnt)

xfo_header = headers.get('X-Frame-Options', '').lower()
if xfo_header:
    if ',' in xfo_header:
        print_details('[ixfo_h]', '[ixfo]', 'm', i_cnt)
    if 'allow-from' in xfo_header:
        print_details('[ixfod_h]', '[ixfod]', 'm', i_cnt)
    if xfo_header not in l_xfo_dir:
        print_details('[ixfoi_h]', '[ixfodi]', 'm', i_cnt)

if 'X-Pad' in headers:
    print_details('[ixpad_h]', '[ixpad]', 'd', i_cnt)

if headers.get('X-Permitted-Cross-Domain-Policies', '') == 'all':
    print_details('[ixcd_h]', '[ixcd]', 'm', i_cnt)

if headers.get('X-Pingback', '').endswith('xmlrpc.php'):
    print_details('[ixpb_h]', '[ixpb]', 'd', i_cnt)

robots_header = headers.get('X-Robots-Tag', '').lower()
if robots_header:
    if not any(elem in robots_header for elem in l_robots):
        print_details('[ixrobv_h]', '[ixrobv]', 'm', i_cnt)
    if 'all' in robots_header:
        print_details('[ixrob_h]', '[ixrob]', 'm', i_cnt)

if 'X-Runtime' in headers:
    print_details('[ixrun_h]', '[ixrun]', 'd', i_cnt)

if 'X-SourceMap' in headers:
    print_details('[ixsrc_h]', '[ixsrc]', 'd', i_cnt)

if 'X-UA-Compatible' in headers:
    print_details('[ixuacom_h]', '[ixuacom]', 'm', i_cnt)

if 'X-Webkit-CSP' in headers:
    print_details('[ixwcsp_h]', '[ixcsp]', 'd', i_cnt)

if 'X-Webkit-CSP-Report-Only' in headers:
    print_details('[ixwcspr_h]', '[ixcspr]', 'd', i_cnt)

if 'X-XSS-Protection' in headers:
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

# 4. Empty HTTP Response Headers Values
e_cnt = 0
l_empty = []
print_detail_r('[4empty]')

if not args.brief:
    print_detail("[aemp]")

for key in sorted(headers):
    if not headers[key]:
        l_empty.append("_" + key)
        print_header(key)
        e_cnt += 1

print("") if e_cnt != 0 else print_nowarnings()
print("")

# 5. Browser Compatibility for Enabled HTTP Security Headers
print_detail_r('[5compat]')

l_sec = ['Access-Control-Allow-Methods', 'Access-Control-Allow-Credentials',
         'Cache-Control', 'Clear-Site-Data', 'Content-Type',
         'Content-Security-Policy', 'Critical-CH',
         'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy',
         'Cross-Origin-Resource-Policy', 'ETag', 'Feature-Policy', 'NEL',
         'Origin-Agent-Cluster', 'Proxy-Authenticate', 'Permissions-Policy',
         'Referrer-Policy', 'Server-Timing', 'Set-Cookie',
         'Strict-Transport-Security', 'Supports-Loading-Mode',
         'Timing-Allow-Origin', 'Trailer', 'WWW-Authenticate',
         'X-Content-Type-Options', 'X-DNS-Prefetch-Control',
         'X-Frame-Options', 'X-XSS-Protection']

header_matches = [header for header in l_sec if header in headers]

if header_matches:
    for key in header_matches:
        output_string = "  " if args.output == 'html' else " "
        key_string = key if args.output else f"{Fore.CYAN}{key}{Fore.RESET}"
        print(f"{output_string}{key_string}{CAN_S}\
{key.replace('Content-Security-Policy', 'contentsecuritypolicy2')}")
else:
    print_detail_l("[no_sec_headers]") if args.output else \
        print_detail_r("[no_sec_headers]", is_red=True)

print(linesep.join(['']*2))
end = time()
get_analysis_result()

# Export analysis
if args.output:
    name_p = f"{name_e[:-5]}.{args.output}"
    sys.stdout = orig_stdout
    f.close()
if args.output == 'txt':
    print_export_path(name_e, reliable)
elif args.output == 'csv':
    generate_csv(name_e, name_p)
elif args.output == 'json':
    generate_json(name_e, name_p)
elif args.output == 'pdf':
    pdf = PDF()
    generate_pdf(name_e, pdf)
elif args.output == 'html':
    html_title = get_detail('[pdf_meta_subject]')
    html_desc = get_detail('[pdf_meta_title]')
    html_keywords = get_detail('[pdf_meta_keywords]')
    html_head = f'<!DOCTYPE HTML><html lang="en"><head><meta http-equiv="\
Content-Type" content="text/html; charset=utf-8"><meta name="description" \
content="{html_desc} {URL}"><meta name="keywords" content="{html_keywords}">\
<meta name="author" content="{GIT_U} | v.{version}"><meta name="generator" \
content="{GIT_U} | v.{version}"><title>{html_title}</title><style>pre \
{{overflow-x: auto; white-space: pre-wrap;white-space: -moz-pre-wrap; \
white-space: -pre-wrap;white-space: -o-pre-wrap; word-wrap: break-word; \
font-size: 13px;}} a {{color: blue; text-decoration: none;}} .ok \
{{color: green;}} .header {{color: #660033;}} .ko {{color: red;}} </style>\
 </head>'
    html_body = '<body><pre>'
    html_footer = '</pre></body></html>'

    l_miss.extend(['Pragma', 'WWW-Authenticate', 'X-Frame-Options',
                   'X-Robots-Tag', 'X-UA-compatible'])
    l_final = sorted(l_miss + l_ins)
    l_fng_final = sorted(l_fng)
    l_fng_final_case = [x.casefold() for x in l_fng_final]

    ok_string, ko_string = [get_detail(f'[{i}]') for i
                            in ['no_warnings', 'no_sec_headers']]

    sub_d = {'ahref_f': '</a>', 'ahref_s': '<a href="', 'close_t': '">',
             'span_ko': '<span class="ko">', 'span_h': '<span class="header">',
             'span_f': '</span>'}

    with open(name_e, 'r', encoding='utf8') as html_source, \
            open(name_p, 'w', encoding='utf8') as html_final:
        html_final.write(f"{html_head}{html_body}")

        for ln in html_source:
            ln_stripped = ln.rstrip('\n')
            if 'rfc-st' in ln or URL_S in ln:
                condition = 'rfc-st' if 'rfc-st' in ln else URL_S
                format_html_info(condition, ln_stripped, sub_d)
            elif any(s in ln for s in BOLD_S):
                format_html_bold(ln_stripped)
            elif ok_string in ln or ko_string in ln:
                condition = ok_string if ok_string in ln else ko_string
                format_html_okko(condition, ln_stripped, sub_d)
            elif REF_2 in ln or REF_1 in ln:
                condition = REF_2 if REF_2 in ln else REF_1
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
        html_final.write(html_footer)

    print_export_path(name_p, reliable)
    remove(name_e)
