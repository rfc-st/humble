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

# Standard Library imports
from time import time
from json import dumps
from shlex import quote
from shutil import copyfile
from platform import system
from itertools import islice
from datetime import datetime
from csv import writer, QUOTE_ALL
from urllib.parse import urlparse
from subprocess import PIPE, Popen
from os import linesep, path, remove
from collections import Counter, defaultdict
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import re
import ssl
import sys
import contextlib
import concurrent.futures

# Third-Party imports
from colorama import Fore, Style, init
from requests.adapters import HTTPAdapter
import requests
import tldextract


BANNER = '''  _                     _     _
 | |__  _   _ _ __ ___ | |__ | | ___
 | '_ \\| | | | '_ ` _ \\| '_ \\| |/ _ \\
 | | | | |_| | | | | | | |_) | |  __/
 |_| |_|\\__,_|_| |_| |_|_.__/|_|\\___|
'''
BOLD_STRING = ("[0.", "HTTP R", "[1.", "[2.", "[3.", "[4.", "[5.",
               "[Cabeceras")
CSV_SECTION = ('0section', '0headers', '1missing', '2fingerprint',
               '3depinsecure', '4empty', '5compat')
DELETED_LINES = '\x1b[1A\x1b[2K\x1b[1A\x1b[2K\x1b[1A\x1b[2K'
FORCED_CIPHERS = ":".join(["HIGH", "!DH", "!aNULL"])
HTTP_SCHEMES = ('http:', 'https:')
HUMBLE_DESC = "'humble' (HTTP Headers Analyzer)"
HUMBLE_DIRS = ('additional', 'l10n')
HUMBLE_FILES = ('analysis_h.txt', 'check_path_permissions', 'fingerprint.txt',
                'guides.txt', 'details_es.txt', 'details.txt',
                'user_agents.txt', 'insecure.txt', 'html_template.html',
                'testssl.sh', 'grades.txt', 'grades_es.txt', 'lic.txt',
                'lic_es.txt')
# https://data.iana.org/TLD/tlds-alpha-by-domain.txt
NON_RU_TLD = ('CYMRU', 'GURU', 'PRU')
RE_PATTERN = (r'\[(.*?)\]',
              (r'^(?:\d{1,3}\.){3}\d{1,3}$|'
               r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'),
              (r'\.\./|/\.\.|\\\.\.|\\\.\\|'
               r'%2e%2e%2f|%252e%252e%252f|%c0%ae%c0%ae%c0%af|'
               r'%uff0e%uff0e%u2215|%uff0e%uff0e%u2216'), r'\[([^\]]+)\]',
              r'\d{4}-\d{2}-\d{2}', r'\[(.*?)\]\n', r"'nonce-([^']+)'",
              r'\(humble_pdf_style\)([^:]+):')
REF_LINKS = (' Ref  : ', ' Ref: ', 'Ref  :', 'Ref: ')
RU_CHECKS = ('https://ipapi.co/country_name/', 'RU', 'Russia')
SLICE_INT = (30, 43, 25, 24, -4, -5)
STYLE = (Style.BRIGHT, f"{Style.BRIGHT}{Fore.RED}", Fore.CYAN, Style.NORMAL,
         Style.RESET_ALL, Fore.RESET, '(humble_pdf_style)')
# Check https://testssl.sh/doc/testssl.1.html to choose your preferred options
TESTSSL_OPTIONS = ['-f', '-g', '-p', '-U', '-s', '--hints']
URL_LIST = (': https://caniuse.com/?search=', ' Ref  : https://developers.clou\
dflare.com/support/troubleshooting/cloudflare-errors/troubleshooting-cloudflar\
e-5xx-errors/', ' Ref  : https://developer.mozilla.org/en-US/docs/Web/HTTP/Sta\
tus/', 'https://raw.githubusercontent.com/rfc-st/humble/master/humble.py', 'ht\
tps://github.com/rfc-st/humble')
URL_STRING = ('rfc-st', ' URL  : ', 'caniuse')

current_time = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
local_version = datetime.strptime('2024-08-16', '%Y-%m-%d').date()


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


def check_humble_updates(local_version):
    try:
        github_repo = requests.get(URL_LIST[3], timeout=10).text
        github_date = re.search(RE_PATTERN[4], github_repo).group()
        github_version = datetime.strptime(github_date, '%Y-%m-%d').date()
        if github_version > local_version:
            print(f"\n{get_detail('[humble_not_recent]')[:-1]}: \
'{local_version}'"f"\n\n{get_detail('[github_humble]', replace=True)}")
        else:
            print(f"\n{get_detail('[humble_recent]', replace=True)}")
    except requests.exceptions.RequestException:
        print_error_detail('[update_error]')
    sys.exit()


def fng_statistics_top():
    print(f"\n{STYLE[0]}{get_detail('[fng_stats]', replace=True)}\
{STYLE[4]}{get_detail('[fng_source]', replace=True)}\n")
    with open(path.join(HUMBLE_DIRS[0], HUMBLE_FILES[2]), 'r',
              encoding='utf8') as fng_f:
        fng_lines = fng_f.readlines()
    fng_incl = sum(1 for _ in islice(fng_lines, SLICE_INT[0], None))
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
    with open(path.join(HUMBLE_DIRS[0], HUMBLE_FILES[2]), 'r',
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
                print(f"  {line[:line.find('[')].strip()}")
    sys.exit()


def print_grades_guide(args):
    grade_l10n = HUMBLE_FILES[11] if args.lang == 'es' else HUMBLE_FILES[10]
    with open(path.join(HUMBLE_DIRS[1], grade_l10n), 'r',
              encoding='utf8') as grades_source:
        for line in islice(grades_source, SLICE_INT[3], None):
            print(f" {STYLE[0]}{line}" if line.startswith('[') else f"\
  {line}", end='')
    sys.exit()


def print_license(args):
    license_l10n = HUMBLE_FILES[13] if args.lang == 'es' else HUMBLE_FILES[12]
    with open(path.join(HUMBLE_DIRS[1], license_l10n), 'r',
              encoding='utf8') as license_source:
        for line in license_source:
            print(f" {STYLE[0]}{line}" if line.startswith('[') else f"\
  {line}", end='')
    sys.exit()


def print_security_guides():
    print_detail('[security_guides]')
    with open(path.join(HUMBLE_DIRS[0], HUMBLE_FILES[3]), 'r',
              encoding='utf8') as guides_source:
        for line in islice(guides_source, SLICE_INT[3], None):
            print(f" {STYLE[0]}{line}" if line.startswith('[') else f"\
  {line}", end='')
    sys.exit()


def testssl_command(testssl_temp_path, uri):
    if not path.isdir(testssl_temp_path):
        print_error_detail('[notestssl_path]')
    testssl_final_path = path.join(testssl_temp_path, HUMBLE_FILES[9])
    if not path.isfile(testssl_final_path):
        print_error_detail('[notestssl_file]')
    else:
        testssl_command = [testssl_final_path] + TESTSSL_OPTIONS + [quote(uri)]
        testssl_analysis(testssl_command)
    sys.exit()


def testssl_analysis(testssl_command):
    try:
        process = Popen(testssl_command, stdout=PIPE, stderr=PIPE, text=True)
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
    l10n_path = path.join(HUMBLE_DIRS[1], HUMBLE_FILES[4] if args.lang == 'es'
                          else HUMBLE_FILES[5])
    with open(l10n_path, 'r', encoding='utf8') as l10n_source:
        return l10n_source.readlines()


def get_analysis_results():
    print(".:\n")
    print_detail_l('[analysis_time]')
    print(round(end - start, 2), end="")
    print_detail_l('[analysis_time_sec]')
    t_cnt = sum([m_cnt, f_cnt, i_cnt[0], e_cnt])
    analysis_totals = save_analysis_results(t_cnt)
    analysis_diff = compare_analysis_results(*analysis_totals, m_cnt=m_cnt,
                                             f_cnt=f_cnt, i_cnt=i_cnt,
                                             e_cnt=e_cnt, t_cnt=t_cnt)
    print("")
    print_analysis_results(*analysis_diff, t_cnt=t_cnt)
    analysis_grade = grade_analysis(m_cnt, f_cnt, i_cnt, e_cnt)
    print(f"{get_detail(analysis_grade)}")


def save_analysis_results(t_cnt):
    with open(HUMBLE_FILES[0], 'a+', encoding='utf8') as all_analysis:
        all_analysis.seek(0)
        url_ln = [line for line in all_analysis if URL in line]
        all_analysis.write(f"{current_time} ; {URL} ; {m_cnt} ; {f_cnt} ; \
{i_cnt[0]} ; {e_cnt} ; {t_cnt}\n")
    return get_analysis_totals(url_ln) if url_ln else ("First",) * 5


def get_analysis_totals(url_ln):
    analysis_date = max(line.split(" ; ")[0] for line in url_ln)
    for line in url_ln:
        if analysis_date in line:
            *totals, = line.strip().split(' ; ')
            break
    return tuple(totals[2:])


def compare_analysis_results(*analysis_totals, m_cnt, f_cnt, i_cnt, e_cnt,
                             t_cnt):
    if analysis_totals[0] == "First":
        return [get_detail('[first_analysis]', replace=True)] * 5
    current = [int(val) for val in analysis_totals]
    differences = [m_cnt, f_cnt, i_cnt[0], e_cnt, t_cnt]
    return [str(d - c) if (d - c) <= 0 else f'+{d - c}' for d, c in
            zip(differences, current)]


def print_analysis_results(*diff, t_cnt):
    literals = ['[missing_cnt]', '[fng_cnt]', '[insecure_cnt]', '[empty_cnt]',
                '[total_cnt]']
    totals = [f"{m_cnt} ({diff[0]})", f"{f_cnt} ({diff[1]})", f"{i_cnt[0]} \
({diff[2]})", f"{e_cnt} ({diff[3]})\n", f"{t_cnt} ({diff[4]})\n"]
    print("")
    for literal, total in zip(literals, totals):
        print(f"{(print_detail_l(literal) or '')[:-1]}{total}")


# Use '-grd' parameter to show the checks to grade an analysis, along with
# advice for improvement.
def grade_analysis(m_cnt, f_cnt, i_cnt, e_cnt):
    if i_cnt and sum(i_cnt) > 0:
        return '[d_grade]'
    if m_cnt > 0:
        return '[c_grade]'
    if f_cnt > 0:
        return '[b_grade]'
    return '[a_grade]' if e_cnt > 0 else '[perfect_grade]'


def analysis_exists(filepath):
    if not path.exists(filepath):
        detail = '[no_analysis]' if args.URL else '[no_global_analysis]'
        print_error_detail(detail)


def url_analytics(is_global=False):
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
    total_a = len(url_ln)
    first_m = get_first_metrics(url_ln)
    second_m = [get_second_metrics(url_ln, i, total_a) for i in range(2, 6)]
    third_m = get_third_metrics(url_ln)
    additional_m = get_additional_metrics(url_ln)
    fourth_m = get_highlights(url_ln)
    return print_metrics(total_a, first_m, second_m, third_m, additional_m,
                         fourth_m)


def get_first_metrics(url_ln):
    first_a = min(f"{line.split(' ; ')[0]}" for line in url_ln)
    latest_a = max(f"{line.split(' ; ')[0]}" for line in url_ln)
    date_w = [(line.split(" ; ")[0],
               int(line.strip().split(" ; ")[-1])) for line in url_ln]
    best_d, best_w = min(date_w, key=lambda x: x[1])
    worst_d, worst_w = max(date_w, key=lambda x: x[1])
    return (first_a, latest_a, best_d, best_w, worst_d, worst_w)


def get_second_metrics(url_ln, index, total_a):
    metric_c = len([line for line in url_ln if int(line.split(' ; ')[index])
                    == 0])
    return f"{metric_c / total_a:.0%} ({metric_c}\
{get_detail('[pdf_footer2]', replace=True)} {total_a})"


def get_third_metrics(url_ln):
    fields = [line.strip().split(';') for line in url_ln]
    total_miss, total_fng, total_dep, total_ety = \
        [sum(int(f[i]) for f in fields) for i in range(2, 6)]
    num_a = len(url_ln)
    avg_miss, avg_fng, avg_dep, avg_ety = \
        [t // num_a for t in (total_miss, total_fng, total_dep, total_ety)]
    return (avg_miss, avg_fng, avg_dep, avg_ety)


def get_additional_metrics(url_ln):
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


def get_highlights(url_ln):
    sections = ['[missing_cnt]', '[fng_cnt]', '[insecure_cnt]', '[empty_cnt]']
    fields_h = [2, 3, 4, 5]
    return [f"{print_detail_l(sections[i], analytics=True)}\n"
            f"  {print_detail_l('[best_analysis]', analytics=True)}: \
{calculate_highlights(url_ln, fields_h[i], min)}\n"
            f"  {print_detail_l('[worst_analysis]', analytics=True)}: \
{calculate_highlights(url_ln, fields_h[i], max)}\n"
            for i in range(len(fields_h))]


def calculate_highlights(url_ln, field_index, func):
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


def extract_global_metrics(all_analysis):
    url_ln = list(all_analysis)
    if not url_ln:
        print_error_detail('[no_global_analysis]')
    total_a = len(url_ln)
    first_m = get_global_first_metrics(url_ln)
    second_m = [get_second_metrics(url_ln, i, total_a) for i in range(2, 6)]
    third_m = get_third_metrics(url_ln)
    additional_m = get_additional_metrics(url_ln)
    return print_global_metrics(total_a, first_m, second_m, third_m,
                                additional_m)


def get_global_first_metrics(url_ln):
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
    fields = [-1, 2, 3, 4, 5]
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


def get_basic_global_metrics(total_a, first_m):
    return {'[main]': "", '[total_analysis]': total_a,
            '[total_global_analysis]': str(first_m[2]),
            '[first_analysis_a]': first_m[0],
            '[latest_analysis]': f"{first_m[1]}\n",
            '[urls]': "", '[most_analyzed]': first_m[3],
            '[least_analyzed]': f"{first_m[4]}\n",
            '[most_missing]': first_m[7],
            '[least_missing]': f"{first_m[8]}\n",
            '[most_fingerprints]': first_m[9],
            '[least_fingerprints]': f"{first_m[10]}\n",
            '[most_insecure]': first_m[11],
            '[least_insecure]': f"{first_m[12]}\n",
            '[most_empty]': first_m[13],
            '[least_empty]': f"{first_m[14]}\n",
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


def csp_store_values(csp_header, l_csp_broad_s, l_csp_ins_s, i_cnt):
    csp_broad, csp_deprecated, csp_insecure = set(), set(), set()
    csp_directives = csp_header.split(';')
    for directive in csp_directives:
        csp_dir = directive.strip()
        csp_broad |= ({value for value in l_csp_broad_s if f' {value} ' in
                       f' {csp_dir} '})
        csp_deprecated |= ({value for value in t_csp_dep if value in csp_dir})
        csp_insecure |= ({value for value in l_csp_ins_s if value in csp_dir})
    csp_check_values(csp_broad, csp_deprecated, csp_insecure, i_cnt)
    return i_cnt


def csp_check_values(csp_broad, csp_deprecated, csp_insecure, i_cnt):
    csp_print_deprecated(csp_deprecated) if csp_deprecated else None
    csp_print_insecure(csp_insecure) if csp_insecure else None
    csp_print_broad(csp_broad) if csp_broad else None
    i_cnt[0] += sum(bool(csp) for csp in (csp_broad, csp_deprecated,
                                          csp_insecure))
    return i_cnt


def csp_print_deprecated(csp_deprecated):
    print_detail_r('[icsi_d]', is_red=True) if args.brief else \
        csp_print_warnings(csp_deprecated, '[icsi_d]', '[icsi_d_s]',
                           '[icsi_d_r]')


def csp_print_insecure(csp_insecure):
    print_detail_r('[icsh_h]', is_red=True) if args.brief else \
        csp_print_warnings(csp_insecure, '[icsh_h]', '[icsh]', '[icsh_b]')
    if not args.brief:
        print("")


def csp_print_broad(csp_broad):
    print_detail_r('[icsw_h]', is_red=True) if args.brief else \
        csp_print_warnings(csp_broad, '[icsw_h]', '[icsw]', '[icsw_b]')


def csp_print_warnings(csp_values, csp_title, csp_desc, csp_refs):
    csp_values = ', '.join(f"'{value}'" for value in csp_values)
    print_detail_r(f'{csp_title}', is_red=True)
    print_detail_l(f'{csp_desc}')
    print(csp_values)
    print_detail(f'{csp_refs}')


def delete_lines(reliable=True):
    if not reliable:
        sys.stdout.write(DELETED_LINES)
    sys.stdout.write(DELETED_LINES)


def print_export_path(filename, reliable):
    delete_lines(reliable=False) if reliable else delete_lines()
    print("")
    print_detail_l('[report]')
    print(path.abspath(filename))


def print_nowarnings():
    print_detail('[no_warnings]')


def print_header(header):
    print(f" {header}" if args.output else f"{STYLE[1]} {header}")


def print_fng_header(header):
    if args.output:
        print(f" {header}")
    elif '[' in header:
        prefix, _, suffix = header.partition(' [')
        print(f"{STYLE[1]} {prefix}{STYLE[3]}{STYLE[5]} [{suffix}")
    else:
        print(f"{STYLE[1]} {header}")


def print_general_info(reliable, export_filename):
    if not args.output:
        delete_lines(reliable=False) if reliable else delete_lines()
        print(f"\n{BANNER}\n ({URL_LIST[4]} | v.{local_version})")
    elif args.output != 'pdf':
        print(f"\n\n{HUMBLE_DESC}\n{URL_LIST[4]} | v.{local_version}\n")
    print_basic_info(export_filename)
    print_extended_info(args, reliable, status_code)


def print_basic_info(export_filename):
    print(linesep.join(['']*2) if args.output == 'html' or not args.output
          else "")
    print_detail_r('[0section]')
    print_detail_l('[analysis_date]')
    print(f" {current_time}")
    print(f'{URL_STRING[1]}{URL}')
    if export_filename:
        print_detail_l('[export_filename]')
        print(f"'{export_filename}'")


def print_extended_info(args, reliable, status_code):
    if args.output in ('csv', 'json'):
        print(get_detail('[limited_analysis_note]', replace=True))
    if (status_code is not None and 400 <= status_code <= 451) or reliable or \
       args.redirects or args.skip_headers:
        print_extra_info(reliable)


def print_extra_info(reliable):
    if (status_code is not None and 400 <= status_code <= 451):
        id_mode = f"[http_{status_code}]"
        if detail := print_detail(id_mode, 0):
            print(detail)
        print(f"{URL_LIST[2]}{status_code}")
    if reliable:
        print(get_detail('[unreliable_analysis_note]', replace=True))
    if args.redirects:
        print(get_detail('[analysis_redirects_note]', replace=True))
    if args.skip_headers:
        print_skipped_headers(args)


def print_response_headers():
    print(linesep.join(['']*2))
    print_detail_r('[0headers]')
    pdf_style = STYLE[6] if args.output == 'pdf' else ""
    for key, value in sorted(headers.items()):
        print(f" {pdf_style}{key}:", value) if args.output else \
            print(f" {STYLE[2]}{key}:", value)
    print('\n')


def print_details(short_d, long_d, id_mode, i_cnt):
    print_detail_r(short_d, is_red=True)
    if not args.brief:
        print_detail(long_d, 2) if id_mode == 'd' else print_detail(long_d, 3)
    i_cnt[0] += 1
    return i_cnt


def print_detail(id_mode, num_lines=1):
    idx = l10n_content.index(id_mode + '\n')
    print(l10n_content[idx+1], end='')
    for i in range(1, num_lines+1):
        if idx+i+1 < len(l10n_content):
            print(l10n_content[idx+i+1], end='')


def print_detail_l(id_mode, analytics=False):
    for i, line in enumerate(l10n_content):
        if line.startswith(id_mode):
            if not analytics:
                print(l10n_content[i+1].replace('\n', ''), end='')
            else:
                return l10n_content[i+1].replace('\n', '').replace(':', '')[1:]


def print_detail_r(id_mode, is_red=False):
    style_str = STYLE[1] if is_red else STYLE[0]
    for i, line in enumerate(l10n_content):
        if line.startswith(id_mode):
            if not args.output:
                print(f"{style_str}{l10n_content[i+1]}", end='')
            else:
                print(l10n_content[i+1], end='')
            if not is_red:
                print("")


def get_detail(id_mode, replace=False):
    for i, line in enumerate(l10n_content):
        if line.startswith(id_mode):
            return (l10n_content[i+1].replace('\n', '')) if replace else \
                l10n_content[i+1]


def print_error_detail(id_mode):
    print(f"\n{get_detail(id_mode, replace=True)}")
    sys.exit()


def get_epilog_content(id_mode):
    epilog_file_path = path.join(HUMBLE_DIRS[1], HUMBLE_FILES[5])
    with open(epilog_file_path, 'r', encoding='utf8') as epilog_source:
        epilog_lines = epilog_source.readlines()
        epilog_idx = epilog_lines.index(id_mode + '\n')
    return ''.join(epilog_lines[epilog_idx+1:epilog_idx+12])


def get_fingerprint_headers():
    with open(path.join(HUMBLE_DIRS[0], HUMBLE_FILES[2]), 'r',
              encoding='utf8') as fng_source:
        l_fng_ex = [line.strip() for line in
                    islice(fng_source, SLICE_INT[0], None) if line.strip()]
        l_fng = [line.split(' [')[0].strip() for line in l_fng_ex]
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
        if not headers[header]:
            print(get_detail('[empty_fng]', replace=True))
        else:
            print(f" {get_detail('[fng_value]', replace=True)} \
'{headers[header]}'")
        print("")
    else:
        print_header(header)


def print_missing_headers(args, headers_l, l_detail, l_miss):
    m_cnt = 0
    headers_set = set(headers_l)
    l_miss_set = {header.lower() for header in l_miss}
    skip_headers = args.skip_headers if args.skip_headers is not None else []
    skip_missing = {header.lower() for header in skip_headers if
                    header.lower() in l_miss_set}
    m_cnt, skip_missing = check_missing_headers(m_cnt, l_miss, l_detail,
                                                headers_set, skip_missing)
    return m_cnt, skip_missing


def check_missing_headers(m_cnt, l_miss, l_detail, headers_set, skip_missing):
    for header, detail in zip(l_miss, l_detail):
        if header.lower() not in headers_set and header.lower() not in \
         skip_missing and 'x-frame-options' not in skip_missing:
            print_header(header)
            if not args.brief:
                print_detail(detail, 2)
            m_cnt += 1
    return m_cnt, skip_missing


def check_frame_options(args, headers_l, l_miss, m_cnt, skip_missing):
    skip_headers = {header.lower() for header in (args.skip_headers or [])}
    if 'x-frame-options' in skip_headers:
        skip_missing.add('x-frame-options')
    xfo_missing = 'x-frame-options' not in skip_missing
    xfo_not_set = 'x-frame-options' not in headers_l
    fra_missing = 'frame-ancestors' not in headers_l.get(
        'content-security-policy', '')
    all_missing = all(header.lower() not in headers_l for header in l_miss)
    if xfo_missing and ((xfo_not_set and fra_missing) or all_missing):
        print_header('X-Frame-Options')
        if not args.brief:
            print_detail("[mxfo]", 2)
        m_cnt += 1
    l_miss.append('X-Frame-Options')
    return m_cnt


def print_empty_headers(headers, l_empty):
    e_cnt = 0
    for key in sorted(headers):
        if not headers[key]:
            l_empty.append(f"{key}")
            print_header(key)
            e_cnt += 1
    return e_cnt


def print_browser_compatibility(compat_headers):
    style_blanks = "  " if args.output == 'html' else " "
    for key in compat_headers:
        styled_header = key if args.output else f"{STYLE[2]}{key}{STYLE[5]}"
        csp_key = 'contentsecuritypolicy2' if key == 'Content-Security-Policy'\
            else key
        print(f"{style_blanks}{styled_header}{URL_LIST[0]}{csp_key}")


def check_path_traversal(path):
    path_traversal_ptrn = re.compile(RE_PATTERN[2])
    if path_traversal_ptrn.search(path):
        print(f"\n{get_detail('[args_path_traversal]', replace=True)} \
('{path}')")
        sys.exit()


def check_path_permissions(output_path):
    try:
        open(path.join(output_path, HUMBLE_FILES[1]), 'w')
    except PermissionError:
        print(f"\n{get_detail('[args_nowr]', replace=True)}'{output_path}'")
        sys.exit()
    else:
        remove(path.join(output_path, HUMBLE_FILES[1]))


def check_output_path(args, output_path):
    check_path_traversal(args.output_path)
    if args.output is None:
        print_error_detail('[args_nooutputfmt]')
    elif path.exists(output_path):
        check_path_permissions(output_path)
    else:
        print(f"\n{get_detail('[args_noexportpath]', replace=True)}\
('{output_path}').")
        sys.exit()


def parse_user_agent(user_agent=False):
    if not user_agent:
        return {'User-Agent': get_user_agent('1')}
    user_agent_id = sys.argv[sys.argv.index('-ua') + 1].lstrip('-ua')
    if not args.URL:
        nourl_user_agent(user_agent_id)
    if args.URL:
        return {'User-Agent': get_user_agent(user_agent_id)}


def nourl_user_agent(user_agent_id):
    try:
        if int(user_agent_id) == 0:
            return {'User-Agent': get_user_agent('0')}
        print_error_detail('[args_useragent]')
    except ValueError:
        print_error_detail('[ua_invalid]')


def get_user_agent(user_agent_id):
    with open(path.join(HUMBLE_DIRS[0], HUMBLE_FILES[6]), 'r',
              encoding='utf8') as ua_source:
        user_agents = [line.strip() for line in islice(ua_source, SLICE_INT[1],
                                                       None)]
    if user_agent_id == str(0):
        print_user_agents(user_agents)
    for line in user_agents:
        if line.startswith(f"{user_agent_id}.-"):
            return line[4:]
    print_error_detail('[ua_invalid]')
    sys.exit()


def print_user_agents(user_agents):
    print(f"\n{STYLE[0]}{get_detail('[ua_available]', replace=True)}\
{STYLE[4]}{get_detail('[ua_source]', replace=True)}\n")
    for line in user_agents:
        print(f' {line}')
    sys.exit()


def get_insecure_checks():
    headers_name = set()
    with open(path.join(HUMBLE_DIRS[0], HUMBLE_FILES[7]), "r") as ins_source:
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


def print_skipped_headers(args):
    print_detail_l("[analysis_skipped_note]")
    print(" " + ", ".join(f"'{header}'" for header in args.skip_headers))


def print_unsupported_headers(unsupported_headers):
    print("")
    print_detail_l("[args_skipped_unknown]")
    print(", ".join(f"'{header}'" for header in unsupported_headers))
    sys.exit()


def generate_csv(temp_filename, final_filename):
    with open(temp_filename, 'r', encoding='utf8') as txt_source, \
         open(final_filename, 'w', newline='', encoding='utf8') as csv_final:
        csv_source = txt_source.read()
        csv_writer = writer(csv_final, quoting=QUOTE_ALL)
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
        txt_sections = re.split(RE_PATTERN[5], txt_content)[1:]
        data = {}
        parse_json_sections(txt_sections, data, section0, sectionh, section5)
        json_data = dumps(data, indent=4, ensure_ascii=False)
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


def generate_pdf(pdf, pdf_links, pdf_prefixes, temp_filename):
    set_pdf_structure()
    set_pdf_content(pdf, pdf_links, pdf_prefixes, temp_filename)
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
    git_urlc = f"{URL_LIST[4]} | v.{local_version}"
    pdf.set_author(git_urlc)
    pdf.set_creation_date = current_time
    pdf.set_creator(git_urlc)
    pdf.set_keywords(get_detail('[pdf_meta_keywords]', replace=True))
    pdf.set_lang(get_detail('[pdf_meta_language]'))
    pdf.set_subject(get_detail('[pdf_meta_subject]', replace=True))
    pdf.set_title(title)
    pdf.set_producer(git_urlc)


def set_pdf_content(pdf, pdf_links, pdf_prefixes, temp_filename):
    with open(temp_filename, "r", encoding='utf8') as txt_source:
        for line in txt_source:
            if '[' in line:
                set_pdf_sections(line)
            if any(bold_str in line for bold_str in BOLD_STRING):
                pdf.set_font(style='B')
            else:
                pdf.set_font(style='')
            for string in pdf_links:
                if string in line:
                    set_pdf_links(line, pdf_prefixes, string)
            set_pdf_color(pdf, line)


def set_pdf_color(pdf, line):
    if re.search(RE_PATTERN[7], line):
        line = f" {line[19:]}"
        pdf.set_text_color(102, 0, 51)
    else:
        pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(197, 6, text=line, align='L', new_y=YPos.LAST)


def set_pdf_sections(i):
    section_dict = {'[0.': '[0section_s]', '[HTTP R': '[0headers_s]',
                    '[1.': '[1missing_s]', '[2.': '[2fingerprint_s]',
                    '[3.': '[3depinsecure_s]', '[4.': '[4empty_s]',
                    '[5.': '[5compat_s]', '[Cabeceras': '[0headers_s]'}
    if match := next((x for x in section_dict if i.startswith(x)), None):
        pdf.start_section(get_detail(section_dict[match]))


def set_pdf_links(i, pdf_prefixes, pdfstring):
    links_d = {URL_STRING[1]: URL,
               REF_LINKS[2]: i.partition(REF_LINKS[2])[2].strip(),
               REF_LINKS[3]: i.partition(REF_LINKS[3])[2].strip(),
               URL_LIST[0]: i.partition(': ')[2].strip()}
    link_final = links_d.get(pdfstring)
    if pdfstring in (URL_STRING[1], REF_LINKS[2], REF_LINKS[3]):
        prefix = pdf_prefixes.get(pdfstring, pdfstring)
        pdf.write(h=6, text=prefix)
    else:
        pdf.write(h=6, text=i[:i.index(": ")+2])
    pdf.set_text_color(0, 0, 255)
    pdf.cell(w=2000, h=6, text=i[i.index(": ")+2:], align="L", link=link_final)


def generate_html():
    copyfile(path.join(HUMBLE_DIRS[0], HUMBLE_FILES[8]), final_filename)
    html_replace = {"html_title": get_detail('[pdf_meta_subject]'),
                    "html_desc": get_detail('[pdf_meta_title]'),
                    "html_keywords": get_detail('[pdf_meta_keywords]'),
                    "humble_URL": URL_LIST[4],
                    "humble_local_v": local_version, "URL_analyzed": URL,
                    "html_body": '<body><pre>', "}}": '}', "{{": '}'}
    with open(final_filename, "r+", encoding='utf8') as html_file:
        temp_html_content = html_file.read()
        replaced_html = temp_html_content.format(**html_replace)
        html_file.seek(0)
        html_file.write(replaced_html)


def format_html_info(condition, ln, sub_d):
    if condition == URL_STRING[0]:
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
{sub_d['ahref_s']}{ln[ln.index(HTTP_SCHEMES[1]):]}{sub_d['close_t']}\
{ln[ln.index(HTTP_SCHEMES[1]):]}{sub_d['ahref_f']}<br>"
    html_final.write(ln)


def format_html_bold(ln):
    html_final.write(f'<strong>{ln}</strong><br>')


def print_http_exception(id_exception, exception_v):
    delete_lines()
    print("")
    print_detail(id_exception)
    raise SystemExit from exception_v


def print_ru_message():
    with contextlib.suppress(requests.exceptions.RequestException):
        requests.packages.urllib3.disable_warnings()
        sffx = tldextract.extract(URL).suffix[-2:].upper()
        cnty = requests.get(RU_CHECKS[0], verify=False, timeout=5).text.strip()
        if (sffx == RU_CHECKS[1] and sffx not in NON_RU_TLD) or cnty == \
                RU_CHECKS[2]:
            print_detail('[ru_analysis_message]', 3)
            sys.exit()


def get_temp_filename(args, export_date):
    file_ext = ".txt" if args.output == 'txt' else "t.txt"
    parsed_url = urlparse(args.URL)
    temp_filename = build_temp_filename(args, export_date, file_ext,
                                        parsed_url)
    if args.output_path:
        temp_filename = path.join(output_path, temp_filename)
    return temp_filename


def build_temp_filename(args, export_date, file_ext, parsed_url):
    str_hum = f"{HUMBLE_DESC[1:7]}_"
    url_str = tldextract.extract(args.URL)
    url_sub = f"_{url_str.subdomain}." if url_str.subdomain else '_'
    url_prt = f"_{parsed_url.port}_" if parsed_url.port is not None else '_'
    return f"{str_hum}{parsed_url.scheme}{url_sub}{url_str.domain}_\
{url_str.suffix}{url_prt}{export_date}{file_ext}"


def handle_server_error(http_status_code, l10n_id):
    delete_lines()
    print()
    if (500 <= http_status_code <= 511) or (520 <= http_status_code <= 530):
        if detail := print_detail(l10n_id, 0):
            print(detail)
        else:
            print((URL_LIST[2] if (500 <= http_status_code <= 511) else
                   URL_LIST[1]) + str(http_status_code))
    else:
        print_error_detail('[server_serror]')
    sys.exit()


def make_http_request():
    try:
        session = requests.Session()
        session.mount("https://", SSLContextAdapter())
        session.mount("http://", HTTPAdapter())
        # If '-df' parameter is provided ('args.redirects') the exact URL will
        # be analyzed; otherwise the last redirected URL will be analyzed.
        #
        # Yes, certificates must always be checked/verified by default on
        # HTTPS connections. However, and within the scope of 'humble', I have
        # chosen to disable these checks so that in certain cases (e.g.
        # development environments, hosts with very old servers/software,
        # self-signed certificates, etc) the URL can still be analyzed.
        r = session.get(quote(URL), allow_redirects=not args.redirects,
                        verify=False, headers=ua_header, timeout=15)
        return r, None, None
    except requests.exceptions.SSLError:
        pass
    except requests.exceptions.RequestException as e:
        return None, None, e


def wait_http_request(future):
    with contextlib.suppress(concurrent.futures.TimeoutError):
        future.result(timeout=5)


def handle_http_exception(r, exception_d):
    if r is None:
        return
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError as err_http:
        http_status_code = err_http.response.status_code
        l10n_id = f"[server_{http_status_code}]"
        if str(http_status_code).startswith('5'):
            handle_server_error(http_status_code, l10n_id)
    except tuple(exception_d.keys()) as e:
        ex = exception_d.get(type(e))
        if ex and (not callable(ex) or ex(e)):
            print_http_exception(ex, e)


def manage_http_request():
    headers = {}
    status_c = None
    reliable = None
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(make_http_request)
            wait_http_request(future)
            if not future.done():
                print(get_detail('[unreliable_analysis]'))
                reliable = 'No'
            r, _, exception = future.result()
            if exception:
                exception_type = type(exception)
                if exception_type in exception_d:
                    error_string = exception_d[exception_type]
                    print_http_exception(error_string, exception)
                else:
                    print(f"Unhandled exception type: {exception_type}")
                return headers, status_c, reliable
            handle_http_exception(r, exception_d)
            if r is not None:
                status_c = r.status_code
                headers = r.headers
    except SystemExit:
        sys.exit()
    return headers, status_c, reliable


def custom_help_formatter(prog):
    return RawDescriptionHelpFormatter(prog, max_help_position=30)


# Main functionality for argparse
init(autoreset=True)
epilog_content = get_epilog_content('[epilog_content]')

parser = ArgumentParser(formatter_class=custom_help_formatter,
                        description=f"{HUMBLE_DESC} | {URL_LIST[4]} | \
v.{local_version}", epilog=epilog_content)

parser.add_argument("-a", dest='URL_A', action="store_true", help="Shows \
statistics of the performed analysis; will be global if the '-u' parameter is \
omitted")
parser.add_argument("-b", dest='brief', action="store_true", help="Shows \
overall findings; if this parameter is omitted detailed ones will be shown")
parser.add_argument("-df", dest='redirects', action="store_true", help="Do not\
 follow redirects; if this parameter is omitted the last redirection will be \
the one analyzed")
parser.add_argument("-e", nargs='?', type=str, dest='testssl_path', help="Show\
s TLS/SSL checks; requires the PATH of https://testssl.sh/")
parser.add_argument("-f", nargs='?', type=str, dest='fingerprint_term', help="\
Shows fingerprint statistics; will be the Top 20 if \'FINGERPRINT_TERM\', e.g.\
 \'Google\', is omitted")
parser.add_argument("-g", dest='guides', action="store_true", help="Shows \
guidelines for enabling security HTTP response headers on popular servers/\
services")
parser.add_argument("-grd", dest='grades', action="store_true", help="Shows \
the checks to grade an analysis, along with advice for improvement")
parser.add_argument("-l", dest='lang', choices=['es'], help="Defines the \
language for displaying analysis, errors and messages; will be English if this\
 parameter is omitted")
parser.add_argument("-lic", dest='license', action="store_true", help="Shows \
the license for 'humble', along with permissions, limitations and conditions.")
parser.add_argument("-o", dest='output', choices=['csv', 'html', 'json', 'pdf',
                                                  'txt'], help="Exports \
analysis to 'humble_scheme_URL_port_yyyymmdd_hhmmss.ext' file; csv/json will \
have a brief analysis")
parser.add_argument("-op", dest='output_path', type=str, help="Exports \
analysis to 'OUTPUT_PATH'; if this parameter is omitted the PATH of 'humble.py\
' will be used")
parser.add_argument("-r", dest='ret', action="store_true", help="Shows HTTP \
response headers and a detailed analysis; '-b' parameter will take priority")
parser.add_argument("-s", dest='skip_headers', nargs='*', type=str, help="S\
kips 'deprecated/insecure' and 'missing' checks for the indicated \
'SKIP_HEADERS' (separated by spaces)")
parser.add_argument('-u', type=str, dest='URL', help="Scheme, host and port to\
 analyze. E.g. https://google.com")
parser.add_argument('-ua', type=str, dest='user_agent', help="User-Agent ID \
from 'additional/user_agents.txt' to use. '0' will show all and '1' is the \
default")
parser.add_argument("-v", "--version", action="store_true", help="Checks for \
updates at https://github.com/rfc-st/humble")

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

# Multilingual messages and Python version checking
l10n_content = get_l10n_content()
check_python_version()

# Functionality for argparse parameters/values
check_humble_updates(local_version) if args.version else None

if '-grd' in sys.argv:
    print_grades_guide(args)

if '-lic' in sys.argv:
    print_license(args)

if '-f' in sys.argv:
    fng_statistics_term(args.fingerprint_term) if args.fingerprint_term else \
        fng_statistics_top()

if '-ua' in sys.argv:
    ua_header = parse_user_agent(user_agent=True)
elif args.URL:
    ua_header = parse_user_agent(user_agent=False)

if '-e' in sys.argv:
    if system().lower() == 'windows':
        print_detail('[windows_ssltls]', 28)
        sys.exit()
    if (args.testssl_path is None or args.URL is None):
        print_error_detail('[args_notestssl]')

if args.lang and not (args.URL or args.URL_A) and not args.guides:
    print_error_detail('[args_lang]')

if args.output_path is not None:
    output_path = path.abspath(args.output_path)
    check_output_path(args, output_path)

if any([args.brief, args.output, args.ret, args.redirects,
        args.skip_headers]) and (args.URL is None or args.guides is None or
                                 args.URL_A is None):
    print_error_detail('[args_several]')

if args.output in ['csv', 'json'] and not args.brief:
    print_error_detail('[args_csv_json]')

skip_list, unsupported_headers = [], []

if '-s' in sys.argv and len(args.skip_headers) == 0:
    print_error_detail('[args_skipped]')
elif args.skip_headers:
    insecure_headers = get_insecure_checks()
    unsupported_headers, skip_list = \
        get_skipped_unsupported_headers(args, insecure_headers)
    print_unsupported_headers(unsupported_headers) if unsupported_headers else\
        None

URL = args.URL

if args.guides or args.testssl_path or args.URL_A:
    if args.guides:
        print_security_guides()
    elif args.testssl_path:
        testssl_command(path.abspath(args.testssl_path), args.URL)
    elif args.URL_A:
        analysis_exists(HUMBLE_FILES[0])
        url_analytics() if args.URL else url_analytics(is_global=True)

start = time()
print_ru_message()

if not args.URL_A:
    detail = '[analysis_output]' if args.output else '[analysis]'
    print("")
    print_detail(detail)

# Retrieving HTTP response headers
exception_d = {
    requests.exceptions.ConnectionError: '[e_404]',
    requests.exceptions.InvalidSchema: '[e_schema]',
    requests.exceptions.InvalidURL: '[e_invalid]',
    requests.exceptions.MissingSchema: '[e_schema]',
    requests.exceptions.SSLError: None,
    requests.exceptions.Timeout: '[e_timeout]',
}
requests.packages.urllib3.disable_warnings()

headers, status_code, reliable = manage_http_request()
headers_l = {header.lower(): value for header, value in headers.items()}

# Export filename generation
export_filename = None

if args.output:
    orig_stdout = sys.stdout
    export_date = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_filename = get_temp_filename(args, export_date)
    temp_filename_content = open(temp_filename, 'w', encoding='utf8')
    sys.stdout = temp_filename_content
    export_slice = SLICE_INT[4] if args.output == 'txt' else SLICE_INT[5]
    export_filename = f"{temp_filename[:export_slice]}.{args.output}"

# Section '0. Info & HTTP Response Headers'
print_general_info(reliable, export_filename)
print_response_headers() if args.ret else print(linesep.join([''] * 2))

# Section '1. Missing HTTP Security Headers'
# Checks: /additional/missing.txt
print_detail_r('[1missing]')

l_miss = ['Cache-Control', 'Clear-Site-Data', 'Content-Type',
          'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy',
          'Cross-Origin-Resource-Policy', 'Content-Security-Policy', 'NEL',
          'Permissions-Policy', 'Referrer-Policy', 'Strict-Transport-Security',
          'X-Content-Type-Options', 'X-Permitted-Cross-Domain-Policies']

l_detail = ['[mcache]', '[mcsd]', '[mctype]', '[mcoe]', '[mcop]', '[mcor]',
            '[mcsp]', '[mnel]', '[mpermission]', '[mreferrer]', '[msts]',
            '[mxcto]', '[mxpcd]', '[mxfo]']

m_cnt, skip_missing = print_missing_headers(args, headers_l, l_detail, l_miss)
m_cnt = check_frame_options(args, headers_l, l_miss, m_cnt, skip_missing)

if args.brief and m_cnt != 0:
    print("")
if m_cnt == 0:
    print_nowarnings()
print("")

# Section '2. Fingerprint HTTP Response Headers'
# Checks: /additional/fingerprint.txt
print_detail_r('[2fingerprint]')

if not args.brief:
    print_detail("[afgp]")

l_fng_ex, l_fng, titled_fng = get_fingerprint_headers()
f_cnt = print_fingerprint_headers(headers_l, l_fng_ex, titled_fng)

if args.brief and f_cnt != 0:
    print("")
if f_cnt == 0:
    print_nowarnings()
print("")

# Section '3. Deprecated HTTP Response Headers/Protocols and Insecure Values'
# Checks: /additional/insecure.txt
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
         'Public-Key-Pins-Report-Only', 'Reporting-Endpoints', 'Repr-Digest',
         'Set-Cookie', 'Server-Timing', 'SourceMap', 'Speculation-Rules',
         'Strict-Dynamic', 'Supports-Loading-Mode', 'Surrogate-Control',
         'Timing-Allow-Origin', 'Tk', 'Trailer', 'Transfer-Encoding', 'Vary',
         'WWW-Authenticate', 'Want-Digest', 'Warning',
         'X-Content-Security-Policy', 'X-Content-Security-Policy-Report-Only',
         'X-DNS-Prefetch-Control', 'X-Download-Options', 'X-Pad',
         'X-Permitted-Cross-Domain-Policies', 'X-Pingback', 'X-Robots-Tag',
         'X-Runtime', 'X-SourceMap', 'X-UA-Compatible', 'X-Webkit-CSP',
         'X-Webkit-CSP-Report-Only', 'X-XSS-Protection']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-CH
t_acceptch_dep = ('content-dpr', 'dpr', 'sec-ch-ua-full-version',
                  'viewport-width', 'width')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
t_cache = ('no-cache', 'no-store', 'must-revalidate')
t_cachev = ('immutable', 'max-age', 'must-revalidate', 'must-understand',
            'no-cache', 'no-store', 'no-transform', 'private',
            'proxy-revalidate', 'public', 's-maxage', 'stale-if-error',
            'stale-while-revalidate')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data
t_csdata = ('cache', 'clientHints', 'cookies', 'storage', 'executionContexts',
            '*')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
t_cencoding = ('br', 'compress', 'deflate', 'gzip', 'x-gzip', 'zstd')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
# https://www.w3.org/TR/CSP2/ & https://www.w3.org/TR/CSP3/
t_csp_broad = ('*',  'blob:', 'data:', 'ftp:', 'filesystem:', 'https:',
               'https://*', 'https://*.*', 'schemes:', 'wss:', 'wss://')
t_csp_equal = ('nonce', 'sha', 'style-src-elem', 'report-to', 'report-uri')
t_csp_dep = ('block-all-mixed-content', 'disown-opener', 'plugin-types',
             'prefetch-src', 'referrer', 'report-uri', 'require-sri-for')
t_csp_dirs = ('base-uri', 'child-src', 'connect-src', 'default-src',
              'fenced-frame-src', 'font-src', 'form-action', 'frame-ancestors',
              'frame-src', 'img-src', 'manifest-src', 'media-src',
              'navigate-to', 'object-src', 'report-to',
              'require-trusted-types-for', 'sandbox', 'script-src',
              'script-src-attr', 'script-src-elem', 'style-src',
              'style-src-attr', 'style-src-elem', 'trusted-types',
              'upgrade-insecure-requests', 'webrtc', 'worker-src')
t_csp_insecs = ('http:', 'ws:')
t_csp_insecv = ('unsafe-eval', 'unsafe-inline')
t_csp_checks = ('upgrade-insecure-requests', 'strict-transport-security',
                'unsafe-hashes', 'nonce-', '127.0.0.1')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
l_csp_ro_dep = ['violated-directive']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type
# https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
t_ct_mime = ('application/xhtml+xml', 'text/html')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy
t_coep = ('credentialless', 'require-corp', 'unsafe-none')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy
t_coop = ('same-origin', 'same-origin-allow-popups', 'unsafe-none')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy
t_corp = ('cross-origin', 'same-origin', 'same-site')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires
t_excc = ('max-age', 's-maxage')

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

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
# https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md
t_per_dep = ('document-domain', 'window-placement')
t_per_ft = ('accelerometer', 'all-screens-capture', 'ambient-light-sensor',
            'attribution-reporting', 'autoplay', 'battery', 'bluetooth',
            'browsing-topics', 'camera', 'captured-surface-control', 'ch-ua',
            'ch-ua-arch', 'ch-ua-bitness', 'ch-ua-full-version',
            'ch-ua-full-version-list', 'ch-ua-mobile', 'ch-ua-model',
            'ch-ua-platform', 'ch-ua-platform-version', 'ch-ua-wow64',
            'clipboard-read', 'clipboard-write', 'compute-pressure',
            'conversion-measurement', 'cross-origin-isolated',
            'digital-credentials-get', 'direct-sockets', 'display-capture',
            'encrypted-media', 'execution-while-not-rendered',
            'execution-while-out-of-viewport',
            'focus-without-user-activation', 'fullscreen', 'gamepad',
            'geolocation', 'gyroscope', 'hid', 'identity-credentials-get',
            'idle-detection', 'interest-cohort', 'join-ad-interest-group',
            'keyboard-map', 'layout-animations', 'local-fonts',
            'magnetometer', 'microphone', 'midi', 'navigation-override',
            'otp-credentials', 'payment', 'picture-in-picture',
            'publickey-credentials-create', 'publickey-credentials-get',
            'run-ad-auction', 'screen-wake-lock', 'serial',
            'shared-autofill', 'smart-card', 'speaker-selection',
            'storage-access', 'sync-script', 'sync-xhr',
            'trust-token-redemption', 'unload', 'usb', 'vertical-scroll',
            'web-share', 'window-management', 'xr-spatial-tracking')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authenticate
# https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
t_proxy_auth = ('AWS4-HMAC-SHA256', 'Basic', 'Bearer', 'Digest', 'DPoP',
                'GNAP', 'HOBA', 'Mutual', 'Negotiate', 'OAuth',
                'PrivateToken', 'SCRAM-SHA-1', 'SCRAM-SHA-256', 'vapid')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
t_ref_secure = ('strict-origin', 'strict-origin-when-cross-origin',
                'no-referrer-when-downgrade', 'no-referrer')
t_ref_values = ('no-referrer', 'no-referrer-when-downgrade', 'origin',
                'origin-when-cross-origin', 'same-origin', 'strict-origin',
                'strict-origin-when-cross-origin', 'unsafe-url')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
t_cookie_prf = ('__Host-', '__Secure-')
t_cookie_sec = ('httponly', 'secure')

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Repr-Digest
t_repdig_sec = ('sha-256', 'sha-512')
t_repdig_ins = ('adler', 'crc32c', 'md5', 'sha-1', 'unixsum', 'unixcksum')

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
            match_value_str = ', '.join(match_value)
            print_detail_l("[ixachd_s]")
            print(match_value_str)
            print_detail('[ixachd]')
        i_cnt[0] += 1

if 'accept-ch-lifetime' in headers_l and '2' not in skip_list:
    print_details('[ixacl_h]', '[ixacld]', 'd', i_cnt)

accescred_header = headers_l.get("access-control-allow-credentials", '')
if accescred_header and accescred_header != 'true' and '3' not in skip_list:
    print_details('[icred_h]', '[icred]', 'd', i_cnt)

if 'access-control-allow-methods' in headers_l and '4' not in skip_list:
    methods = headers_l["access-control-allow-methods"]
    if any(method in methods for method in t_methods):
        print_detail_r('[imethods_h]', is_red=True)
        if not args.brief:
            match_method = [x for x in t_methods if x in methods]
            match_method_str = ', '.join(match_method)
            print_detail_l("[imethods_s]")
            print(match_method_str)
            print_detail("[imethods]")
        i_cnt[0] += 1

accesso_header = headers_l.get("access-control-allow-origin", '')
if accesso_header and ((accesso_header in ['*', 'null']) and
                       (not any(val in accesso_header for
                                val in ['.*', '*.']))) and '5' not in \
                                    skip_list:
    print_details('[iaccess_h]', '[iaccess]', 'd', i_cnt)

accesma_header = headers_l.get("access-control-max-age", '')
if accesma_header and int(accesma_header) > 86400 and '6' not in skip_list:
    print_details('[iacessma_h]', '[iaccessma]', 'd', i_cnt)

if 'allow' in headers_l and '7' not in skip_list:
    methods = headers_l["allow"]
    if any(method in methods for method in t_methods):
        print_detail_r('[imethods_hh]', is_red=True)
        if not args.brief:
            match_method = [x for x in t_methods if x in methods]
            match_method_str = ', '.join(match_method)
            print_detail_l("[imethods_s]")
            print(match_method_str)
            print_detail("[imethods]")
        i_cnt[0] += 1

cache_header = headers_l.get("cache-control", '')
if cache_header and '8' not in skip_list:
    if not any(elem in cache_header for elem in t_cachev):
        print_details('[icachev_h]', '[icachev]', 'd', i_cnt)
    if not all(elem in cache_header for elem in t_cache):
        print_details('[icache_h]', '[icache]', 'd', i_cnt)

if 'clear-site-data' in headers_l and '9' not in skip_list:
    clsdata_header = headers_l['clear-site-data']
    if unsafe_scheme:
        print_details('[icsd_h]', '[icsd]', 'd', i_cnt)
    if not any(elem in clsdata_header for elem in t_csdata):
        print_details('[icsdn_h]', '[icsdn]', 'd', i_cnt)

if 'content-dpr' in headers_l and '10' not in skip_list:
    print_details('[ixcdpr_h]', '[ixcdprd]', 'd', i_cnt)

cencod_header = headers_l.get("content-enconding", '')
if cencod_header and not any(elem in cencod_header for elem in t_cencoding) \
     and '11' not in skip_list:
    print_details('[icencod_h]', '[icencod]', 'd', i_cnt)

if 'content-security-policy' in headers_l and '12' not in skip_list:
    csp_h = headers_l['content-security-policy']
    if not any(elem in csp_h for elem in t_csp_dirs):
        print_details('[icsi_h]', '[icsi]', 'd', i_cnt)
    if ('=' in csp_h) and not (any(elem in csp_h for elem in t_csp_equal)):
        print_details('[icsn_h]', '[icsn]', 'd', i_cnt)
    csp_store_values(csp_h, t_csp_broad, t_csp_insecs, i_cnt)
    if any(elem in csp_h for elem in t_csp_insecv):
        print_details('[icsp_h]', '[icsp]', 'm', i_cnt)
    if t_csp_checks[0] in csp_h and t_csp_checks[1] not in headers:
        print_details('[icspi_h]', '[icspi]', 'm', i_cnt)
    if t_csp_checks[2] in csp_h:
        print_details('[icsu_h]', '[icsu]', 'd', i_cnt)
    if t_csp_checks[3] in csp_h:
        nonces_csp = re.findall(RE_PATTERN[6], csp_h)
        for nonce_csp in nonces_csp:
            if len(nonce_csp) < 32:
                print_details('[icsnces_h]', '[icsnces]', 'd', i_cnt)
                break
    ip_mtch = re.findall(RE_PATTERN[1], csp_h)
    if ip_mtch != t_csp_checks[4]:
        for match in ip_mtch:
            if re.match(RE_PATTERN[1], match):
                print_details('[icsipa_h]', '[icsipa]', 'm', i_cnt)
                break

csp_ro_header = headers_l.get('content-security-policy-report-only', '')
if csp_ro_header and any(elem in csp_ro_header for elem in l_csp_ro_dep) and \
     '13' not in skip_list:
    print_detail_r('[icsiro_d]', is_red=True)
    if not args.brief:
        matches_csp_ro = [x for x in l_csp_ro_dep if x in csp_ro_header]
        print_detail_l("[icsi_d_s]")
        print(', '.join(matches_csp_ro))
        print_detail("[icsiro_d_r]")
    i_cnt[0] += 1

ctype_header = headers_l.get('content-type', '')
if ctype_header and '14' not in skip_list:
    if any(elem in ctype_header for elem in t_legacy):
        print_details('[ictlg_h]', '[ictlg]', 'm', i_cnt)
    if 'html' not in ctype_header:
        print_details('[ictlhtml_h]', '[ictlhtml]', 'd', i_cnt)
    if any(elem in ctype_header for elem in t_ct_mime) and ('charset' not in
                                                            ctype_header):
        print_details('[ictlchar_h]', '[ictlchar]', 'd', i_cnt)

if 'critical-ch' in headers_l and unsafe_scheme and '15' not in skip_list:
    print_details('[icrch_h]', '[icrch]', 'd', i_cnt)

if 'cross-origin-embedder-policy' in headers_l and '16' not in skip_list:
    coep_h = headers_l['cross-origin-embedder-policy']
    if not any(elem in coep_h for elem in t_coep):
        print_details('[icoep_h]', '[icoep]', 'd', i_cnt)

if 'cross-origin-opener-policy' in headers_l and '17' not in skip_list:
    coop_h = headers_l['cross-origin-opener-policy']
    if not any(elem in coop_h for elem in t_coop):
        print_details('[icoop_h]', '[icoop]', 'd', i_cnt)

if 'cross-origin-resource-policy' in headers_l and '18' not in skip_list:
    corp_h = headers_l['cross-origin-resource-policy']
    if not any(elem in corp_h for elem in t_corp):
        print_details('[icorp_h]', '[icorp]', 'd', i_cnt)

if 'digest' in headers_l and '19' not in skip_list:
    print_details('[idig_h]', '[idig]', 'd', i_cnt)

if 'etag' in headers_l and '20' not in skip_list:
    print_details('[ieta_h]', '[ieta]', 'd', i_cnt)

if 'expect-ct' in headers_l and '21' not in skip_list:
    print_details('[iexct_h]', '[iexct]', 'm', i_cnt)

if 'expires' in headers_l and any(elem in headers_l.get('cache-control', '')
                                  for elem in t_excc) and '22' \
                                    not in skip_list:
    print_details('[iexpi_h]', '[iexpi]', 'd', i_cnt)

if 'feature-policy' in headers_l and '23' not in skip_list:
    print_details('[iffea_h]', '[iffea]', 'd', i_cnt)

if unsafe_scheme:
    print_details('[ihttp_h]', '[ihttp]', 'd', i_cnt)

if ('keep-alive' in headers_l and headers_l['keep-alive'] and
    ('connection' not in headers_l or
     headers_l['connection'] != 'keep-alive')) and '25' not in skip_list:
    print_details('[ickeep_h]', '[ickeep]', 'd', i_cnt)

if 'large-allocation' in headers_l and '26' not in skip_list:
    print_details('[ixlalloc_h]', '[ixallocd]', 'd', i_cnt)

if 'nel' in headers_l and '27' not in skip_list:
    nel_header = headers_l['nel']
    if not any(elem in nel_header for elem in t_nel_dir):
        print_details('[inel_h]', '[inel]', 'd', i_cnt)
    if not all(elem in nel_header for elem in t_nel_req):
        print_details("[inelm_h]", "[inelm]", "d", i_cnt)

if 'no-vary-search' in headers_l and '28' not in skip_list:
    nvarys_header = headers_l['no_vary-search']
    if not any(elem in nvarys_header for elem in t_nvarysearch):
        print_details('[ifnvarys_h]', '[ifnvarys]', 'd', i_cnt)

observe_brows_header = headers_l.get('observe-browsing-topics', '')
if observe_brows_header and '?1' not in observe_brows_header and \
     '29' not in skip_list:
    print_details('[iobsb_h]', '[iobsb]', 'd', i_cnt)

if 'onion-location' in headers_l and '30' not in skip_list:
    print_details('[ionloc_h]', '[ionloc]', 'm', i_cnt)

if 'origin-agent-cluster' in headers_l and '31' not in skip_list:
    origin_cluster_h = headers_l['origin-agent-cluster']
    if not any(elem in origin_cluster_h for elem in l_origcluster):
        print_details('[iorigcluster_h]', '[iorigcluster]', 'd', i_cnt)

if 'p3p' in headers_l and '32' not in skip_list:
    print_details('[ip3p_h]', '[ip3p]', 'd', i_cnt)

if 'permissions-policy' in headers_l and '33' not in skip_list:
    perm_header = headers_l['permissions-policy']
    if not any(elem in perm_header for elem in t_per_ft):
        print_details('[ifpoln_h]', '[ifpoln]', 'm', i_cnt)
    if '*' in perm_header:
        print_details('[ifpol_h]', '[ifpol]', 'd', i_cnt)
    if 'none' in perm_header:
        print_details('[ifpoli_h]', '[ifpoli]', 'd', i_cnt)
    if any(elem in perm_header for elem in t_per_dep):
        print_detail_r('[ifpold_h]', is_red=True)
        if not args.brief:
            matches_perm = [x for x in t_per_dep if x in perm_header]
            print_detail_l("[ifpold_h_s]")
            print(', '.join(f"'{x}'" for x in matches_perm))
            print_detail("[ifpold]")
        i_cnt[0] += 1

if 'pragma' in headers_l and '34' not in skip_list:
    print_details('[iprag_h]', '[iprag]', 'd', i_cnt)

if 'proxy-authenticate' in headers_l and '35' not in skip_list:
    prxyauth_h = headers_l['proxy-authenticate']
    if 'basic' in prxyauth_h and unsafe_scheme:
        print_details('[iprxauth_h]', '[ihbas]', 'd', i_cnt)
    if not any(elem in prxyauth_h for elem in t_proxy_auth):
        print_details('[iprxauthn_h]', '[iprxauthn]', 'd', i_cnt)

if 'public-key-pins' in headers_l and '36' not in skip_list:
    print_details('[ipkp_h]', '[ipkp]', 'd', i_cnt)

if 'public-key-pins-report-only' in headers_l and '37' not in skip_list:
    print_details('[ipkpr_h]', '[ipkp]', 'd', i_cnt)

referrer_header = headers_l.get('referrer-policy', '')
if referrer_header and '38' not in skip_list:
    if not any(elem in referrer_header for elem in t_ref_secure):
        print_details('[iref_h]', '[iref]', 'm', i_cnt)
    if 'unsafe-url' in referrer_header:
        print_details('[irefi_h]', '[irefi]', 'd', i_cnt)
    if not any(elem in referrer_header for elem in t_ref_values):
        print_details('[irefn_h]', '[irefn]', 'd', i_cnt)

report_h = headers_l.get('reporting-endpoints', '')
if report_h and '39' not in skip_list and HTTP_SCHEMES[0] in report_h:
    print_details('[irepe_h]', '[irepe]', 'd', i_cnt)

repdig_header = headers_l.get('repr-digest', '')
if repdig_header and '40' not in skip_list:
    if not any(elem in repdig_header for elem in t_repdig_sec):
        print_details('[irepdig_h]', '[irepdig]', 'd', i_cnt)
    if any(elem in repdig_header for elem in t_repdig_ins):
        print_details('[irepdigi_h]', '[irepdigi]', 'm', i_cnt)

if 'server-timing' in headers_l and '41' not in skip_list:
    print_details('[itim_h]', '[itim]', 'd', i_cnt)

stc_header = headers_l.get("set-cookie", '')
if stc_header and '42' not in skip_list:
    if not unsafe_scheme and not all(elem in stc_header for elem in
                                     t_cookie_sec):
        print_details("[iset_h]", "[iset]", "d", i_cnt)
    if unsafe_scheme:
        if 'secure' in stc_header:
            print_details("[iseti_h]", "[iseti]", "d", i_cnt)
        if any(prefix in stc_header for prefix in t_cookie_prf):
            print_details("[ispref_m]", "[ispref]", "d", i_cnt)
    if "samesite=none" in stc_header and "secure" not in stc_header:
        print_details("[iseti_m]", "[isetm]", "d", i_cnt)

setlogin_header = headers_l.get("set-login", '')
if setlogin_header and not any(elem in setlogin_header for elem in t_setlogin)\
     and '43' not in skip_list:
    print_details('[islogin_h]', '[islogin]', 'd', i_cnt)

if 'sourcemap' in headers_l and '44' not in skip_list:
    print_details('[ismap_m]', '[ismap]', 'd', i_cnt)

if 'speculation-rules' in headers_l and '45' not in skip_list:
    print_details('[ispec_m]', '[ispec]', 'm', i_cnt)

if 'strict-dynamic' in headers_l and '46' not in skip_list:
    print_details('[isdyn_h]', '[isdyn]', 'd', i_cnt)

sts_header = headers_l.get('strict-transport-security', '')
if sts_header and '47' not in skip_list:
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

if 'supports-loading-mode' in headers_l and '48' not in skip_list:
    support_mode_h = headers_l['supports-loading-mode']
    if unsafe_scheme:
        print_details('[islmodei_h]', '[islmodei]', 'd', i_cnt)
    if not any(elem in support_mode_h for elem in t_support_mode):
        print_details('[islmode_h]', '[islmode]', 'd', i_cnt)

if 'surrogate-control' in headers_l and '49' not in skip_list:
    surrogate_mode_h = headers_l['surrogate-control']
    if not any(elem in surrogate_mode_h for elem in t_surrogate):
        print_details('[isurrmode_h]', '[isurrmode]', 'd', i_cnt)

if headers_l.get('timing-allow-origin', '') == '*' and '50' not in skip_list:
    print_details('[itao_h]', '[itao]', 'd', i_cnt)

if 'tk' in headers_l and '51' not in skip_list:
    print_details('[ixtk_h]', '[ixtkd]', 'd', i_cnt)

if 'trailer' in headers_l and '52' not in skip_list:
    trailer_h = headers_l['trailer']
    if any(elem in trailer_h for elem in t_trailer):
        print_detail_r('[itrailer_h]', is_red=True)
        if not args.brief:
            matches_trailer = [x for x in t_trailer if x in trailer_h]
            print_detail_l("[itrailer_d_s]")
            print(', '.join(matches_trailer))
            print_detail("[itrailer_d_r]")
        i_cnt[0] += 1

if 'transfer-encoding' in headers_l and '53' not in skip_list:
    transfer_h = headers_l['transfer-encoding']
    if not any(elem in transfer_h for elem in t_transfer):
        print_details('[ictrf_h]', '[itrf]', 'd', i_cnt)

if 'vary' in headers_l and '54' not in skip_list:
    print_details('[ixvary_h]', '[ixvary]', 'm', i_cnt)

if 'want-digest' in headers_l and '55' not in skip_list:
    print_details('[ixwandig_h]', '[ixwandig]', 'd', i_cnt)

wwwa_header = headers_l.get('www-authenticate', '')
if wwwa_header and unsafe_scheme and ('basic' in wwwa_header) and '57' not in \
     skip_list:
    print_details('[ihbas_h]', '[ihbas]', 'd', i_cnt)

if 'warning' in headers_l and '56' not in skip_list:
    print_details('[ixwar_h]', '[ixward]', 'd', i_cnt)

if 'x-content-security-policy' in headers_l and '58' not in skip_list:
    print_details('[ixcsp_h]', '[ixcsp]', 'd', i_cnt)

if 'x-content-security-policy-report-only' in headers_l and '59' not in \
     skip_list:
    print_details('[ixcspr_h]', '[ixcspr]', 'd', i_cnt)

if 'x-content-type-options' in headers_l and '60' not in skip_list:
    if ',' in headers['X-Content-Type-Options']:
        print_details('[ictpd_h]', '[ictpd]', 'd', i_cnt)
    elif 'nosniff' not in headers['X-Content-Type-Options']:
        print_details('[ictp_h]', '[ictp]', 'd', i_cnt)

if headers_l.get('x-dns-prefetch-control', '') == 'on' and '61' not in \
     skip_list:
    print_details('[ixdp_h]', '[ixdp]', 'd', i_cnt)

if 'x-download-options' in headers_l and '62' not in skip_list:
    print_details('[ixdow_h]', '[ixdow]', 'm', i_cnt)

xfo_header = headers_l.get('x-frame-options', '')
if xfo_header and '63' not in skip_list:
    if ',' in xfo_header:
        print_details('[ixfo_h]', '[ixfo]', 'm', i_cnt)
    if 'allow-from' in xfo_header:
        print_details('[ixfod_h]', '[ixfod]', 'm', i_cnt)
    if xfo_header not in t_xfo_dir:
        print_details('[ixfoi_h]', '[ixfodi]', 'm', i_cnt)

if 'x-pad' in headers_l and '64' not in skip_list:
    print_details('[ixpad_h]', '[ixpad]', 'd', i_cnt)

permcross_header = headers_l.get('x-permitted-cross-domain-policies', '')
if permcross_header and '65' not in skip_list:
    if not any(elem in permcross_header for elem in t_permcross):
        print_details('[ixpermcross_h]', '[ixpermcross]', 'm', i_cnt)
    if 'all' in permcross_header:
        print_details('[ixpermcrossu_h]', '[ixcd]', 'm', i_cnt)
    if ',' in permcross_header:
        print_details('[ixpermcrossd_h]', '[ixpermcrossd]', 'm', i_cnt)

if headers_l.get('x-pingback', '').endswith('xmlrpc.php') and '66' not in \
     skip_list:
    print_details('[ixpb_h]', '[ixpb]', 'd', i_cnt)

robots_header = headers_l.get('x-robots-tag', '')
if robots_header and '67' not in skip_list:
    if not any(elem in robots_header for elem in t_robots):
        print_details('[ixrobv_h]', '[ixrobv]', 'm', i_cnt)
    if 'all' in robots_header:
        print_details('[ixrob_h]', '[ixrob]', 'm', i_cnt)

if 'x-runtime' in headers_l and '68' not in skip_list:
    print_details('[ixrun_h]', '[ixrun]', 'd', i_cnt)

if 'x-sourcemap' in headers_l and '69' not in skip_list:
    print_details('[ixsrc_h]', '[ixsrc]', 'd', i_cnt)

if 'x-ua-compatible' in headers_l and '70' not in skip_list:
    print_details('[ixuacom_h]', '[ixuacom]', 'm', i_cnt)

if 'x-webkit-csp' in headers_l and '71' not in skip_list:
    print_details('[ixwcsp_h]', '[ixcsp]', 'd', i_cnt)

if 'x-webkit-csp-report-only' in headers_l and '72' not in skip_list:
    print_details('[ixwcspr_h]', '[ixcspr]', 'd', i_cnt)

if 'x-xss-protection' in headers_l and '73' not in skip_list:
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

t_sec = ('Access-Control-Allow-Credentials', 'Access-Control-Allow-Methods',
         'Access-Control-Max-Age', 'Cache-Control', 'Clear-Site-Data',
         'Content-Security-Policy', 'Content-Security-Policy-Report-Only',
         'Content-Type', 'Critical-CH', 'Cross-Origin-Embedder-Policy',
         'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy',
         'Document-Policy', 'ETag', 'Feature-Policy', 'NEL',
         'Observe-Browsing-Topics', 'Origin-Agent-Cluster',
         'Permissions-Policy', 'Proxy-Authenticate', 'Referrer-Policy',
         'Server-Timing', 'Set-Cookie', 'Set-Login', 'Speculation-Rules',
         'Strict-Transport-Security', 'Supports-Loading-Mode',
         'Timing-Allow-Origin', 'Trailer', 'Vary', 'WWW-Authenticate',
         'X-Content-Type-Options', 'X-DNS-Prefetch-Control',
         'X-Frame-Options', 'X-XSS-Protection')

compat_headers = sorted(header for header in t_sec if header in headers)

if compat_headers:
    print_browser_compatibility(compat_headers)
else:
    print_detail_l("[no_sec_headers]") if args.output else \
        print_detail_r("[no_sec_headers]", is_red=True)

# Printing analysis summary and the changes with respect to the previous one
print(linesep.join(['']*2))
end = time()
get_analysis_results()

# Exporting analysis results based on file type
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
    # Optimized the loading of the third-party dependency and relevant logic
    # for 'fpdf2', enhancing analysis speed for tasks not involving PDF export
    from fpdf import FPDF, YPos

    class PDF(FPDF):

        def header(self):
            self.set_font('Courier', 'B', 9)
            self.set_y(15)
            self.set_text_color(0, 0, 0)
            self.cell(0, 5, get_detail('[pdf_title]'), new_x="CENTER",
                      new_y="NEXT", align='C')
            self.ln(1)
            self.cell(0, 5, f"{URL_LIST[4]} | v.{local_version}", align='C')
            self.ln(9 if self.page_no() == 1 else 13)

        def footer(self):
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(0, 0, 0)
            self.cell(0, 10, get_detail('[pdf_footer]') + str(self.page_no()) +
                      get_detail('[pdf_footer2]') + ' {nb}', align='C')
    pdf = PDF()
    pdf_links = (URL_STRING[1], REF_LINKS[2], REF_LINKS[3], URL_LIST[0])
    pdf_prefixes = {REF_LINKS[2]: REF_LINKS[0], REF_LINKS[3]: REF_LINKS[1]}
    generate_pdf(pdf, pdf_links, pdf_prefixes, temp_filename)
elif args.output == 'html':
    generate_html()

    l_final = sorted(set(l_miss + l_ins))
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
            if URL_STRING[0] in ln or URL_STRING[1] in ln:
                condition = URL_STRING[0] if URL_STRING[0] in ln else \
                    URL_STRING[1]
                format_html_info(condition, ln_stripped, sub_d)
            elif any(s in ln for s in BOLD_STRING):
                format_html_bold(ln_stripped)
            elif ok_string in ln or ko_string in ln:
                condition = ok_string if ok_string in ln else ko_string
                format_html_okko(condition, ln_stripped, sub_d)
            elif REF_LINKS[1] in ln or REF_LINKS[0] in ln:
                condition = REF_LINKS[1] if REF_LINKS[1] in ln else \
                            REF_LINKS[0]
                format_html_refs(condition, ln_stripped, sub_d)
            elif URL_STRING[2] in ln:
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
                    if i in ln_stripped and '[' not in ln_stripped:
                        ln = f"{sub_d['span_ko']}{ln}{sub_d['span_f']}"
                html_final.write(ln)
        html_final.write('</pre></body></html>')

    print_export_path(final_filename, reliable)
    remove(temp_filename)
