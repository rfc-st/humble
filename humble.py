#! /usr/bin/env python3

# humble (HTTP Headers Analyzer)
#
# MIT License
#
# Copyright (c) 2020-2023 Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)
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
# attacking or taking advantage. Don't just be a 'script kiddie': if this
# really interests you, learn, research and become a Security Analyst!.

# GREETINGS:
# María Antonia, Fernando, Joanna, Eduardo, Ana, Iván, Luis Joaquín, Juan
# Carlos, David, Carlos, Juán, Alejandro, Pablo, Íñigo, Naiara, Ricardo,
# Gabriel, Miguel Angel, David (x2), Sergio, Marta, Alba, Montse & Eloy.

from fpdf import FPDF
from time import time
from datetime import datetime
from os import linesep, path, remove
from colorama import Fore, Style, init
from collections import Counter, defaultdict
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import re
import sys
import requests
import tldextract

A_FILE = 'analysis_h.txt'
F_FILE = 'fingerprint.txt'
BOLD_S = ("[0.", "HTTP R", "[1.", "[2.", "[3.", "[4.", "[5.", "[Cabeceras")
BRI_R = Style.BRIGHT + Fore.RED
CAN_S = ': https://caniuse.com/?search='
CLI_E = [400, 401, 402, 403, 405, 406, 409, 410, 411, 412, 413, 414, 415, 416,
         417, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451]
GIT_U = "https://github.com/rfc-st/humble"
INS_S = 'http:'
# https://data.iana.org/TLD/tlds-alpha-by-domain.txt
NON_RU_TLDS = ['CYMRU', 'GURU', 'PRU']
RU_DESC = '[bcnt]'
PRG_N = 'humble (HTTP Headers Analyzer) - '
REF_S = 'Ref: '
SEC_S = "https://"
URL_S = ' URL  : '

export_date = datetime.now().strftime("%Y%m%d")
now = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
version = datetime.strptime('2023-08-04', '%Y-%m-%d').date()


class PDF(FPDF):

    def header(self):
        self.set_font('Courier', 'B', 10)
        self.set_y(15)
        pdf.set_text_color(0, 0, 0)
        self.cell(0, 5, get_detail('[pdf_t]'), new_x="CENTER", new_y="NEXT",
                  align='C')
        self.ln(1)
        self.cell(0, 5, f"({GIT_U})", align='C')
        if self.page_no() == 1:
            self.ln(9)
        else:
            self.ln(13)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(0, 0, 0)
        self.cell(0, 10, get_detail('[pdf_p]') + str(self.page_no()) +
                  get_detail('[pdf_po') + '{nb}', align='C')


def pdf_metadata():
    title = get_detail('[pdf_m]', replace=True) + URL
    git_urlc = f"{GIT_U} (v.{version})"
    pdf.set_author(git_urlc)
    pdf.set_creation_date = now
    pdf.set_creator(git_urlc)
    pdf.set_keywords(get_detail('[pdf_k]', replace=True))
    pdf.set_lang(get_detail('[pdf_l]'))
    pdf.set_subject(get_detail('[pdf_s]', replace=True))
    pdf.set_title(title)
    pdf.set_producer(git_urlc)


def pdf_sections():
    section_dict = {'[0.': '[0section_s]', '[HTTP R': '[0headers_s]',
                    '[1.': '[1missing_s]', '[2.': '[2fingerprint_s]',
                    '[3.': '[3depinsecure_s]', '[4.': '[4empty_s]',
                    '[5.': '[5compat_s]', '[Cabeceras': '[0headers_s]'}
    if match := next((i for i in section_dict if x.startswith(i)), None):
        pdf.start_section(get_detail(section_dict[match]))


def pdf_links(pdfstring):
    links = {URL_S: URL, REF_S: x.partition(REF_S)[2].strip(),
             CAN_S: x.partition(': ')[2].strip()}
    link_h = links.get(pdfstring)
    if pdfstring in (URL_S, REF_S):
        prefix = ' Ref: ' if pdfstring == REF_S else pdfstring
        pdf.write(h=3, txt=prefix)
    else:
        pdf.write(h=3, txt=x[:x.index(": ")+2])
    pdf.set_text_color(0, 0, 255)
    pdf.cell(w=2000, h=3, txt=x[x.index(": ")+2:], align="L", link=link_h)


def python_ver():
    if sys.version_info < (3, 9):
        print("")
        print_detail('[python]', 2)
        sys.exit()


def check_updates(version):
    r_url = 'https://raw.githubusercontent.com/rfc-st/humble/master/humble.py'
    try:
        response_t = requests.get(r_url, timeout=10).text
        remote_v = re.search(r"\d{4}-\d{2}-\d{2}", response_t).group()
        remote_v_date = datetime.strptime(remote_v, '%Y-%m-%d').date()
        if remote_v_date > version:
            print(f"\n v.{version}{get_detail('[not_latest]')[:-1]}{remote_v})\
                  \n{get_detail('[home]')}")
        else:
            print(f"\n v.{version}{get_detail('[latest]')}")
    except requests.exceptions.RequestException:
        print(f"\n{get_detail('[update_error]')}")


def fng_analytics_global():
    print(f"\n{Style.BRIGHT}{get_detail('[fng_stats]', replace=True)}\
{Style.RESET_ALL}{get_detail('[fng_source]', replace=True)}\n")
    with open(path.join('additional', F_FILE), 'r', encoding='utf8') as fng_f:
        fng_lines = fng_f.readlines()
    fng_analytics_global_groups(fng_lines)


def fng_analytics_global_groups(fng_lines):
    pattern_fng_global = r'\[([^\]]+)\]'
    content_cnt = Counter(match.strip() for line in fng_lines for match in
                          re.findall(pattern_fng_global, line))
    total_ln = len(fng_lines)
    print(f"{get_detail('[fng_top]', replace=True)}{total_ln}\
{get_detail('[fng_top_2]', replace=True)}\n")
    for content, count in content_cnt.most_common(20):
        pct_fng_global = round(count / total_ln * 100, 2)
        print(f" [{content}]: {pct_fng_global}% ({count})")


def fng_analytics(term):
    print(f"\n{Style.BRIGHT}{get_detail('[fng_stats]', replace=True)}\
{Style.RESET_ALL}{get_detail('[fng_source]', replace=True)}\n")
    with open(path.join('additional', F_FILE), 'r', encoding='utf8') as fng_f:
        fng_lines = fng_f.readlines()
    distinct_content, term_count = fng_analytics_groups(fng_lines, term)
    if not distinct_content:
        print(f"{get_detail('[fng_zero]', replace=True)} '{term}'.\n\n\
{get_detail('[fng_zero_2]', replace=True)}.\n")
    else:
        fng_ln = len(fng_lines)
        pct_fng = round(term_count / fng_ln * 100, 2)
        print(f"{get_detail('[fng_add]', replace=True)} '{term}': {pct_fng}%\
 ({term_count}{get_detail('[pdf_po]', replace=True)}{fng_ln})")
        fng_analytics_sorted(fng_lines, term, distinct_content)


def fng_analytics_groups(fng_ln, term):
    pattern_fng = r'\[(.*?)\]'
    distinct_content = \
        {match[1].strip()
         for line in fng_ln if (match := re.search(pattern_fng, line)) and
         term.lower() in match[1].lower()}
    term_cnt = sum(bool((match := re.search(pattern_fng, line)) and
                        term.lower() in match[1].lower()) for line in fng_ln)
    return distinct_content, term_cnt


def fng_analytics_sorted(fng_lines, term, distinct_content):
    for content in sorted(distinct_content):
        print(f"\n [{content}]")
        for line in fng_lines:
            match = re.search(r'\[(.*?)\]', line)
            if match and term.lower() in match[1].lower() \
               and content == match[1].strip():
                print(f"  {line[:line.find('[')].strip()}")


def print_guides():
    print("")
    print_detail('[guides]')
    with open(path.join('additional', 'guides.txt'), 'r', encoding='utf8') as \
            gd:
        for line in gd:
            if line.startswith('['):
                print(f" {Style.BRIGHT}{line}", end='')
            else:
                print(f"  {line}", end='')


def ua_ru_analysis(suffix, country):
    print("")
    if suffix == "UA" or country == 'Ukraine':
        detail = '[analysis_ua_output]' if args.output else '[analysis_ua]'
    elif suffix == "RU" and suffix not in NON_RU_TLDS or country == 'Russia':
        detail = RU_DESC
    print_detail(detail, 2) if detail == RU_DESC else print_detail(detail)
    if detail == RU_DESC:
        sys.exit()


def get_details_lines():
    file_path = path.join('i10n', 'details_es.txt' if args.lang == 'es' else
                          'details.txt')
    with open(file_path, encoding='utf8') as file:
        return file.readlines()


def analysis_time():
    print(".:")
    print("")
    print_detail_l('[analysis_time]')
    print(round(end - start, 2), end="")
    print_detail_l('[analysis_time_sec]')
    t_cnt = m_cnt + f_cnt + i_cnt[0] + e_cnt
    mh_cnt, fh_cnt, ih_cnt, eh_cnt, th_cnt = save_extract_totals(t_cnt)
    mhr_cnt, fhr_cnt, ihr_cnt, ehr_cnt,\
        thr_cnt = compare_totals(mh_cnt, m_cnt, fh_cnt, f_cnt, ih_cnt, i_cnt,
                                 eh_cnt, e_cnt, th_cnt, t_cnt)
    print("")
    analysis_detail(mhr_cnt, fhr_cnt, ihr_cnt, ehr_cnt, t_cnt, thr_cnt)


def save_extract_totals(t_cnt):
    with open(A_FILE, 'a+', encoding='utf8') as a_history, \
         open(A_FILE, 'r', encoding='utf8') as c_history:
        a_history.write(f"{now} ; {URL} ; {m_cnt} ; {f_cnt} ; {i_cnt[0]} ; \
{e_cnt} ; {t_cnt}\n")
        url_ln = [line for line in c_history if URL in line]
        if not url_ln:
            return ("First",) * 5
        mh_cnt, fh_cnt, ih_cnt, eh_cnt, th_cnt = extract_totals(url_ln)
        return mh_cnt, fh_cnt, ih_cnt, eh_cnt, th_cnt


def extract_totals(url_ln):
    date_var = max(line.split(" ; ")[0] for line in url_ln)
    for line in url_ln:
        if date_var in line:
            _, _, mh_cnt, fh_cnt, ih_cnt, eh_cnt, th_cnt = \
                line.strip().split(' ; ')
            break
    return mh_cnt, fh_cnt, ih_cnt, eh_cnt, th_cnt


def compare_totals(mh_cnt, m_cnt, fh_cnt, f_cnt, ih_cnt, i_cnt, eh_cnt, e_cnt,
                   th_cnt, t_cnt):
    if mh_cnt == "First":
        return [get_detail('[first_one]', replace=True)] * 5
    mhr_cnt = m_cnt - int(mh_cnt)
    fhr_cnt = f_cnt - int(fh_cnt)
    ihr_cnt = i_cnt[0] - int(ih_cnt)
    ehr_cnt = e_cnt - int(eh_cnt)
    thr_cnt = t_cnt - int(th_cnt)
    return [f'+{n}' if n > 0 else str(n) for n in [mhr_cnt, fhr_cnt, ihr_cnt,
                                                   ehr_cnt, thr_cnt]]


def file_exists(filepath):
    if not path.exists(filepath):
        detail = '[no_analysis]' if args.URL else '[no_global_analysis]'
        print(f"\n{get_detail(detail).strip()}\n")
        sys.exit()


def url_analytics(is_global=False):
    file_exists(A_FILE)
    with open(A_FILE, 'r', encoding='utf8') as c_history:
        analysis_stats = extract_global_metrics(c_history) if is_global else \
            extract_metrics(c_history)
    stats_s = '[global_stats_analysis]' if is_global else '[stats_analysis]'
    print(f"\n{get_detail(stats_s, replace=True)}{'' if is_global else URL}\n")
    for key, value in analysis_stats.items():
        key = f"{Style.BRIGHT}{key}{Style.RESET_ALL}" \
            if (not value or not key.startswith(' ')) else key
        print(f"{key}: {value}")


def extract_metrics(c_history):
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
    fourth_m = extract_highlights_metrics(url_ln)
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
{get_detail('[pdf_po]', replace=True)}{total_a})"


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
    year_a, avg_w_y, month_a = extract_year_month_metrics(url_ln)
    return (avg_w, year_a, avg_w_y, month_a)


def extract_year_month_metrics(url_ln):
    year_cnt = defaultdict(int)
    year_wng = defaultdict(int)
    for line in url_ln:
        date_str = line.split(' ; ')[0].split()[0]
        year, _, _ = map(int, date_str.split('/'))
        year_cnt[year] += 1
        year_wng[year] += int(line.split(' ; ')[-1])
    years_str = generate_year_month_group(year_cnt, url_ln)
    avg_wng_y = sum(year_wng.values()) // len(year_wng)
    return years_str, avg_wng_y, year_wng


def generate_year_month_group(year_cnt, url_ln):
    years_str = []
    for year in sorted(year_cnt.keys()):
        year_str = f" {year}: {year_cnt[year]} \
{get_detail('[analysis_y]').rstrip()}"
        month_cnts = get_month_counts(year, url_ln)
        months_str = '\n'.join([f"   ({count}){month_name.rstrip()}" for
                                month_name, count in month_cnts.items()])
        year_str += '\n' + months_str + '\n'
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


def extract_highlights_metrics(url_ln):
    sections = ['[miss_cnt]', '[finger_cnt]', '[ins_cnt]', '[empty_cnt]']
    fields_h = [2, 3, 4, 5]
    return [f"{print_detail_h(sections[i])}\n"
            f"  {print_detail_h('[best_analysis]')}: \
{get_best_worst_highlights(url_ln, fields_h[i], min)}\n"
            f"  {print_detail_h('[worst_analysis]')}: \
{get_best_worst_highlights(url_ln, fields_h[i], max)}\n"
            for i in range(len(fields_h))]


def get_best_worst_highlights(url_ln, field_index, func):
    values = [int(line.split(';')[field_index].strip()) for line in url_ln]
    target_value = func(values)
    target_line = next(line for line in url_ln
                       if int(line.split(';')[field_index].strip()) ==
                       target_value)
    return target_line.split(';')[0].strip()


def print_metrics(total_a, first_m, second_m, third_m, additional_m, fourth_m):
    basic_m = get_basic_metrics(total_a, first_m)
    error_m = get_error_metrics(second_m)
    warning_m = get_warning_metrics(additional_m)
    averages_m = get_averages_metrics(third_m)
    fourth_m = get_fourth_metrics(fourth_m)
    analysis_year_m = get_analysis_year_metrics(additional_m)
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


def get_error_metrics(second_m):
    return {'[analysis_y]': "", '[no_missing]': second_m[0],
            '[no_fingerprint]': second_m[1],
            '[no_ins_deprecated]': second_m[2],
            '[no_empty]': second_m[3] + "\n"}


def get_warning_metrics(additional_m):
    return {'[averages]': "", '[average_warnings]': f"{additional_m[0]}",
            '[average_warnings_year]': f"{additional_m[2]}"}


def get_averages_metrics(third_m):
    return {'[average_miss]': f"{third_m[0]}",
            '[average_fng]': f"{third_m[1]}", '[average_dep]': f"{third_m[2]}",
            '[average_ety]': f"{third_m[3]}\n"}


def get_fourth_metrics(fourth_m):
    return {'[highlights]': "\n" + "\n".join(fourth_m)}


def get_analysis_year_metrics(additional_m):
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
    return get_global_first_metrics(url_ln, url_lines)


def get_global_first_metrics(url_ln, url_lines):
    first_a = min(f"{line.split(' ; ')[0]}" for line in url_ln)
    latest_a = max(f"{line.split(' ; ')[0]}" for line in url_ln)
    unique_u = len({line.split(' ; ')[1] for line in url_ln})
    most_analyzed_u = max(url_lines, key=url_lines.get)
    most_analyzed_c = url_lines[most_analyzed_u]
    most_analyzed_cu = f"({most_analyzed_c}) {most_analyzed_u}"
    least_analyzed_u = min(url_lines, key=url_lines.get)
    least_analyzed_c = url_lines[least_analyzed_u]
    least_analyzed_cu = f"({least_analyzed_c}) {least_analyzed_u}"
    return first_a, latest_a, unique_u, most_analyzed_cu, least_analyzed_cu


def get_basic_global_metrics(total_a, first_m):
    return {'[main]': "", '[total_analysis]': total_a,
            '[total_global_analysis]': str(first_m[2]),
            '[first_analysis_a]': first_m[0],
            '[latest_analysis]': first_m[1] + "\n",
            '[most_analyzed]': first_m[3],
            '[least_analyzed]': first_m[4] + "\n"}


def print_global_metrics(total_a, first_m, second_m, third_m, additional_m):
    basic_m = get_basic_global_metrics(total_a, first_m)
    error_m = get_error_metrics(second_m)
    warning_m = get_warning_metrics(additional_m)
    averages_m = get_averages_metrics(third_m)
    analysis_year_m = get_analysis_year_metrics(additional_m)
    totals_m = {**basic_m, **error_m, **warning_m, **averages_m,
                **analysis_year_m}
    return {get_detail(key, replace=True): value for key, value in
            totals_m.items()}


def clean_output():
    # Kudos to Aniket Navlur!!!: https://stackoverflow.com/a/52590238
    sys.stdout.write('\x1b[1A\x1b[2K\x1b[1A\x1b[2K\x1b[1A\x1b[2K')


def print_path(filename):
    clean_output()
    print("")
    print_detail_l('[report]')
    print(path.abspath(filename))


def print_ok():
    print_detail('[ok]')


def print_header(header):
    if not args.output:
        print(f"{BRI_R} {header}")
    else:
        print(f" {header}")


def print_header_fng(header):
    prefix, _, suffix = [x.strip() for x in header.partition(' [')]
    if args.output:
        print(f" {header}")
    elif '[' in header:
        print(f"{BRI_R} {prefix}{Style.NORMAL}{Fore.RESET} [{suffix}")
    else:
        print(f"{BRI_R} {header}")


def print_summary():
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
        print(f" ({GIT_U})")
    elif args.output != 'pdf':
        print("")
        print_detail('[humble]', 2)
    print(linesep.join(['']*2))
    print_detail_r('[0section]')
    print_detail_l('[info]')
    print(f" {now}")
    print(f' URL  : {URL}')
    if status_code in CLI_E:
        id_mode = f"[http_{status_code}]"
        print(f"{get_detail(id_mode, replace=True)}")


def print_headers():
    if args.ret:
        print(linesep.join(['']*2))
        print_detail_r('[0headers]')
        for key, value in sorted(headers.items()):
            if not args.output:
                print(f" {Fore.CYAN}{key}:", value)
            else:
                print(f" {key}:", value)
    print('\n')


def print_details(short_d, long_d, id_mode, i_cnt):
    print_detail_r(short_d, is_red=True)
    if not args.brief:
        print_detail(long_d, 2) if id_mode == 'd' else print_detail(long_d, 3)
    i_cnt[0] += 1
    return i_cnt


def print_detail(id_mode, num_lines=1):
    idx = details_f.index(id_mode + '\n')
    print(details_f[idx+1], end='')
    for i in range(1, num_lines+1):
        if idx+i+1 < len(details_f):
            print(details_f[idx+i+1], end='')


def print_detail_l(id_mode):
    for i, line in enumerate(details_f):
        if line.startswith(id_mode):
            print(details_f[i+1].replace('\n', ''), end='')


def print_detail_h(id_mode):
    for i, line in enumerate(details_f):
        if line.startswith(id_mode):
            return details_f[i+1].replace('\n', '').replace(':', '')[1:]


def print_detail_r(id_mode, is_red=False):
    style_str = BRI_R if is_red else Style.BRIGHT
    for i, line in enumerate(details_f):
        if line.startswith(id_mode):
            if not args.output:
                print(style_str + details_f[i+1], end='')
            else:
                print(details_f[i+1], end='')
            if not is_red:
                print("")


def get_detail(id_mode, replace=False):
    for i, line in enumerate(details_f):
        if line.startswith(id_mode):
            return (details_f[i+1].replace('\n', '')) if replace else \
                details_f[i+1]


def fingerprint_headers(headers, l_fng, l_fng_ex):
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
        print_header_fng(l_fng_ex[index_fng])
        if not headers[header]:
            print(get_detail('[empty_fng]'))
        else:
            print(f" {headers[header]}")
        print("")
    else:
        print_header(header)


def analysis_detail(mhr_cnt, fhr_cnt, ihr_cnt, ehr_cnt, t_cnt, thr_cnt):
    literals = ['[miss_cnt]', '[finger_cnt]', '[ins_cnt]', '[empty_cnt]',
                '[total_cnt]']
    totals = [f"{m_cnt} ({mhr_cnt})", f"{f_cnt} ({fhr_cnt})", f"{i_cnt[0]} \
({ihr_cnt})", f"{e_cnt} ({ehr_cnt})\n", f"{t_cnt} ({thr_cnt})\n"]
    print("")
    for literal, total in zip(literals, totals):
        print(f"{(print_detail_l(literal) or '')[:-1]}{total}")


def detail_exceptions(id_exception, exception_v):
    clean_output()
    print("")
    print_detail(id_exception)
    raise SystemExit from exception_v


def request_exceptions():
    headers = {}
    status_c = None
    try:
        # Yes: Server certificates should be verified during SSL/TLS
        # connections. Despite this, I think 'verify=False' would benefit
        # analysis of URLs with self-signed certificates, associated with
        # development environments, etc.
        r = requests.get(URL, verify=False, headers=c_headers, timeout=15)
        status_c = r.status_code
        headers = r.headers
        r.raise_for_status()
    except requests.exceptions.HTTPError as err_http:
        if err_http.response.status_code == 407:
            detail_exceptions('[e_proxy]', err_http)
        if str(err_http.response.status_code).startswith('5'):
            detail_exceptions('[e_serror]', err_http)
    except tuple(exception_d.keys()) as e:
        ex = exception_d.get(type(e))
        if ex and (not callable(ex) or ex(e)):
            detail_exceptions(ex, e)
    except requests.exceptions.RequestException as err:
        raise SystemExit from err
    return headers, status_c


init(autoreset=True)

parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
                        description=PRG_N + GIT_U)
parser.add_argument("-a", dest='URL_A', action="store_true", help="show \
statistics of the performed analysis (will be global if '-u URL' is omitted)")
parser.add_argument("-b", dest='brief', action="store_true", help="show a \
brief analysis (if omitted, a detailed one will be shown)")
parser.add_argument("-f", nargs='?', type=str, dest='term', help="show \
fingerprint statistics (will be the Top 20 if \"TERM\", e.g. \"Google\", is \
omitted)")
parser.add_argument("-g", dest='guides', action="store_true", help="show \
guidelines for securing popular web servers/services")
parser.add_argument("-l", dest='lang', choices=['es'], help="show the \
analysis in the indicated language (if omitted, English will be used)")
parser.add_argument("-o", dest='output', choices=['html', 'pdf', 'txt'],
                    help="save analysis to file (with the format \
URL_headers_yyyymmdd.ext)")
parser.add_argument("-r", dest='ret', action="store_true", help="show full \
HTTP response headers and a detailed analysis")
parser.add_argument('-u', type=str, dest='URL', help="schema and URL to \
analyze. E.g. https://google.com")
parser.add_argument("-v", "--version", action="store_true",
                    help="show the version of this tool and check for \
updates")

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

if args.version:
    details_f = get_details_lines()
    if args.lang:
        details_f = get_details_lines()
    check_updates(version)
    sys.exit()

if args.term is None and '-f' in sys.argv:
    details_f = get_details_lines()
    if args.lang:
        details_f = get_details_lines()
    fng_analytics_global()
    sys.exit()

if args.term:
    term = args.term
    details_f = get_details_lines()
    if args.lang:
        details_f = get_details_lines()
    fng_analytics(term)
    sys.exit()

if args.lang and not (args.URL or args.URL_A) and not args.guides:
    parser.error("'-l' option requires also '-u' or '-a'.")

if any([args.brief, args.output, args.ret]) \
        and (args.URL is None or args.guides is None or args.URL_A is None):
    parser.error("'-b', -'o' and '-r' options requires also '-u'.")

URL = args.URL
details_f = get_details_lines()
python_ver()

if args.guides:
    print_guides()
    sys.exit()

if args.URL_A:
    if args.URL:
        url_analytics()
    else:
        details_f = get_details_lines()
        url_analytics(is_global=True)
    sys.exit()

start = time()

# https://github.com/rfc-st/humble/blob/master/CODE_OF_CONDUCT.md#update-20220326
sffx = tldextract.extract(URL).suffix[-2:].upper()
cnty = requests.get('https://ipapi.co/country_name/').text.strip()
if (sffx in ("UA", 'RU') and sffx not in NON_RU_TLDS) or cnty in ('Ukraine',
                                                                  'Russia'):
    ua_ru_analysis(sffx, cnty)
else:
    if not args.URL_A:
        detail = '[analysis_output]' if args.output else '[analysis]'
        print("")
        print_detail(detail)

# Regarding 'dh key too small' errors: https://stackoverflow.com/a/41041028
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
try:
    requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS \
        += ':HIGH:!DH:!aNULL'
except AttributeError:
    pass

exception_d = {
    requests.exceptions.ConnectionError: '[e_404]',
    requests.exceptions.InvalidSchema: '[e_schema]',
    requests.exceptions.InvalidURL: '[e_invalid]',
    requests.exceptions.MissingSchema: '[e_schema]',
    requests.exceptions.SSLError: None,
    requests.exceptions.Timeout: '[e_timeout]',
}
requests.packages.urllib3.disable_warnings()

c_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'}

headers, status_code = request_exceptions()

# Export analysis
ext = "t.txt" if args.output in ['pdf', 'html'] else ".txt"

if args.output:
    orig_stdout = sys.stdout
    name_s = tldextract.extract(URL)
    name_sub = name_s.subdomain + '.' if name_s.subdomain else ''
    name_dom = name_s.domain
    name_tld = name_s.suffix
    name_e = f"{name_sub}{name_dom}.{name_tld}_headers_{export_date}{ext}"
    f = open(name_e, 'w', encoding='utf8')
    sys.stdout = f

print_summary()
print_headers()

# Report - 1. Missing HTTP Security Headers
m_cnt = 0

print_detail_r('[1missing]')

l_miss = ['Cache-Control', 'Clear-Site-Data', 'Content-Type',
          'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy',
          'Cross-Origin-Resource-Policy', 'Content-Security-Policy', 'NEL',
          'Permissions-Policy', 'Referrer-Policy', 'Strict-Transport-Security',
          'X-Content-Type-Options']

l_detail = ['[mcache]', '[mcsd]', '[mctype]', '[mcoe]', '[mcop]', '[mcor]',
            '[mcsp]', '[mnel]', '[mpermission]', '[mreferrer]', '[msts]',
            '[mxcto]', '[mxfo]']

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
    print_ok()

print("")

# Report - 2. Fingerprinting through headers/values

# Certain content of the file 'fingerprint.txt' has been made possible by:
#
# OWASP Secure Headers Project
# https://github.com/OWASP/www-project-secure-headers/blob/master/LICENSE.txt
print_detail_r('[2fingerprint]')

if not args.brief:
    print_detail("[afgp]")

l_fng = []
l_fng_ex = []

with open(path.join('additional', 'fingerprint.txt'), 'r', encoding='utf8') \
          as fn:
    for line in fn:
        l_fng.append(line.partition(' [')[0].strip())
        l_fng_ex.append(line.strip())

f_cnt = fingerprint_headers(headers, l_fng, l_fng_ex)

if args.brief and f_cnt != 0:
    print("")

if f_cnt == 0:
    print_ok()

print("")

# Report - 3. Deprecated HTTP Headers/Protocols and Insecure values
i_cnt = [0]

print_detail_r('[3depinsecure]')

if not args.brief:
    print_detail("[aisc]")

l_ins = ['Access-Control-Allow-Methods', 'Access-Control-Allow-Origin',
         'Allow', 'Content-Type', 'Etag', 'Expect-CT', 'Feature-Policy',
         'Onion-Location', 'P3P', 'Public-Key-Pins', 'Set-Cookie',
         'Server-Timing', 'Timing-Allow-Origin', 'X-Content-Security-Policy',
         'X-Content-Security-Policy-Report-Only', 'X-DNS-Prefetch-Control',
         'X-Download-Options', 'X-Pad', 'X-Permitted-Cross-Domain-Policies',
         'X-Pingback', 'X-Runtime', 'X-Webkit-CSP',
         'X-Webkit-CSP-Report-Only', 'X-XSS-Protection']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
# https://cyberwhite.co.uk/http-verbs-and-their-security-risks/
l_methods = ['PUT', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE', 'TRACK', 'DELETE',
             'DEBUG', 'PATCH', '*']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
l_cachev = ['immutable', 'max-age', 'must-revalidate', 'must-understand',
            'no-cache', 'no-store', 'no-transform', 'private',
            'proxy-revalidate', 'public', 's-maxage', 'stale-if-error',
            'stale-while-revalidate']

l_cache = ['no-cache', 'no-store', 'must-revalidate']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data
l_csdata = ['cache', 'cookies', 'storage', 'executionContexts', '*']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
l_cencoding = ['br', 'compress', 'deflate', 'gzip', 'x-gzip']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
l_csp_directives = ['base-uri', 'child-src', 'connect-src', 'default-src',
                    'font-src', 'form-action', 'frame-ancestors', 'frame-src',
                    'img-src', 'manifest-src', 'media-src', 'navigate-to',
                    'object-src', 'report-to', 'require-trusted-types-for',
                    'sandbox', 'script-src', 'script-src-elem',
                    'script-src-attr', 'style-src', 'style-src-elem',
                    'style-src-attr', 'trusted-types',
                    'upgrade-insecure-requests', 'webrtc', 'worker-src']

l_csp_dep = ['block-all-mixed-content', 'disown-opener', 'plugin-types',
             'prefetch-src', 'referrer', 'report-uri', 'require-sri-for']

l_csp_ro_dep = ['violated-directive']

l_csp_equal = ['nonce', 'sha', 'style-src-elem', 'report-to', 'report-uri']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types
l_legacy = ['application/javascript', 'application/ecmascript',
            'application/x-ecmascript', 'application/x-javascript',
            'text/ecmascript', 'text/javascript1.0', 'text/javascript1.1',
            'text/javascript1.2', 'text/javascript1.3', 'text/javascript1.4',
            'text/javascript1.5', 'text/jscript', 'text/livescript',
            'text/x-ecmascript', 'text/x-javascript']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Trailer
l_trailer = ['Authorization', 'Cache-Control', 'Content-Encoding',
             'Content-Length', 'Content-Type', 'Content-Range', 'Host',
             'Max-Forwards', 'Set-Cookie', 'TE', 'Trailer',
             'Transfer-Encoding']

# https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md
# https://csplite.com/fp/
l_per_feat = ['accelerometer', 'ambient-light-sensor', 'autoplay', 'battery',
              'bluetooth', 'browsing-topics', 'camera', 'ch-ua', 'ch-ua-arch',
              'ch-ua-bitness', 'ch-ua-full-version', 'ch-ua-full-version-list',
              'ch-ua-mobile', 'ch-ua-model', 'ch-ua-platform',
              'ch-ua-platform-version', 'ch-ua-wow64', 'clipboard-read',
              'clipboard-write', 'conversion-measurement',
              'cross-origin-isolated', 'display-capture', 'document-access',
              'document-write', 'encrypted-media',
              'execution-while-not-rendered',
              'execution-while-out-of-viewport',
              'focus-without-user-activation', 'font-display-late-swap',
              'fullscreen', 'gamepad', 'geolocation', 'gyroscope', 'hid',
              'identity-credentials-get', 'idle-detection', 'interest-cohort',
              'join-ad-interest-group', 'keyboard-map', 'layout-animations',
              'lazyload', 'legacy-image-formats',
              'loading-frame-default-eager', 'local-fonts', 'magnetometer',
              'microphone', 'midi', 'navigation-override', 'otp-credentials',
              'oversized-images', 'payment', 'picture-in-picture',
              'publickey-credentials-create', 'publickey-credentials-get',
              'run-ad-auction', 'screen-wake-lock', 'serial',
              'shared-autofill', 'speaker', 'speaker-selection',
              'storage-access', 'sync-script', 'sync-xhr',
              'trust-token-redemption', 'unload', 'unoptimized-images',
              'unoptimized-lossless-images',
              'unoptimized-lossless-images-strict', 'unoptimized-lossy-images',
              'unsized-media', 'usb', 'vertical-scroll', 'vibrate',
              'wake-lock', 'web-share', 'window-placement',
              'xr-spatial-tracking']

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
l_ref_values = ['no-referrer', 'no-referrer-when-downgrade', 'origin',
                'origin-when-cross-origin', 'same-origin', 'strict-origin',
                'strict-origin-when-cross-origin', 'unsafe-url']

l_ref_secure = ['strict-origin', 'strict-origin-when-cross-origin',
                'no-referrer-when-downgrade', 'no-referrer']

# https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag
# https://www.bing.com/webmasters/help/which-robots-metatags-does-bing-support-5198d240
# https://seranking.com/blog/guide-meta-tag-robots-x-robots-tag/
l_robots = ['all', 'archive', 'follow', 'index', 'indexifembedded',
            'max-image-preview', 'max-snippet', 'max-video-preview',
            'noarchive', 'nocache', 'noodp', 'nofollow', 'noimageindex',
            'noindex', 'none', 'nopagereadaloud', 'nositelinkssearchbox',
            'nosnippet', 'notranslate', 'noydir', 'unavailable_after']

if 'Accept-CH' in headers and URL.startswith(INS_S):
    print_details('[ixach_h]', '[ixach]', 'd', i_cnt)

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
    if any(elem in csp_h for elem in ['unsafe-eval', 'unsafe-inline']):
        print_details('[icsp_h]', '[icsp]', 'm', i_cnt)
    elif not any(elem in csp_h for elem in l_csp_directives):
        print_details('[icsi_h]', '[icsi]', 'd', i_cnt)
    if any(elem in csp_h for elem in l_csp_dep):
        print_detail_r('[icsi_d]', is_red=True)
        if not args.brief:
            matches_csp = [x for x in l_csp_dep if x in csp_h]
            print_detail_l("[icsi_d_s]")
            print(', '.join(matches_csp))
            print_detail("[icsi_d_r]")
        i_cnt[0] += 1
    if ('=' in csp_h) and not (any(elem in csp_h for elem in l_csp_equal)):
        print_details('[icsn_h]', '[icsn]', 'd', i_cnt)
    if (INS_S in csp_h) and (URL.startswith('https')):
        print_details('[icsh_h]', '[icsh]', 'd', i_cnt)
    if ' * ' in csp_h:
        print_details('[icsw_h]', '[icsw]', 'd', i_cnt)
    if 'unsafe-hashes' in csp_h:
        print_details('[icsu_h]', '[icsu]', 'd', i_cnt)
    if "'nonce-" in csp_h:
        nonces_csp = re.findall(r"'nonce-([^']+)'", csp_h)
        for nonce_csp in nonces_csp:
            if len(nonce_csp) < 32:
                print_details('[icsnces_h]', '[icsnces]', 'd', i_cnt)
                break
    ip_ptrn = (r'^(?:\d{1,3}\.){3}\d{1,3}$|'
               r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    ip_mtch = re.findall(ip_ptrn, csp_h)
    if ip_mtch != ['127.0.0.1']:
        for match in ip_mtch:
            if re.match(ip_ptrn, match):
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

if 'Digest' in headers:
    print_details('[idig_h]', '[idig]', 'd', i_cnt)

if 'Etag' in headers:
    print_details('[ieta_h]', '[ieta]', 'd', i_cnt)

if 'Expect-CT' in headers:
    print_details('[iexct_h]', '[iexct]', 'm', i_cnt)

if 'Feature-Policy' in headers:
    print_details('[iffea_h]', '[iffea]', 'd', i_cnt)

if URL.startswith(INS_S):
    print_details('[ihttp_h]', '[ihttp]', 'd', i_cnt)

if 'Large-Allocation' in headers:
    print_details('[ixlalloc_h]', '[ixallocd]', 'd', i_cnt)

if 'Permissions-Policy' in headers:
    perm_header = headers['Permissions-Policy'].lower()
    if not any(elem in perm_header for elem in l_per_feat):
        print_details('[ifpoln_h]', '[ifpoln]', 'm', i_cnt)
    if '*' in perm_header:
        print_details('[ifpol_h]', '[ifpol]', 'd', i_cnt)
    if 'none' in perm_header:
        print_details('[ifpoli_h]', '[ifpoli]', 'd', i_cnt)
    if 'document-domain' in perm_header:
        print_detail_r('[ifpold_h]', is_red=True)
        if not args.brief:
            print_detail_l('[ifpold_s]')
            print('document-domain')
            print_detail('[ifpold]')
        i_cnt[0] += 1

if 'Onion-Location' in headers:
    print_details('[ionloc_h]', '[ionloc]', 'm', i_cnt)

if 'P3P' in headers:
    print_details('[ip3p_h]', '[ip3p]', 'd', i_cnt)

if 'Pragma' in headers:
    print_details('[iprag_h]', '[iprag]', 'd', i_cnt)

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

ck_header = headers.get("Set-Cookie", '').lower()
if ck_header:
    if not (URL.startswith(INS_S)) and not all(elem in ck_header for elem in
                                               ('secure', 'httponly')):
        print_details("[iset_h]", "[iset]", "d", i_cnt)
    if (URL.startswith(INS_S)) and ('secure' in ck_header):
        print_details("[iseti_h]", "[iseti]", "d", i_cnt)
    if "samesite=none" in ck_header and "secure" not in ck_header:
        print_details("[iseti_m]", "[isetm]", "d", i_cnt)

sts_header = headers.get('Strict-Transport-Security', '').lower()
if (sts_header) and not (URL.startswith(INS_S)):
    age = int(''.join(filter(str.isdigit, sts_header)))
    if not all(elem in sts_header for elem in ('includesubdomains',
       'max-age')) or (age is None or age < 31536000):
        print_details('[ists_h]', '[ists]', 'm', i_cnt)
    if ',' in sts_header:
        print_details('[istsd_h]', '[istsd]', 'd', i_cnt)

if (sts_header) and (URL.startswith(INS_S)):
    print_details('[ihsts_h]', '[ihsts]', 'd', i_cnt)

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
    if xfo_header not in ['deny', 'sameorigin']:
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
    if '0' not in headers["X-XSS-Protection"]:
        print_details('[ixxp_h]', '[ixxp]', 'd', i_cnt)
    if ',' in headers['X-XSS-Protection']:
        print_details('[ixxpd_h]', '[ixxpd]', 'd', i_cnt)

if args.brief and i_cnt[0] != 0:
    print("")

if i_cnt[0] == 0:
    print_ok()

print("")

# Report - 4. Empty HTTP Response Headers Values
e_cnt = 0
empty_s_headers = sorted(headers)
l_empty = []
print_detail_r('[4empty]')

if not args.brief:
    print_detail("[aemp]")

for key in empty_s_headers:
    if not headers[key]:
        l_empty.append("_" + key)
        print_header(key)
        e_cnt += 1

print("") if e_cnt != 0 else print_ok()
print("")

# Report - 5. Browser Compatibility for Enabled HTTP Security Headers
print_detail_r('[5compat]')

l_sec = ['Cache-Control', 'Clear-Site-Data', 'Content-Type',
         'Content-Security-Policy', 'Cross-Origin-Embedder-Policy',
         'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy', 'NEL',
         'Permissions-Policy', 'Referrer-Policy', 'Strict-Transport-Security',
         'X-Content-Type-Options', 'X-Frame-Options']

header_matches = [header for header in l_sec if header in headers]

if header_matches:
    for key in header_matches:
        output_string = "  " if args.output == 'html' else " "
        key_string = key if args.output else Fore.CYAN + key + Fore.RESET
        print(f"{output_string}{key_string}{CAN_S}\
{key.replace('Content-Security-Policy', 'contentsecuritypolicy2')}")
else:
    print_detail_l("[bcompat_n]") if args.output else \
        print_detail_r("[bcompat_n]", is_red=True)

print(linesep.join(['']*2))
end = time()
analysis_time()

# Export analysis
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
    f = open(name_e, "r", encoding='utf8')
    links_strings = (URL_S, REF_S, CAN_S)

    for x in f:
        if '[' in x:
            pdf_sections()
        pdf.set_font(style='B' if any(s in x for s in BOLD_S) else '')
        for string in links_strings:
            if string in x:
                pdf_links(string)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(197, 2.6, txt=x, align='L')

    name_p = f"{name_e[:-5]}.pdf"
    pdf.output(name_p)
    print_path(name_p)
    f.close()
    remove(name_e)
elif args.output == 'html':
    sys.stdout = orig_stdout
    f.close()

    # HTML Template
    title = get_detail('[pdf_s]')
    header = f'<!DOCTYPE HTML><html lang="en"><head><meta charset="utf-8">\
<title>{title}</title><style>pre {{overflow-x: auto; white-space: \
pre-wrap;white-space: -moz-pre-wrap; white-space: -pre-wrap;white-space: \
-o-pre-wrap; word-wrap: break-word; font-size: medium;}} a {{color: blue; \
text-decoration: none;}} .ok {{color: green;}} .header {{color: #660033;}} \
.ko {{color: red;}} </style></head>'
    body = '<body><pre>'
    footer = '</pre></body></html>'

    name_p = f"{name_e[:-5]}.html"
    l_miss.extend(['Pragma', 'WWW-Authenticate', 'X-Frame-Options',
                   'X-Robots-Tag', 'X-UA-compatible'])
    l_final = sorted(l_miss + l_ins)
    l_fng_final = sorted(l_fng)

    with open(name_e, 'r', encoding='utf8') as input_file,\
            open(name_p, 'w', encoding='utf8') as output:
        output.write(str(header))
        output.write(str(body))

        sub_d = {'ahref_f': '</a>', 'ahref_s': '<a href="', 'close_t': '">',
                 'span_ko': '<span class="ko">', 'span_h':
                 '<span class="header">', 'span_f': '</span>'}

        for ln in input_file:
            if 'rfc-st' in ln:
                output.write(f"{ln[:2]}{sub_d['ahref_s']}{ln[2:-2]}\
                             {sub_d['close_t']}{ln[2:]}{sub_d['ahref_f']}")
            elif ' URL  : ' in ln:
                output.write(f"{ln[:7]}{sub_d['ahref_s']}{ln[7:]}\
                             {sub_d['close_t']}{ln[7:]}{sub_d['ahref_f']}")
            elif any(s in ln for s in BOLD_S):
                output.write(f'<strong>{ln}</strong>')
            elif get_detail('[ok]') in ln:
                output.write(f'<span class="ok">{ln}{sub_d["span_f"]}')
            elif get_detail('[bcompat_n]') in ln:
                output.write(f"{sub_d['span_ko']}{ln}{sub_d['span_f']}")
            elif ' Ref: ' in ln:
                output.write(f"{ln[:6]}{sub_d['ahref_s']}{ln[6:]}\
                             {sub_d['close_t']}{ln[6:]}{sub_d['ahref_f']}")
            elif 'caniuse' in ln:
                ln = f"{sub_d['span_h']}{ln[1:ln.index(': ')]}: \
{sub_d['span_f']}{sub_d['ahref_s']}{ln[ln.index(SEC_S):]}{sub_d['close_t']}\
{ln[ln.index(SEC_S):]}{sub_d['ahref_f']}"
                output.write(ln)
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
                        ln = f"{sub_d['span_ko']}{ln[:idx]}{sub_d['span_f']}\
{ln[idx:]}"
                    elif i in ln and args.brief:
                        ln = f"{sub_d['span_ko']}{ln}{sub_d['span_f']}"
                for i in l_final:
                    if (i in ln) and ('"' not in ln) or ('HTTP (' in ln):
                        ln = ln.replace(ln, sub_d['span_ko'] +
                                        ln + sub_d['span_f'])
                for i in l_empty:
                    if i[1:] in ln:
                        ln = f"{sub_d['span_ko']}{ln}{sub_d['span_f']}"
                output.write(ln)
        output.write(footer)

    print_path(name_p)
    remove(name_e)
