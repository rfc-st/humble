#!/usr/bin/env python3

import sys
import pytest
import shutil
import contextlib
import subprocess
from datetime import datetime
from os import listdir, path, remove
from argparse import ArgumentParser, RawDescriptionHelpFormatter

HUMBLE_TESTS_DIR = path.dirname(__file__)
HUMBLE_TEMP_FILE = path.join(HUMBLE_TESTS_DIR, 'analysis_h.txt')
PYTEST_CACHE_DIRS = [
    path.join(HUMBLE_TESTS_DIR, d)
    for d in ['__pycache__', '.pytest_cache']
]
HUMBLE_DESC = "Basic unit tests for 'humble' (HTTP Headers Analyzer)"
HUMBLE_GIT = 'https://github.com/rfc-st/humble'
HUMBLE_PROJECT_ROOT = path.abspath(path.join(HUMBLE_TESTS_DIR, '..'))
HUMBLE_INPUT_DIR = path.join(HUMBLE_PROJECT_ROOT, 'samples')
HUMBLE_INPUT_FILE = path.abspath(path.join(HUMBLE_INPUT_DIR,
                                           'github_input_file.txt'))
HUMBLE_INPUT_URL = 'https://github.com'
HUMBLE_L10N_DIR = path.join(HUMBLE_PROJECT_ROOT, 'l10n')
HUMBLE_L10N_FILE = ('details.txt', 'details_es.txt')
HUMBLE_MAIN_FILE = path.abspath(path.join(HUMBLE_TESTS_DIR, '..', 'humble.py'))
INPUT_FILE_URL = "https://github.com"
REQUIRED_PYTHON = (3, 11)
TEST_URL = 'https://google.com'
TEST_CFGS = {
    'test_help': (['-h'], 'want to contribute?'),
    'test_brief': (['-u', TEST_URL, '-b'], 'Analysis Grade:'),
    'test_cicd': (['-u', TEST_URL, '-cicd'], 'Analysis Grade'),
    'test_detailed': (['-u', TEST_URL], 'Analysis Grade:'),
    'test_export_csv': (['-u', TEST_URL, '-o', 'csv'], 'CSV saved'),
    'test_export_html': (['-u', TEST_URL, '-o', 'html'], 'HTML saved'),
    'test_export_json': (['-u', TEST_URL, '-o', 'json'], 'JSON saved'),
    'test_export_json_brief': (['-u', TEST_URL, '-o', 'json', '-b'],
                               'JSON saved'),
    'test_export_pdf': (['-u', TEST_URL, '-o', 'pdf'], 'PDF saved'),
    'test_export_xlsx': (['-u', TEST_URL, '-o', 'xlsx'], 'XLSX saved'),
    'test_export_xml': (['-u', TEST_URL, '-o', 'xml'], 'XML saved'),
    'test_fingerprint_groups': (['-f'], 'Top 20 groups'),
    'test_fingerprint_term': (['-f', 'Google'], 'Headers related to'),
    'test_input_file': (['-if', HUMBLE_INPUT_FILE, '-u', HUMBLE_INPUT_URL],
                        'Input:'),
    'test_l10n': (['-u', TEST_URL, '-l', 'es'], 'Advertencias a revisar'),
    'test_l10n_file': (['-grd', '-l', 'es'], 'No te obsesiones'),
    'test_response_headers': (['-u', TEST_URL, '-r'], 'HTTP Response Headers'),
    'test_skipped_headers': (['-u', TEST_URL, '-s', 'ETAG', 'NEL'],
                             'expressly excluded'),
    'test_updates': (['-v'], 'Keeping your security tools'),
    'test_user_agent': (['-u', TEST_URL, '-ua', '4'],
                        'Selected the User-Agent'),
    'test_user_agent_list': (['-ua', '0'], 'source: '),
}
TEST_SUMMS = ('[test_help]', '[test_brief]', '[test_cicd]', '[test_detailed]',
              '[test_export_csv]', '[test_export_html]', '[test_export_json]',
              '[test_export_json_brief]', '[test_export_pdf]',
              '[test_export_xlsx]', '[test_export_xml]', '[test_fng_groups]',
              '[test_fng_term]', '[test_input_file]', '[test_l10n]',
              '[test_l10n_file]', '[test_skipped_headers]', '[test_updates]',
              '[test_user_agent]', '[test_user_agent_list]', '[test_python]')


class _Args:
    URL = INPUT_FILE_URL
    lang = None


@pytest.fixture(scope="session", autouse=True)
def delete_prior_temps():
    if path.isfile(HUMBLE_TEMP_FILE):
        with contextlib.suppress(Exception):
            remove(HUMBLE_TEMP_FILE)
    yield


def get_detail(id_mode, replace=False):
    for i, line in enumerate(l10n_main):
        if line.startswith(id_mode):
            return (l10n_main[i+1].replace('\n', '')) if replace else \
                l10n_main[i+1]


def print_error_detail(id_mode):
    print(f"\n{get_detail(id_mode, replace=True)}")
    sys.exit()


def get_l10n_content():
    if args.lang == 'en':
        l10n_file = HUMBLE_L10N_FILE[0]
    elif args.lang == 'es':
        l10n_file = HUMBLE_L10N_FILE[1]

    l10n_path = path.join(HUMBLE_TESTS_DIR, HUMBLE_L10N_DIR, l10n_file)
    with open(l10n_path, 'r', encoding='utf8') as l10n_content:
        return l10n_content.readlines()


def print_results():
    print()
    summaries = [(tag, get_detail(tag, replace=True)) for tag in TEST_SUMMS]
    max_len = max(len(tag.strip("[]")) for tag, _ in summaries)
    for tag, detail in summaries:
        print(f"{tag.strip("[]").ljust(max_len + 1)}:{detail}")
    print()


def run_test(args, expected_text, timeout=5):
    test_args = [TEST_URL if a is None else a for a in args]
    try:
        result = subprocess.run(
            [sys.executable, HUMBLE_MAIN_FILE] + test_args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace"
        )
        output = result.stdout if result.returncode == 0 else ""
    except subprocess.TimeoutExpired:
        pytest.fail(get_detail('[test_timeout]', replace=True))
    if expected_text not in output:
        pytest.fail(
            f"{get_detail('[test_expected]', replace=True)} '{expected_text}' "
            f"{get_detail('[test_notfound]', replace=True)}"
        )


def make_test_func(cfg_key):
    def test_func():
        run_test(*TEST_CFGS[cfg_key])
    return test_func


for key in TEST_CFGS.keys():
    globals()[key] = make_test_func(key)


def get_python_version(req=REQUIRED_PYTHON):
    return sys.version_info[:2] >= req


def test_python():
    if not get_python_version():
        pytest.fail(
            f"{get_detail('[test_pythonm]', replace=True)} "
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )


def delete_humble_analysis(file_path):
    msgs = []
    if path.isfile(file_path):
        try:
            remove(file_path)
            msgs.append((get_detail('[test_temp]', replace=True), file_path))
        except Exception as e:
            msgs.append((get_detail('[test_ftemp]', replace=True),
                         f"({type(e).__name__}) {file_path}"))
    return msgs


def delete_export_files(extension, ok_msg, ko_msg):
    msgs = []
    with contextlib.suppress(Exception):
        file = next(
            f for f in listdir(HUMBLE_TESTS_DIR)
            if f.lower().endswith(extension)
        )
        export_file = path.join(HUMBLE_TESTS_DIR, file)
        try:
            remove(export_file)
            msgs.append((get_detail(ok_msg, replace=True), export_file))
        except Exception as e:
            msgs.append((get_detail(ko_msg, replace=True),
                         f"({type(e).__name__}) {export_file}"))
    return msgs


def delete_pytest_caches(dir_path):
    msgs = []
    if path.isdir(dir_path):
        try:
            shutil.rmtree(dir_path)
            msgs.append((get_detail('[test_cache]', replace=True), dir_path))
        except Exception as e:
            msgs.append((get_detail('[test_fcache]', replace=True),
                         f"({type(e).__name__}) {dir_path}"))
    return msgs


def delete_temps():
    current_time = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
    info_msgs = [
        (get_detail('[test_tests]', replace=True), current_time),
        (get_detail('[test_input]', replace=True), INPUT_FILE_URL),
        (get_detail('[test_remaining]', replace=True), TEST_URL)
    ]
    info_msgs.extend(delete_humble_analysis(HUMBLE_TEMP_FILE))
    info_msgs.extend(delete_export_files('.csv', '[test_csv]', '[test_fcsv]'))
    info_msgs.extend(delete_export_files('.txt', '[test_txt]', '[test_ftxt]'))
    info_msgs.extend(delete_export_files('.html', '[test_html]',
                                         '[test_fhtml]'))
    info_msgs.extend(delete_export_files('.json', '[test_json]',
                                         '[test_fjson]'))
    info_msgs.extend(delete_export_files('.json', '[test_json_brief]',
                                         '[test_fjson_brief]'))
    info_msgs.extend(delete_export_files('.pdf', '[test_pdf]', '[test_fpdf]'))
    info_msgs.extend(delete_export_files('.xlsx', '[test_xlsx]',
                                         '[test_fxlsx]'))
    info_msgs.extend(delete_export_files('.xml', '[test_xml]', '[test_fxml]'))
    for cache_dir in PYTEST_CACHE_DIRS:
        info_msgs.extend(delete_pytest_caches(cache_dir))
    error_msgs = [(msg, val) for msg, val in info_msgs
                  if msg.startswith("Failed")]
    info_msgs = [(msg, val) for msg, val in info_msgs
                 if not msg.startswith("Failed")]
    max_len = max(len(msg) for msg, val in info_msgs)
    for message, value in error_msgs:
        print(f"[ERROR] {message.ljust(max_len + 1)}: {value}")
    if error_msgs:
        print()
    for message, value in info_msgs:
        print(f"[INFO] {message.ljust(max_len + 2)}: {value}")


local_version = datetime.strptime('2025-11-30', '%Y-%m-%d').date()
parser = ArgumentParser(
    formatter_class=lambda prog: RawDescriptionHelpFormatter(
        prog, max_help_position=34
    ),
    description=(
        f"{HUMBLE_DESC} | {HUMBLE_GIT} | v.{local_version}"
    )
)

parser.add_argument("-l", dest='lang', choices=['en', 'es'], help="Defines the\
 language for displaying errors and messages")

args = _Args()

if __name__ == "__main__":
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    l10n_main = get_l10n_content()
    code = pytest.main([__file__, "--tb=no", "-rA", "-q", "-v"])
    print_results()
    delete_temps()
    sys.exit()
