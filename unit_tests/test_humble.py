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
HUMBLE_DESC = "Unit tests for 'humble' (HTTP Headers Analyzer)"
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
TEST_CFGS = {
    'test_help': (['-h'], 'want to contribute?'),
    'test_brief': (['-u', None, '-b'], 'Analysis Grade:'),
    'test_cicd': (['-u', None, '-cicd'], 'Analysis Grade'),
    'test_detailed': (['-u', None], 'Analysis Grade:'),
    'test_export': (['-u', None, '-o', 'html'], 'HTML saved'),
    'test_fingerprint_stats': (['-f', 'Google'], 'Headers related to'),
    'test_input_file': (['-if', HUMBLE_INPUT_FILE, '-u', HUMBLE_INPUT_URL],
                        'Input:'),
    'test_l10n': (['-u', None, '-l', 'es'], 'Advertencias a revisar'),
    'test_response_headers': (['-u', None, '-r'], 'HTTP Response Headers'),
    'test_skipped_headers': (['-u', None, '-s', 'ETAG', 'NEL'],
                             'expressly excluded'),
    'test_updates': (['-v'], 'Keeping your security tools'),
    'test_user_agent': (['-u', None, '-ua', '4'], 'Selected the User-Agent'),
}
TEST_SUMMS = ('[test_python]', '[test_help]', '[test_brief]', '[test_cicd]',
              '[test_detailed]', '[test_export]', '[test_fingerprint_stats]',
              '[test_input_file]', '[test_l10]', '[test_skipped_headers]',
              '[test_updates]', '[test_user_agent]')


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


def get_l10n_content_old():
    l10n_path = path.join(HUMBLE_TESTS_DIR, HUMBLE_L10N_DIR, HUMBLE_L10N_DIR)
    with open(l10n_path, 'r', encoding='utf8') as l10n_content:
        return l10n_content.readlines()


def get_l10n_content():
    l10n_path = path.join(HUMBLE_TESTS_DIR, HUMBLE_L10N_DIR,
                          HUMBLE_L10N_FILE[1] if args.lang == 'es' else
                          HUMBLE_L10N_FILE[0])
    with open(l10n_path, 'r', encoding='utf8') as l10n_content:
        return l10n_content.readlines()


def print_results():
    print()
    summaries = [(tag, get_detail(tag, replace=True)) for tag in TEST_SUMMS]
    max_len = max(len(tag.strip("[]")) for tag, _ in summaries)
    for tag, detail in summaries:
        print(f"{tag.strip("[]").ljust(max_len + 1)}:{detail}")
    print()


def run_cmd(args):
    try:
        result = subprocess.run(
            [sys.executable, HUMBLE_MAIN_FILE] + args,
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
            errors="replace"
        )
        return result.stdout if result.returncode == 0 else ""
    except subprocess.TimeoutExpired:
        return ""


def run_test(test_name, args, expected_text):
    test_args = [url_test if arg is None else arg for arg in args]
    try:
        output = run_cmd(test_args)
    except subprocess.TimeoutExpired:
        pytest.fail(get_detail('[test_timeout]', replace=True))
    if expected_text not in output:
        pytest.fail(
            f"{get_detail('[test_expected]', replace=True)} '{expected_text}' \
{get_detail('[test_notfound]', replace=True)}")


def get_python_version(required_python=REQUIRED_PYTHON):
    local_python = sys.version_info
    return (local_python.major, local_python.minor) >= required_python


def test_python():
    if not get_python_version():
        pytest.fail(
            f"{get_detail('[test_pythonm]', replace=True)} "
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )


def test_help():
    run_test('help', *TEST_CFGS['test_help'])


def test_brief():
    run_test('brief', *TEST_CFGS['test_brief'])


def test_cicd():
    run_test('cicd', *TEST_CFGS['test_cicd'])


def test_detailed():
    run_test('detailed', *TEST_CFGS['test_detailed'])


def test_export():
    run_test('export', *TEST_CFGS['test_export'])


def test_fingerprint_stats():
    run_test('fingerprint_stats', *TEST_CFGS['test_fingerprint_stats'])


def test_input_file():
    run_test('input_file', *TEST_CFGS['test_input_file'])


def test_l10n():
    run_test('l10n', *TEST_CFGS['test_l10n'])


def test_response_headers():
    run_test('response_headers', *TEST_CFGS['test_response_headers'])


def test_skipped_headers():
    run_test('skipped_headers', *TEST_CFGS['test_skipped_headers'])


def test_updates():
    run_test('updates', *TEST_CFGS['test_updates'])


def test_user_agent():
    run_test('user_agent', *TEST_CFGS['test_user_agent'])


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


def delete_txt_file():
    msgs = []
    with contextlib.suppress(Exception):
        file = next(
            f for f in listdir(HUMBLE_TESTS_DIR) if f.lower().endswith('.txt')
        )
        txt_file = path.join(HUMBLE_TESTS_DIR, file)
        try:
            remove(txt_file)
            msgs.append((get_detail('[test_txt]', replace=True), txt_file))
        except Exception as e:
            msgs.append((get_detail('[test_ftxt]', replace=True),
                         f"({type(e).__name__}) {txt_file}"))
    return msgs


def delete_html_file():
    msgs = []
    with contextlib.suppress(Exception):
        file = next(
            f for f in listdir(HUMBLE_TESTS_DIR) if f.lower().endswith('.html')
        )
        html_file = path.join(HUMBLE_TESTS_DIR, file)
        try:
            remove(html_file)
            msgs.append((get_detail('[test_html]', replace=True), html_file))
        except Exception as e:
            msgs.append((get_detail('[test_fhtml]', replace=True),
                         f"({type(e).__name__}) {html_file}"))
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
        (get_detail('[test_remaining]', replace=True), url_test)
    ]
    info_msgs.extend(delete_humble_analysis(HUMBLE_TEMP_FILE))
    info_msgs.extend(delete_txt_file())
    info_msgs.extend(delete_html_file())
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


local_version = datetime.strptime('2025-09-27', '%Y-%m-%d').date()
parser = ArgumentParser(
    formatter_class=lambda prog: RawDescriptionHelpFormatter(
        prog, max_help_position=34
    ),
    description=(
        f"{HUMBLE_DESC} | {HUMBLE_GIT} | v.{local_version}"
    )
)

parser.add_argument('-u', type=str, dest='URL',
                    help="Scheme, host and port to use in the tests. E.g., \
https://google.com")
parser.add_argument("-l", dest='lang', choices=['es'], help="Defines the \
language for displaying errors and messages; if omitted, will be shown in \
English")

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
url_test = args.URL

if args.lang and not args.URL:
    print_error_detail('[test_elang]')

l10n_main = get_l10n_content()

if __name__ == "__main__":
    code = pytest.main([__file__, "--tb=no", "-rA", "-q", "-v"])
    print_results()
    delete_temps()
    sys.exit()
