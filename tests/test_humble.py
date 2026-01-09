#!/usr/bin/env python3

# 'humble' (HTTP Headers Analyzer)
# https://humble.readthedocs.io/
# https://github.com/rfc-st/humble/
#
# MIT License
#
# Copyright (c) 2020-2026 Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)
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

# Standard Library imports
import sys
import shutil
import subprocess
from platform import system
from datetime import datetime
from contextlib import suppress
from os import listdir, path, remove, fsync
from argparse import ArgumentParser, RawDescriptionHelpFormatter

# Third-Party imports
import pytest

# To-Do: Enable code coverage in Windows
WIN_COV_ERROR = (
    "Code coverage is disabled on native Windows; try to run it through "
    "Cygwin, MSYS2 or Windows Subsystem for Linux."
)
if system().lower() == "windows" and any("--cov" in arg for arg in sys.argv):
    pytest.fail(WIN_COV_ERROR)

EXTENDED_TAGS = ['[test_python_version]', '[test_missing_arguments]']
HUMBLE_TESTS_DIR = path.dirname(__file__)
HUMBLE_TEMP_HISTORY = path.join(HUMBLE_TESTS_DIR, 'analysis_h.txt')
HUMBLE_TEMP_PREFIX = 'humble_'
HUMBLE_TEST_FILES = {
    'CORNER_CASES': 'headers_test_corner_cases.txt',
    'ALL_HEADERS': 'headers_test_all.txt',
    'PERFECT_GRADE': 'headers_test_grade_perfect.txt',
    'GRADE_A': 'headers_test_grade_a.txt',
    'GRADE_B': 'headers_test_grade_b.txt',
    'GRADE_C': 'headers_test_grade_c.txt',
    'GRADE_D': 'headers_test_grade_d.txt',
    'CLIENT_ERROR': 'client_error_test.txt',
    'CSP_HEX_NONCE': 'headers_test_csp_hex_nonce.txt',
    'NO_HEADERS': 'headers_test_none.txt',
    'NO_SEC_HEADERS': 'headers_test_nonesecurity.txt',
    'NONEXISTENT': 'headers_test_nonexistent.txt',
    'UNICODE': 'headers_test_unicode.txt',
}
PATHS = {k: path.abspath(path.join(HUMBLE_TESTS_DIR, v)) for k, v in
         HUMBLE_TEST_FILES.items()}
HUMBLE_DESC = "Basic unit tests for 'humble' (HTTP Headers Analyzer)"
HUMBLE_PROJECT_ROOT = path.abspath(path.join(HUMBLE_TESTS_DIR, '..'))
HUMBLE_INPUT_DIR = path.join(HUMBLE_PROJECT_ROOT, 'samples')
HUMBLE_INPUT_FILE = path.abspath(path.join(HUMBLE_INPUT_DIR,
                                           'github_input_file.txt'))
HUMBLE_INPUT_TRAVERSAL = '../../../humbleinputtraversal/'
HUMBLE_INVALID_EXPORT_FILE = 'non_existent_folder/humble_export_file_test'
HUMBLE_L10N_DIR = path.join(HUMBLE_PROJECT_ROOT, 'l10n')
HUMBLE_L10N_FILE = ('details.txt', 'details_es.txt')
HUMBLE_MAIN_FILE = path.abspath(path.join(HUMBLE_TESTS_DIR, '..', 'humble.py'))
HUMBLE_WRONG_TESTSSL_DIR = '/dev/'
PYTEST_CACHE_DIRS = [
    path.join(HUMBLE_TESTS_DIR, d)
    for d in ['__pycache__', '.pytest_cache']
]

# URLs to use in unit tests
TEST_URLS = ('https://github.com/rfc-st/humble',
             'https://httpbin.org/status/403', 'https://github.com',
             'http://github.com', 'https://humbletestresponseheaders.com',
             'https://en.wikipedia.org', 'https://microsoft.com',
             'http://127.0.0.1:65535', 'https://tass.ru/',
             'https://google.com', 'https://httpbin.org/delay/10',
             'https://httpbin.org/status/502', 'http://10.255.255.1',
             'ftp://google.com')

REQUIRED_PYTHON_VERSION = (3, 11)

# Definition of unit tests; for each item:
#
# - Key: The name of the unit test.
# - Value: A tuple containing the command-line arguments for the test and the
#          expected console output.
TEST_CFGS = {
    'test_help': (['-h'], 'want to contribute?'),
    'test_all_headers': (['-u', TEST_URLS[2], '-if', PATHS['ALL_HEADERS']],
                         'Input:'),
    'test_unsafe_all_headers': (['-u', TEST_URLS[3], '-if',
                                 PATHS['ALL_HEADERS'], ], 'Input:'),
    'test_grade_perfect_headers': (['-u', TEST_URLS[4], '-if',
                                    PATHS['PERFECT_GRADE']], 'A+ ('),
    'test_grade_a_headers': (['-u', TEST_URLS[4], '-if', PATHS['GRADE_A']],
                             'A ('),
    'test_grade_b_headers': (['-u', TEST_URLS[4], '-if', PATHS['GRADE_B']],
                             'B ('),
    'test_grade_c_headers': (['-u', TEST_URLS[4], '-if', PATHS['GRADE_C']],
                             'C ('),
    'test_grade_d_headers': (['-u', TEST_URLS[4], '-if', PATHS['GRADE_D']],
                             'D ('),
    'test_grade_e_headers': (['-u', TEST_URLS[4], '-if',
                              PATHS['NO_SEC_HEADERS']], 'E ('),
    'test_brief_analysis': (['-u', TEST_URLS[9], '-b'], 'Analysis Grade:'),
    'test_cicd_analysis': (['-u', TEST_URLS[9], '-cicd'], 'Analysis Grade'),
    'test_client_error_response': (['-u', TEST_URLS[1], '-if',
                                    PATHS['CLIENT_ERROR']], 'HTTP code'),
    'test_corner_cases': (['-u', TEST_URLS[2], '-if', PATHS['CORNER_CASES']],
                          'Analysis Grade'),
    'test_corner_cases_brief': (['-u', TEST_URLS[2], '-if',
                                 PATHS['GRADE_D'], '-b'], 'Analysis Grade'),
    'test_csp_hex_nonce': (['-u', TEST_URLS[2], '-if', PATHS['CSP_HEX_NONCE']],
                           'Analysis Grade'),
    'test_detailed_analysis': (['-u', TEST_URLS[9]], 'Analysis Grade:'),
    'test_export_csv': (['-u', TEST_URLS[9], '-o', 'csv'], 'CSV saved'),
    'test_export_html': (['-u', TEST_URLS[9], '-o', 'html', '-r'],
                         'HTML saved'),
    'test_export_html_brief': (['-u', TEST_URLS[9], '-o', 'html', '-b'],
                               'HTML saved'),
    'test_export_html_csp': (['-u', TEST_URLS[2], '-o', 'html', '-r'],
                             'HTML saved'),
    'test_export_html_empty_headers': (['-u', TEST_URLS[9], '-if',
                                       PATHS['GRADE_D'], '-o', 'html'],
                                       'HTML saved'),
    'test_export_json': (['-u', TEST_URLS[9], '-o', 'json', '-r'],
                         'JSON saved'),
    'test_export_json_brief': (['-u', TEST_URLS[9], '-o', 'json', '-b'],
                               'JSON saved'),
    'test_export_json_empty_headers': (['-u', TEST_URLS[9], '-if',
                                        PATHS['GRADE_D'], '-o', 'json'],
                                       'JSON saved'),
    'test_export_json_l10n': (['-u', TEST_URLS[9], '-o', 'json', '-l', 'es'],
                              'JSON guardado'),
    'test_export_no_security_headers': (['-u', TEST_URLS[9], '-if',
                                         PATHS['NO_SEC_HEADERS'], '-o', 'txt'],
                                        'TXT saved'),
    'test_export_pdf': (['-u', TEST_URLS[9], '-o', 'pdf'], 'PDF saved'),
    'test_export_pdf_color': (['-u', TEST_URLS[9], '-if',
                               PATHS['PERFECT_GRADE'], '-o', 'pdf', '-b'],
                              'PDF saved'),
    'test_export_pdf_empty_headers': (['-u', TEST_URLS[9], '-if',
                                       PATHS['GRADE_D'], '-o', 'pdf'],
                                      'PDF saved'),
    'test_export_xlsx': (['-u', TEST_URLS[9], '-o', 'xlsx'], 'XLSX saved'),
    'test_export_xml': (['-u', TEST_URLS[9], '-o', 'xml'], 'XML saved'),
    'test_fingerprint_groups': (['-f'], 'Top 20 groups'),
    'test_fingerprint_term': (['-f', 'Google'], 'Headers related to'),
    'test_fingerprint_term_no_results': (['-f', 'TestingHumble'], 'quote'),
    'test_global_statistics': (['-a'], 'Empty headers'),
    'test_http_exception': (['-u', TEST_URLS[13]], 'scheme'),
    'test_input_file': (['-u', TEST_URLS[2], '-if', HUMBLE_INPUT_FILE],
                        'Input:'),
    'test_input_file_nonexistent': (['-u', TEST_URLS[2], '-if',
                                     PATHS['NONEXISTENT']], 'found'),
    'test_input_traversal': (['-u', TEST_URLS[9], '-op',
                              HUMBLE_INPUT_TRAVERSAL], 'wrong:'),
    'test_invalid_file_path': (['-u', TEST_URLS[9], '-o', 'csv', '-of',
                                HUMBLE_INVALID_EXPORT_FILE], 'Unable'),
    'test_invalid_output_path': (['-u', TEST_URLS[9], '-o', 'csv', '-op',
                                  HUMBLE_MAIN_FILE], 'Error:'),
    'test_l10n_analysis': (['-u', TEST_URLS[9], '-l', 'es'],
                           'Advertencias a revisar'),
    'test_l10n_grades': (['-grd', '-l', 'es'], 'No te obsesiones'),
    'test_license': (['-lic'], 'copyright'),
    'test_no_headers': (['-u', TEST_URLS[4], '-if', PATHS['NO_HEADERS']],
                        'contain'),
    'test_no_security_headers': (['-u', TEST_URLS[4], '-if',
                                  PATHS['NO_SEC_HEADERS']], 'are present'),
    'test_owasp_compliance': (['-u', TEST_URLS[9], '-c'],
                              'non-recommended values'),
    'test_proxy_unreachable': (['-u', TEST_URLS[9], '-p', TEST_URLS[7]],
                               'reachable'),
    'test_redirects': (['-u', TEST_URLS[9], '-df'], 'Analysis Grade:'),
    'test_malformed_request_headers': (
        ['-u', TEST_URLS[9], '-H', 'Cache-Control no-cache'], 'malformed'),
    'test_request_exception': (['-u', TEST_URLS[12]], 'Request', 25),
    'test_request_headers': (
        ['-u', TEST_URLS[9], '-H', 'Cache-Control: no-cache', '-H',
         'If-Modified-Since: Wed, 21 Oct 2020 00:00:00 GMT'],
        'Analysis Grade:'
    ),
    'test_request_invalid_header': (
        ['-u', TEST_URLS[9], '-H', ''], 'least'),
    'test_response_headers': (['-u', TEST_URLS[9], '-r'],
                              'HTTP Response Headers'),
    'test_russian_block': (['-u', TEST_URLS[8]], 'withdraws'),
    'test_security_guidelines': (['-g'], 'headers-in-wordpress'),
    'test_server_error_response': (['-u', TEST_URLS[11]], 'Server'),
    'test_skipped_headers': (['-u', TEST_URLS[9], '-s', 'ETAG', 'NEL'],
                             'expressly excluded'),
    'test_unicode_error': (['-u', TEST_URLS[9], '-if', PATHS['UNICODE']],
                           'unicode'),
    'test_unreliable_analysis': (['-u', TEST_URLS[10]], 'reliable'),
    'test_unsupported_header': (['-u', TEST_URLS[9], '-s', 'testhumbleheader'],
                                'testhumbleheader'),
    'test_updates': (['-v'], 'Keeping your security tools'),
    'test_url_statistics': (['-u', TEST_URLS[5], '-if', PATHS['ALL_HEADERS'],
                             '-a'], 'Empty headers'),
    'test_url_insufficient_statistics': (['-u', TEST_URLS[6], '-if',
                                          PATHS['ALL_HEADERS'], '-a'],
                                         'reliable'),
    'test_user_agent': (['-u', TEST_URLS[9], '-ua', '4'],
                        'Selected the User-Agent'),
    'test_user_agent_list': (['-ua', '0'], 'source: '),
    'test_user_agent_only': (['-ua', '4'], 'requires'),
    'test_user_agent_wrong': (['-u', TEST_URLS[9], '-ua', '999999'],
                              'available'),
    'test_valid_output_path': (['-u', TEST_URLS[9], '-o', 'csv', '-op', '.'],
                               'saved'),
    'test_wrong_testssl': (['-u', TEST_URLS[9], '-e',
                            HUMBLE_WRONG_TESTSSL_DIR], 'not found'),
}


class _Args:
    URL = TEST_URLS[2]
    lang = None


def get_detail(id_mode, replace=False):
    """Print a message, optionally removing newlines"""
    for i, line in enumerate(l10n_main):
        if line.startswith(id_mode):
            return (l10n_main[i+1].replace('\n', '')) if replace else \
                l10n_main[i+1]


def get_l10n_content():
    """
    Assign the correct lookup file to handle localized messaging and error
    reporting
    """
    if args.lang == 'en':
        l10n_file = HUMBLE_L10N_FILE[0]
    elif args.lang == 'es':
        l10n_file = HUMBLE_L10N_FILE[1]

    l10n_path = path.join(HUMBLE_TESTS_DIR, HUMBLE_L10N_DIR, l10n_file)
    with open(l10n_path, 'r', encoding='utf8') as l10n_content:
        return l10n_content.readlines()


def print_results():
    """
    Shows the description of each unit test

    Descriptions are retrieved via `get_detail` function using tags derived
    from `TEST_CFGS` keys plus extended ones for complex standalone unit tests.

    Tags correspond to entries in the following localization files:

    - `<HUMBLE_PROJECT_ROOT>/l10n/details.txt`
    - `<HUMBLE_PROJECT_ROOT>/l10n/details_es.txt`
    """
    print()
    dynamic_tags = [f"[{key}]" for key in TEST_CFGS.keys()]
    all_tags = dynamic_tags + EXTENDED_TAGS
    descriptions = [(tag, get_detail(tag, replace=True)) for tag in all_tags]
    max_len = max(len(tag.strip("[]")) for tag in all_tags)
    for tag, detail in descriptions:
        label = tag.strip('[]').ljust(max_len + 1)
        print(f"{label}:{detail}")
    print()


def run_test(args, expected_text, timeout=15):
    """Run unit test and check for expected console output"""
    test_args = [TEST_URLS[9] if a is None else a for a in args]

    try:
        result = subprocess.run(
            [sys.executable, HUMBLE_MAIN_FILE] + test_args,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace"
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        pytest.fail(get_detail('[test_timeout]', replace=True))
    parse_expected_text(output, expected_text)


def parse_expected_text(output, expected_text):
    """
    Validates console output against expected results after each unit test
    """
    exp_msg = get_detail('[test_expected]', replace=True)
    not_found_msg = get_detail('[test_notfound]', replace=True)
    if isinstance(expected_text, (list, tuple, set)):
        if all(e not in output for e in expected_text):
            pytest.fail(f"{exp_msg} {expected_text} {not_found_msg}")
        return
    if expected_text not in output:
        pytest.fail(f"{exp_msg} '{expected_text}' {not_found_msg}")


def make_test_func(cfg_key):
    """
    Generate unit test execution function; skip `test_wrong_testssl` on Windows
    due to the Unix-environment requirement (Cygwin, MSYS2, or Windows
    Subsystem for Linux) for testssl.sh
    """
    def test_func():
        return run_test(*TEST_CFGS[cfg_key])

    if cfg_key == "test_wrong_testssl":
        test_func = pytest.mark.skipif(
            system().lower() == "windows",
            reason="'test_wrong_testssl' skipped on Windows"
        )(test_func)

    return test_func


for key in TEST_CFGS.keys():
    globals()[key] = make_test_func(key)


def test_python_version():
    """
    Returns an error message if the current Python version does not meet the
    minimum requirement
    """
    if sys.version_info[:2] < REQUIRED_PYTHON_VERSION:
        pytest.fail(
            f"{get_detail('[test_pythonm]', replace=True)} "
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )


def test_missing_arguments():
    """
    Consolidates multiple checks for missing required arguments into a single
    unit test
    """
    expected = ["Error:", "error:", "TXT", "HTML"]
    run_test(['-H', 'Cache-Control: no-cache'], expected)
    run_test(['-if', 'humble_test.txt', '-r'], expected)
    run_test(['-if', 'humble_test.txt'], expected)
    run_test(['-l', 'es'], expected)
    run_test(['-of', 'humble_test.txt'], expected)
    run_test(['-of', 'humble_test.html', '-o', 'html', '-u', TEST_URLS[9]],
             expected)
    run_test(['-b'], expected)
    run_test(['-s'], expected)


def test_proxy_wrong():
    """
    Consolidates multiple checks for missing required arguments across various
    proxy-related features
    """
    expected = ["Error:", "error:"]
    run_test(['-p', 'https://'], expected)
    run_test(['-p', 'http://127.0.0.1:test'], expected)


def delete_export_files(extension, ko_msg):
    """Remove temporary files from export unit tests"""
    msgs = []
    test_files = [
        f for f in listdir(HUMBLE_TESTS_DIR)
        if f.lower().startswith(HUMBLE_TEMP_PREFIX)
        and f.lower().endswith(extension)
    ]
    for file in test_files:
        export_file = path.join(HUMBLE_TESTS_DIR, file)
        try:
            remove(export_file)
        except Exception as e:
            msgs.append((get_detail(ko_msg, replace=True),
                         f"({type(e).__name__}) {export_file}"))
    return msgs


def delete_pytest_caches(dir_path):
    """
    Remove all `.pytest_cache` folders following the execution of all unit
    tests
    """
    msgs = []
    if path.isdir(dir_path):
        try:
            shutil.rmtree(dir_path)
        except Exception as e:
            msgs.append((get_detail('[test_fcache]', replace=True),
                         f"({type(e).__name__}) {dir_path}"))
    return msgs


def delete_pytestcov_caches(dir_path):
    """
    Remove all pytest cache folders following the completion of code coverage
    analysis
    """
    if path.isdir(dir_path):
        with suppress(Exception):
            shutil.rmtree(dir_path)


def set_temp_content(current_time):
    """
    Define the files and folders to be purged upon completion of the test suite
    """
    info_msgs = [(get_detail('[test_tests]', replace=True), current_time)]
    delete_extensions = [
        ('.csv', '[test_fcsv]'),
        ('.txt', '[test_ftxt]'),
        ('.html', '[test_fhtml]'),
        ('.json', '[test_fjson]'),
        ('.json', '[test_fjson_brief]'),
        ('.pdf', '[test_fpdf]'),
        ('.xlsx', '[test_fxlsx]'),
        ('.xml', '[test_fxml]'),
    ]
    for extension, ko_msg in delete_extensions:
        info_msgs.extend(delete_export_files(extension, ko_msg))
    for cache_dir in PYTEST_CACHE_DIRS:
        info_msgs.extend(delete_pytest_caches(cache_dir))
    return info_msgs


def delete_temp_content():
    """Remove the files and folders after all unit tests have been run"""
    current_time = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
    info_msgs = set_temp_content(current_time)
    error_msgs = [(msg, val) for msg, val in info_msgs
                  if msg.startswith("Failed")]
    info_msgs = [(msg, val) for msg, val in info_msgs
                 if not msg.startswith("Failed")]
    max_msg_len = len(get_detail('[test_tests]', replace=True))
    for message, value in error_msgs:
        print(f"[ERROR] {message.ljust(max_msg_len + 1)}: {value}")
    if error_msgs:
        print()
    for message, value in info_msgs:
        print(f"[INFO] {message.ljust(max_msg_len + 1)}: {value}")


def cleanup_analysis_history():
    """
    Truncate the test analysis history file after all unit tests complete,
    retaining only the first twenty-five lines to ensure file size stability
    while preserving data required for testing
    """
    original_lines = []

    with suppress(Exception):
        with open(HUMBLE_TEMP_HISTORY, "r", encoding="utf-8") as history_file:
            original_lines.extend(next(history_file) for _ in range(25))

    if not original_lines:
        return

    with suppress(Exception):
        with open(HUMBLE_TEMP_HISTORY, "w", encoding="utf-8") as original_file:
            original_file.writelines(original_lines)
            original_file.flush()
            fsync(original_file.fileno())


local_version = datetime.strptime('2026-01-09', '%Y-%m-%d').date()
parser = ArgumentParser(
    formatter_class=lambda prog: RawDescriptionHelpFormatter(
        prog, max_help_position=34
    ),
    description=(
        f"{HUMBLE_DESC} | {TEST_URLS[0]} | v.{local_version}"
    )
)

parser.add_argument("-l", dest='lang', choices=['en', 'es'], help="Defines the\
 language for displaying errors and messages")

args = _Args()


@pytest.fixture(scope="session", autouse=True)
def delete_temp_coverage():
    global l10n_main
    global args
    args.lang = "en"
    l10n_main = get_l10n_content()
    yield
    cleanup_analysis_history()
    delete_temp_content()


if __name__ == "__main__":
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    l10n_main = get_l10n_content()
    code = pytest.main([__file__, "--tb=no", "-rA", "-q", "-v", "-p",
                        "no:cacheprovider", "-o", "dont_write_bytecode=True"])
    print_results()
    delete_temp_content()
    sys.exit(0)
