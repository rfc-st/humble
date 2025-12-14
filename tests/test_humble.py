#!/usr/bin/env python3

import sys
import pytest
import shutil
import subprocess
from platform import system
from datetime import datetime
from contextlib import suppress
from os import listdir, path, remove, fsync
from argparse import ArgumentParser, RawDescriptionHelpFormatter

HUMBLE_TESTS_DIR = path.dirname(__file__)
HUMBLE_TEMP_HISTORY = path.join(HUMBLE_TESTS_DIR, 'analysis_h.txt')
HUMBLE_TEMP_PREFIX = 'humble_'
PYTEST_CACHE_DIRS = [
    path.join(HUMBLE_TESTS_DIR, d)
    for d in ['__pycache__', '.pytest_cache']
]
HUMBLE_DESC = "Basic unit tests for 'humble' (HTTP Headers Analyzer)"
HUMBLE_PROJECT_ROOT = path.abspath(path.join(HUMBLE_TESTS_DIR, '..'))
HUMBLE_HEADERS_FILE = path.abspath(path.join(HUMBLE_TESTS_DIR,
                                             'headers_test_all.txt'))
HUMBLE_GRADE_PERFECT_FILE = path.abspath(
    path.join(HUMBLE_TESTS_DIR, 'headers_test_grade_perfect.txt'))
HUMBLE_GRADE_A_FILE = path.abspath(path.join(HUMBLE_TESTS_DIR,
                                             'headers_test_grade_a.txt'))
HUMBLE_GRADE_B_FILE = path.abspath(path.join(HUMBLE_TESTS_DIR,
                                             'headers_test_grade_b.txt'))
HUMBLE_GRADE_C_FILE = path.abspath(path.join(HUMBLE_TESTS_DIR,
                                             'headers_test_grade_c.txt'))
HUMBLE_GRADE_D_FILE = path.abspath(path.join(HUMBLE_TESTS_DIR,
                                             'headers_test_grade_d.txt'))
HUMBLE_CLIENTERROR_FILE = path.abspath(path.join(HUMBLE_TESTS_DIR,
                                                 'client_error_test.txt'))
HUMBLE_INPUT_DIR = path.join(HUMBLE_PROJECT_ROOT, 'samples')
HUMBLE_INPUT_FILE = path.abspath(path.join(HUMBLE_INPUT_DIR,
                                           'github_input_file.txt'))
HUMBLE_INPUT_TRAVERSAL = '../../../humbleinputtraversal/'
HUMBLE_L10N_DIR = path.join(HUMBLE_PROJECT_ROOT, 'l10n')
HUMBLE_L10N_FILE = ('details.txt', 'details_es.txt')
HUMBLE_MAIN_FILE = path.abspath(path.join(HUMBLE_TESTS_DIR, '..', 'humble.py'))
HUMBLE_NOSECHEADERS_FILE = path.abspath(path.join(HUMBLE_TESTS_DIR,
                                                  'headers_none_security.txt'))
TEST_URLS = ('https://github.com/rfc-st/humble',
             'https://www.chicagotribune.com/', 'https://github.com',
             'http://github.com', 'https://humbletestingnosecheaders.com',
             'https://en.wikipedia.org', 'https://microsoft.com',
             'http://127.0.0.1:65535', 'https://tass.ru/',
             'https://google.com')
HUMBLE_WRONG_TESTSSL_DIR = '/dev/'
REQUIRED_PYTHON = (3, 11)
TEST_CFGS = {
    'test_help': (['-h'], 'want to contribute?'),
    'test_all_headers': (['-if', HUMBLE_HEADERS_FILE, '-u', TEST_URLS[2]],
                         'Input:'),
    'test_unsafe_all_headers': (['-if', HUMBLE_HEADERS_FILE, '-u',
                                 TEST_URLS[3]], 'Input:'),
    'test_grade_perfect_headers': (['-if', HUMBLE_GRADE_PERFECT_FILE, '-u',
                                    TEST_URLS[4]], 'A+ ('),
    'test_grade_a_headers': (['-if', HUMBLE_GRADE_A_FILE, '-u', TEST_URLS[4]],
                             'A ('),
    'test_grade_b_headers': (['-if', HUMBLE_GRADE_B_FILE, '-u', TEST_URLS[4]],
                             'B ('),
    'test_grade_c_headers': (['-if', HUMBLE_GRADE_C_FILE, '-u', TEST_URLS[4]],
                             'C ('),
    'test_grade_d_headers': (['-if', HUMBLE_GRADE_D_FILE, '-u', TEST_URLS[4]],
                             'D ('),
    'test_grade_e_headers': (['-if', HUMBLE_NOSECHEADERS_FILE, '-u',
                              TEST_URLS[4]], 'E ('),
    'test_brief_analysis': (['-u', TEST_URLS[9], '-b'], 'Analysis Grade:'),
    'test_cicd_analysis': (['-u', TEST_URLS[9], '-cicd'], 'Analysis Grade'),
    'test_client_error_response': (['-if', HUMBLE_CLIENTERROR_FILE, '-u',
                                    TEST_URLS[1]], 'HTTP code'),
    'test_detailed_analysis': (['-u', TEST_URLS[9]], 'Analysis Grade:'),
    'test_export_csv': (['-u', TEST_URLS[9], '-o', 'csv'], 'CSV saved'),
    'test_export_html': (['-u', TEST_URLS[9], '-o', 'html', '-r'],
                         'HTML saved'),
    'test_export_json': (['-u', TEST_URLS[9], '-o', 'json', '-r'],
                         'JSON saved'),
    'test_export_json_brief': (['-u', TEST_URLS[9], '-o', 'json', '-b'],
                               'JSON saved'),
    'test_export_pdf': (['-u', TEST_URLS[9], '-o', 'pdf'], 'PDF saved'),
    'test_export_xlsx': (['-u', TEST_URLS[9], '-o', 'xlsx'], 'XLSX saved'),
    'test_export_xml': (['-u', TEST_URLS[9], '-o', 'xml'], 'XML saved'),
    'test_fingerprint_groups': (['-f'], 'Top 20 groups'),
    'test_fingerprint_term': (['-f', 'Google'], 'Headers related to'),
    'test_fingerprint_term_no_results': (['-f', 'TestingHumble'], 'quote'),
    'test_global_statistics': (['-a'], 'Empty headers'),
    'test_input_file': (['-if', HUMBLE_INPUT_FILE, '-u', TEST_URLS[2]],
                        'Input:'),
    'test_input_traversal': (['-u', TEST_URLS[9], '-op',
                              HUMBLE_INPUT_TRAVERSAL], 'wrong:'),
    'test_l10n_analysis': (['-u', TEST_URLS[9], '-l', 'es'],
                           'Advertencias a revisar'),
    'test_l10n_grades': (['-grd', '-l', 'es'], 'No te obsesiones'),
    'test_license': (['-lic'], 'copyright'),
    'test_no_security_headers': (['-if', HUMBLE_NOSECHEADERS_FILE, '-u',
                                  TEST_URLS[4]], 'are present'),
    'test_owasp_compliance': (['-u', TEST_URLS[9], '-c'],
                              'non-recommended values'),
    'test_proxy_unreachable': (['-u', TEST_URLS[9], '-p', TEST_URLS[7]],
                               'reachable'),
    'test_redirects': (['-u', TEST_URLS[9], '-df'], 'Analysis Grade:'),
    'test_request_headers': (
        ['-u', TEST_URLS[9], '-H', 'Cache-Control: no-cache', '-H',
         'If-Modified-Since: Wed, 21 Oct 2020 00:00:00 GMT'],
        'Analysis Grade:'
    ),
    'test_response_headers': (['-u', TEST_URLS[9], '-r'],
                              'HTTP Response Headers'),
    'test_russian_block': (['-u', TEST_URLS[8]], 'withdraws'),
    'test_security_guidelines': (['-g'], 'headers-in-wordpress'),
    'test_skipped_headers': (['-u', TEST_URLS[9], '-s', 'ETAG', 'NEL'],
                             'expressly excluded'),
    'test_unsupported_header': (['-u', TEST_URLS[9], '-s', 'testhumbleheader'],
                                'testhumbleheader'),
    'test_updates': (['-v'], 'Keeping your security tools'),
    'test_url_statistics': (['-if', HUMBLE_HEADERS_FILE, '-u', TEST_URLS[5],
                             '-a'], 'Empty headers'),
    'test_url_insufficient_statistics': (['-if', HUMBLE_HEADERS_FILE, '-u',
                                          TEST_URLS[6], '-a'], 'reliable'),
    'test_user_agent': (['-u', TEST_URLS[9], '-ua', '4'],
                        'Selected the User-Agent'),
    'test_user_agent_list': (['-ua', '0'], 'source: '),
    'test_wrong_testssl': (['-u', TEST_URLS[9], '-e',
                            HUMBLE_WRONG_TESTSSL_DIR], 'not found'),
}
TEST_SUMMS = ('[test_help]', '[test_all_headers]', '[test_unsafe_all_headers]',
              '[test_grade_perfect_headers]', '[test_grade_a_headers]',
              '[test_grade_b_headers]', '[test_grade_c_headers]',
              '[test_grade_d_headers]', '[test_grade_e_headers]',
              '[test_brief_analysis]', '[test_cicd_analysis]',
              '[test_client_error_response]', '[test_detailed_analysis]',
              '[test_export_csv]', '[test_export_html]', '[test_export_json]',
              '[test_export_json_brief]', '[test_export_pdf]',
              '[test_export_xlsx]', '[test_export_xml]',
              '[test_fingerprint_groups]', '[test_fingerprint_term]',
              '[test_fingerprint_term_no_results]', '[test_global_statistics]',
              '[test_input_file]', '[test_input_traversal]',
              '[test_l10n_analysis]', '[test_l10n_grades]', '[test_license]',
              '[test_no_security_headers]', '[test_owasp_compliance]',
              '[test_proxy_unreachable]', '[test_proxy_wrong]',
              '[test_redirects]', '[test_request_headers]',
              '[test_response_headers]', '[test_russian_block]',
              '[test_security_guidelines]', '[test_skipped_headers]',
              '[test_unsupported_header]', '[test_updates]',
              '[test_url_statistics]', '[test_url_insufficient_statistics]',
              '[test_user_agent]', '[test_user_agent_list]',
              '[test_wrong_testssl]', '[test_python_version]',
              '[test_missing_parameters]')


class _Args:
    URL = TEST_URLS[2]
    lang = None


def get_detail(id_mode, replace=False):
    """Print a message, optionally removing newlines"""
    for i, line in enumerate(l10n_main):
        if line.startswith(id_mode):
            return (l10n_main[i+1].replace('\n', '')) if replace else \
                l10n_main[i+1]


def print_error_detail(id_mode):
    """
    Print an error message, optionally removing previously printed lines on
    the console, and terminate execution
    """
    print(f"\n{get_detail(id_mode, replace=True)}")
    sys.exit()


def get_l10n_content():
    """
    Define the literal file to use, to print messages and errors, based on
    the language provided
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
    Print the summary results for all defined tests
    """
    print()
    summaries = [(tag, get_detail(tag, replace=True)) for tag in TEST_SUMMS]
    max_len = max(len(tag.strip("[]")) for tag, _ in summaries)
    for tag, detail in summaries:
        print(f"{tag.strip("[]").ljust(max_len + 1)}:{detail}")
    print()


def run_test(args, expected_text, timeout=5):
    """Run each of the available tests"""
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
    # sourcery skip: invert-any-all
    """Checks if expected text is present in each test"""
    if isinstance(expected_text, (list, tuple, set)):
        if not any(e in output for e in expected_text):
            pytest.fail(
                f"{get_detail('[test_expected]', replace=True)} "
                f"{expected_text} {get_detail('[test_notfound]',
                                              replace=True)}"
            )
        return

    if expected_text not in output:
        pytest.fail(
            f"{get_detail('[test_expected]', replace=True)} '{expected_text}' "
            f"{get_detail('[test_notfound]', replace=True)}"
        )


def make_test_func(cfg_key):
    """
    Generate a function to run the available tests. 'test_wrong_testssl' test
    is skipped in Windows because testssl.sh, for that platform, requires
    running it under Cygwin, MSYS2, or Windows Subsystem for Linux
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
    Returns an error message if the installed Python version is less than the
    minimum required
    """
    if sys.version_info[:2] < REQUIRED_PYTHON:
        pytest.fail(
            f"{get_detail('[test_pythonm]', replace=True)} "
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )


def test_missing_arguments():
    """
    Performs multiple checks, under a single test, associated with missing
    parameters required for certain functionalities
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
    Performs checks associated with parameters required for proxy-related
    functionalities
    """
    expected = ["Error:", "error:"]
    run_test(['-p', 'https://'], expected)
    run_test(['-p', 'http://127.0.0.1:test'], expected)


def delete_export_files(extension, ok_msg, ko_msg):
    """
    Delete all files associated with export tests
    """
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
            msgs.append((get_detail(ok_msg, replace=True), export_file))
        except Exception as e:
            msgs.append((get_detail(ko_msg, replace=True),
                         f"({type(e).__name__}) {export_file}"))
    return msgs


def delete_pytest_caches(dir_path):
    """
    Delete the directories associated with the pytest cache after all tests
    have been run.
    """
    msgs = []
    if path.isdir(dir_path):
        try:
            shutil.rmtree(dir_path)
            msgs.append((get_detail('[test_cache]', replace=True), dir_path))
        except Exception as e:
            msgs.append((get_detail('[test_fcache]', replace=True),
                         f"({type(e).__name__}) {dir_path}"))
    return msgs


def delete_pytestcov_caches(dir_path):
    """
    Delete the directories associated with the pytest caches after code
    coverage has been run.
    """
    if path.isdir(dir_path):
        with suppress(Exception):
            shutil.rmtree(dir_path)


def set_temp_content(current_time):
    """
    Define the files and directories to be deleted after all tests have been
    run
    """
    info_msgs = [
        (get_detail('[test_tests]', replace=True), current_time),
        (get_detail('[test_input]', replace=True), TEST_URLS[2]),
        (get_detail('[test_remaining]', replace=True), TEST_URLS[9])
    ]
    delete_extensions = [
        ('.csv', '[test_csv]', '[test_fcsv]'),
        ('.txt', '[test_txt]', '[test_ftxt]'),
        ('.html', '[test_html]', '[test_fhtml]'),
        ('.json', '[test_json]', '[test_fjson]'),
        ('.json', '[test_json_brief]', '[test_fjson_brief]'),
        ('.pdf', '[test_pdf]', '[test_fpdf]'),
        ('.xlsx', '[test_xlsx]', '[test_fxlsx]'),
        ('.xml', '[test_xml]', '[test_fxml]'),
    ]
    for extension, ok_msg, ko_msg in delete_extensions:
        info_msgs.extend(delete_export_files(extension, ok_msg, ko_msg))
    for cache_dir in PYTEST_CACHE_DIRS:
        info_msgs.extend(delete_pytest_caches(cache_dir))
    return info_msgs


def delete_temp_content():
    """Delete the files and directories after all tests have been run"""
    current_time = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
    info_msgs = set_temp_content(current_time)
    error_msgs = [(msg, val) for msg, val in info_msgs
                  if msg.startswith("Failed")]
    info_msgs = [(msg, val) for msg, val in info_msgs
                 if not msg.startswith("Failed")]
    all_msgs = [
        '[test_tests]', '[test_input]', '[test_remaining]', '[test_temp]',
        '[test_csv]', '[test_txt]', '[test_html]', '[test_json]',
        '[test_json_brief]', '[test_pdf]', '[test_xlsx]', '[test_xml]',
        '[test_cache]'
    ]
    max_msg_len = max(len(get_detail(key, replace=True)) for key in all_msgs)
    for message, value in error_msgs:
        print(f"[ERROR] {message.ljust(max_msg_len + 1)}: {value}")
    if error_msgs:
        print()
    for message, value in info_msgs:
        print(f"[INFO] {message.ljust(max_msg_len + 1)}: {value}")


def cleanup_analysis_history():
    """
    Once all tests have been completed, delete all lines from the test analysis
    history file except for the first twenty-five (which are necessary for some
    of the tests), ensuring that the size of this file remains stable over
    time.
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


local_version = datetime.strptime('2025-12-13', '%Y-%m-%d').date()
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
    for cache_dir in PYTEST_CACHE_DIRS:
        delete_pytestcov_caches(cache_dir)


if __name__ == "__main__":
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    l10n_main = get_l10n_content()
    code = pytest.main([__file__, "--tb=no", "-rA", "-q", "-v"])
    print_results()
    delete_temp_content()
    sys.exit()
