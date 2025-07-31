#!/usr/bin/env python3

import os
import sys
import time
import pytest
import shutil
import contextlib
import subprocess
from datetime import datetime
from argparse import ArgumentParser, RawDescriptionHelpFormatter

SCRIPT_DIR = os.path.dirname(__file__)
ANALYSIS_FILE = [os.path.join(SCRIPT_DIR, 'analysis_h.txt')]
PYTEST_CACHES = [os.path.join(SCRIPT_DIR, d) for d in ['__pycache__',
                                                       '.pytest_cache']]
HUMBLE_DESC = "Unit tests for 'humble' (HTTP Headers Analyzer)"
HUMBLE_FILE = os.path.abspath(os.path.join(SCRIPT_DIR, '..', 'humble.py'))
HUMBLE_GIT = 'https://github.com/rfc-st/humble'
TEST_CFGS = {
    'test_help': (['-h'], 'want to contribute?'),
    'test_brief': (['-u', None, '-b'], 'Analysis Grade:'),
    'test_detailed': (['-u', None], 'Analysis Grade:'),
    'test_fingerprint_stats': (['-f', 'Google'], 'Headers related to'),
    'test_l10n': (['-u', None, '-l', 'es'], 'Advertencias a revisar'),
    'test_response_headers': (['-u', None, '-r'], 'HTTP Response Headers'),
    'test_skipped_headers': (['-u', None, '-s', 'ETAG', 'NEL'],
                             'expressly excluded'),
    'test_updates': (['-v'], 'Keeping your security tools'),
    'test_user_agent': (['-u', None, '-ua', '4'], 'Selected the User-Agent'),
}
TEST_SUMMS = {
    "test_python": "(no param); Verifies Python version is ≥ 3.11.",
    "test_help": "('-h' param); Confirms that the help message is displayed \
correctly.",
    "test_brief": "('-b' param); checks brief analysis output.",
    "test_detailed": "(no param); checks detailed analysis output.",
    "test_fingerprint_stats": "('-f Google' param); checks fingerprint match \
for 'Google'.",
    "test_l10n": "('-l es' param); checks detailed analysis in Spanish.",
    "test_response_headers": "('-r' param); checks display of HTTP response \
headers.",
    "test_skipped_headers": "('-s ETAG NEL' param); checks skipping of ETAG \
and NEL.",
    "test_updates": "('-v' param); checks for updates.",
    "test_user_agent": "('-ua 4' param); checks usage of 4th User-Agent.",
}


@pytest.fixture(scope="session", autouse=True)
def delete_prior_temps():
    for f in ANALYSIS_FILE:
        if os.path.isfile(f):
            with contextlib.suppress(Exception):
                os.remove(f)
    yield


def run_cmd(args):
    try:
        result = subprocess.run(
            [sys.executable, HUMBLE_FILE] + args,
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8"
        )
        return result.stdout if result.returncode == 0 else ""
    except subprocess.TimeoutExpired:
        return ""


def run_test(test_name, args, expected_text, case_sensitive=True):
    test_args = [url_test if arg is None else arg for arg in args]
    try:
        output = run_cmd(test_args)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{test_name} timed out")
    search_text = expected_text if case_sensitive else expected_text.lower()
    search_output = output if case_sensitive else output.lower()
    if search_text not in search_output:
        pytest.fail(f"Missing '{expected_text}' text")


def get_python_version(min_major=3, min_minor=11):
    v = sys.version_info
    return (v.major, v.minor) >= (min_major, min_minor)


def test_python():
    assert get_python_version(), (
        f"Python 3.11+ required, found {sys.version_info.major}."
        f"{sys.version_info.minor}"
    )


def test_help():
    run_test('help', *TEST_CFGS['test_help'], case_sensitive=False)


def test_brief():
    run_test('brief', *TEST_CFGS['test_brief'])


def test_detailed():
    run_test('detailed', *TEST_CFGS['test_detailed'])


def test_fingerprint_stats():
    run_test('fingerprint_stats', *TEST_CFGS['test_fingerprint_stats'])


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


def delete_humble_analysis(file_path, retries=5, delay=0.1):
    messages = []
    if not os.path.isfile(file_path):
        return messages
    for attempt in range(1, retries + 1):
        try:
            os.remove(file_path)
            time.sleep(delay)
            if not os.path.isfile(file_path):
                messages.append(("Successfully deleted 'humble' temp file",
                                 file_path))
                return messages
            messages.append((f"temp file still exists after attempt {attempt}",
                             file_path))
        except Exception as e:
            messages.append((f"Error deleting temp file: {file_path}", str(e)))
            break
    return messages


def delete_pytest_caches(dir_path):
    messages = []
    if os.path.isdir(dir_path):
        try:
            shutil.rmtree(dir_path)
            messages.append(("Successfully deleted pytest cache folder",
                             dir_path))
        except Exception as e:
            messages.append((f"Could not remove pytest cache folder: \
{dir_path}", str(e)))
    return messages


def delete_temps():
    timestamp = datetime.now().strftime("%Y/%m/%d - %H:%M:%S")
    info_messages = [
        ("Tests run at", timestamp),
        ("URL used for all the tests", url_test)
    ]
    for f in ANALYSIS_FILE:
        info_messages.extend(delete_humble_analysis(f))
    for cache_dir in PYTEST_CACHES:
        info_messages.extend(delete_pytest_caches(cache_dir))
    max_len = max(len(msg[0]) for msg in info_messages)
    for message, value in info_messages:
        print(f"[INFO] {message.ljust(max_len + 2)}: {value}")


local_version = datetime.strptime('2025-07-31', '%Y-%m-%d').date()
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

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
url_test = args.URL

if __name__ == "__main__":
    code = pytest.main([__file__, "--tb=no", "-rA", "-q", "-v"])
    max_len = max(len(name) for name in TEST_SUMMS)
    print()
    for name, desc in TEST_SUMMS.items():
        print(f"{name.ljust(max_len + 1)}: {desc}")
    print()
    delete_temps()
    sys.exit()
