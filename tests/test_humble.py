#!/usr/bin/env python3
"""Classes, Functions and unit tests of `test_humble.py`."""

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
import importlib.util
import shutil
import subprocess
import sys
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from contextlib import suppress
from datetime import date, datetime
from os import fsync
from pathlib import Path
from platform import system
from typing import NamedTuple
from unittest.mock import patch

# Third-Party imports
import pytest
from requests.exceptions import RequestException

# To-Do: Enable code coverage in Windows
WIN_COV_ERROR = (
    "Code coverage is disabled on native Windows; try to run it through "
    "Cygwin, MSYS2 or Windows Subsystem for Linux."
)
if system().lower() == "windows" and any("--cov" in arg for arg in sys.argv):
    pytest.fail(WIN_COV_ERROR)

ASSERT_STR = ["error", "Error"]
EXTENDED_TAGS = ["[test_python_version]", "[test_missing_arguments]",
                 "[test_print_detail_s]", "[test_skip_file]",
                 "[test_response_headers_none]"]
HUMBLE_TESTS_DIR = Path(__file__).parent
HUMBLE_TEMP_HISTORY = HUMBLE_TESTS_DIR / "analysis_h.txt"
HUMBLE_TEMP_PREFIX = "humble_"
HUMBLE_TEST_FILES = {
    "CORNER_CASES": "headers_test_corner_cases.txt",
    "ALL_HEADERS": "headers_test_all.txt",
    "PERFECT_GRADE": "headers_test_grade_perfect.txt",
    "GRADE_A": "headers_test_grade_a.txt",
    "GRADE_B": "headers_test_grade_b.txt",
    "GRADE_C": "headers_test_grade_c.txt",
    "GRADE_D": "headers_test_grade_d.txt",
    "CLIENT_ERROR": "client_error_test.txt",
    "CSP_BASE64_NONCE": "headers_test_csp_base64_nonce.txt",
    "CSP_HEX_NONCE": "headers_test_csp_hex_nonce.txt",
    "NO_HEADERS": "headers_test_none.txt",
    "NO_SEC_HEADERS": "headers_test_nonesecurity.txt",
    "NONEXISTENT": "headers_test_nonexistent.txt",
    "PERFECT_OWASP": "headers_test_perfect_owasp.txt",
    "UNICODE": "headers_test_unicode.txt",
}
PATHS = {
    k: (HUMBLE_TESTS_DIR / v).resolve() for k, v in HUMBLE_TEST_FILES.items()
}
HUMBLE_DESC = "Basic unit tests for 'humble' (HTTP Headers Analyzer)"
HUMBLE_PROJECT_ROOT = HUMBLE_TESTS_DIR.parent.resolve()
HUMBLE_INPUT_DIR = HUMBLE_PROJECT_ROOT / "samples"
HUMBLE_INPUT_FILE = (HUMBLE_INPUT_DIR / "github_input_file.txt").resolve()
HUMBLE_HAR_FILE = (HUMBLE_INPUT_DIR / "github_edited.har").resolve()
HUMBLE_HAR_EMPTY_FILE = (HUMBLE_INPUT_DIR / "github_empty.har").resolve()
HUMBLE_HAR_MALFORMED_FILE = (
    HUMBLE_INPUT_DIR / "github_malformed.har"
).resolve()
HUMBLE_INPUT_TRAVERSAL = "../../../humbleinputtraversal/"
HUMBLE_L10N_DIR = HUMBLE_PROJECT_ROOT / "l10n"
HUMBLE_L10N_FILE = ("details.txt", "details_es.txt")
HUMBLE_MAIN_FILE = (HUMBLE_PROJECT_ROOT / "humble.py").resolve()
HUMBLE_OUTPUT_PATHS = ("home/tests/test",
                       "non_existent_path_for_humble/39332524")
HUMBLE_WRONG_TESTSSL_DIR = "/dev/"
PYTEST_CACHE_DIRS = [
    HUMBLE_TESTS_DIR / ".pytest_cache",
    HUMBLE_TESTS_DIR / "__pycache__",
    HUMBLE_PROJECT_ROOT / ".pytest_cache",
    HUMBLE_PROJECT_ROOT / "__pycache__",
]

# URLs to use in unit tests
TEST_URLS = ("https://github.com/rfc-st/humble",
             "https://httpbin.org/status/403", "https://github.com",
             "http://github.com", "https://humbletestresponseheaders.com",
             "https://en.wikipedia.org/", "https://microsoft.com",
             "http://127.0.0.1:65535", "https://tass.ru/",
             "https://google.com", "https://httpbin.org/delay/10",
             "https://httpbin.org/status/502", "http://10.255.255.1", # NOSONAR
             "ftp://google.com", "https://\u0442\u0435\u0441\u0442.ru",
             "https://httpbin.org/status/529",
             "https://httpbin.org/status/520",
             "http://nonexistenturl.com", "https://httpbin.org/status/432",
             "google.com", "https://", "https://google.com:443g")

REQUIRED_PYTHON_VERSION = (3, 11)

# Definition of unit tests; for each item:
#
# - Key: The name of the unit test:
#
#        Matches an entry in the files 'details.txt' and 'details_es.txt' in
#        '../l10n/' path to print its description.
#
# - Value: A tuple containing the command-line arguments for the test and the
#          expected string output.
TEST_CFGS = {
    "test_help": (["-h"], "want to contribute?"),
    "test_all_headers": (["-u", TEST_URLS[2], "-if", PATHS["ALL_HEADERS"]],
                         "Input:"),
    "test_unsafe_all_headers": (["-u", TEST_URLS[3], "-if",
                                 PATHS["ALL_HEADERS"]], "Input:"),
    "test_grade_perfect_headers": (["-u", TEST_URLS[4], "-if",
                                    PATHS["PERFECT_GRADE"]], "A+ ("),
    "test_grade_a_headers": (["-u", TEST_URLS[4], "-if", PATHS["GRADE_A"]],
                             "A ("),
    "test_grade_b_headers": (["-u", TEST_URLS[4], "-if", PATHS["GRADE_B"]],
                             "B ("),
    "test_grade_c_headers": (["-u", TEST_URLS[4], "-if", PATHS["GRADE_C"]],
                             "C ("),
    "test_grade_d_headers": (["-u", TEST_URLS[4], "-if", PATHS["GRADE_D"]],
                             "D ("),
    "test_grade_e_headers": (["-u", TEST_URLS[4], "-if",
                              PATHS["NO_SEC_HEADERS"]], "E ("),
    "test_brief_analysis": (["-u", TEST_URLS[9], "-b"], "Analysis Grade:"),
    "test_cicd_analysis": (["-u", TEST_URLS[9], "-cicd"], "Analysis Grade"),
    "test_cicd_error": (["-u", TEST_URLS[9], "cicd"], "Error"),
    "test_cicd_grade_error": (["-u", TEST_URLS[9], "-cicd", "g"], "Error"),
    "test_cicd_grade_pass": (["-u", TEST_URLS[9], "-cicd", "E"], "meets"),
    "test_cicd_grade_fail": (["-u", TEST_URLS[9], "-cicd", "A+"],
                             "does not meet"),
    "test_client_error_response": (["-u", TEST_URLS[1], "-if",
                                    PATHS["CLIENT_ERROR"]], "HTTP code"),
    "test_client_unsupported_error": (["-u", TEST_URLS[18]], "HTTP code"),
    "test_corner_cases": (["-u", TEST_URLS[2], "-if", PATHS["CORNER_CASES"]],
                          "Analysis Grade"),
    "test_corner_cases_brief": (["-u", TEST_URLS[2], "-if",
                                 PATHS["GRADE_D"], "-b"], "Analysis Grade"),
    "test_csp_base64_nonce": (["-u", TEST_URLS[2], "-if",
                               PATHS["CSP_BASE64_NONCE"]], "Analysis Grade"),
    "test_csp_hex_nonce": (["-u", TEST_URLS[2], "-if", PATHS["CSP_HEX_NONCE"]],
                           "Analysis Grade"),
    "test_detailed_analysis": (["-u", TEST_URLS[9]], "Analysis Grade:"),
    "test_export_all": (["-u", TEST_URLS[9], "-o", "all"], "Exported"),
    "test_export_all_brief": (["-u", TEST_URLS[9], "-o", "all", "-b"],
                              "Exported"),
    "test_export_all_responses": (["-u", TEST_URLS[9], "-o", "all", "-r"],
                                  "Exported"),
    "test_export_csv": (["-u", TEST_URLS[9], "-o", "csv"], "Analysis"),
    "test_export_extension": (["-u", TEST_URLS[9], "-o", "html", "-of",
                               ".html"], "Error:"),
    "test_export_html": (["-u", TEST_URLS[9], "-o", "html", "-r"], "Analysis"),
    "test_export_html_brief": (["-u", TEST_URLS[9], "-o", "html", "-b"],
                               "Analysis"),
    "test_export_html_csp": (["-u", TEST_URLS[2], "-o", "html", "-r"],
                             "Analysis"),
    "test_export_html_empty_headers": (["-u", TEST_URLS[9], "-if",
                                       PATHS["GRADE_D"], "-o", "html"],
                                       "Analysis"),
    "test_export_html_no_security_headers": (["-u", TEST_URLS[9], "-if",
                                             PATHS["NO_SEC_HEADERS"], "-o",
                                             "html"], "Analysis"),
    "test_export_json": (["-u", TEST_URLS[9], "-o", "json", "-r"], "Analysis"),
    "test_export_json_brief": (["-u", TEST_URLS[9], "-o", "json", "-b"],
                               "Analysis"),
    "test_export_json_empty_headers": (["-u", TEST_URLS[9], "-if",
                                        PATHS["GRADE_D"], "-o", "json"],
                                       "Analysis"),
    "test_export_json_l10n": (["-u", TEST_URLS[9], "-o", "json", "-l", "es"],
                              "Análisis"),
    "test_export_no_security_headers": (["-u", TEST_URLS[9], "-if",
                                         PATHS["NO_SEC_HEADERS"], "-o", "txt"],
                                        "Analysis"),
    "test_export_pdf": (["-u", TEST_URLS[9], "-o", "pdf"], "Analysis"),
    "test_export_pdf_color": (["-u", TEST_URLS[9], "-if",
                               PATHS["PERFECT_GRADE"], "-o", "pdf", "-b"],
                              "Analysis"),
    "test_export_pdf_empty_headers": (["-u", TEST_URLS[9], "-if",
                                       PATHS["GRADE_D"], "-o", "pdf"],
                                      "Analysis"),
    "test_export_pdf_no_security_headers": (["-u", TEST_URLS[9], "-if",
                                             PATHS["NO_SEC_HEADERS"], "-o",
                                             "pdf"], "Analysis"),
    "test_export_pdf_response_headers": (["-u", TEST_URLS[9], "-o", "pdf",
                                          "-r"], "Analysis"),
    "test_export_xlsx": (["-u", TEST_URLS[9], "-o", "xlsx"], "Analysis"),
    "test_export_xml": (["-u", TEST_URLS[9], "-o", "xml"], "Analysis"),
    "test_fingerprint_groups": (["-f"], "Top 20 groups"),
    "test_fingerprint_term": (["-f", "Google"], "Headers related to"),
    "test_fingerprint_term_no_results": (["-f", "TestingHumble"], "quote"),
    "test_file_access_errors": ([], "Error"),
    "test_global_statistics": (["-a"], "Empty headers"),
    "test_har_file": (["-u", TEST_URLS[2], "-if", HUMBLE_HAR_FILE],
                        "Input:"),
    "test_har_empty_file": (["-u", TEST_URLS[2], "-if", HUMBLE_HAR_EMPTY_FILE],
                        "Error:"),
    "test_har_malformed_file": (["-u", TEST_URLS[2], "-if",
                                 HUMBLE_HAR_MALFORMED_FILE], "Error:"),
    "test_http_exception": (["-u", TEST_URLS[13]], "scheme"),
    "test_input_file": (["-u", TEST_URLS[2], "-if", HUMBLE_INPUT_FILE],
                        "Input:"),
    "test_input_file_nonexistent": (["-u", TEST_URLS[2], "-if",
                                     PATHS["NONEXISTENT"]], "found"),
    "test_input_traversal": (["-u", TEST_URLS[9], "-op",
                              HUMBLE_INPUT_TRAVERSAL], "wrong:"),
    "test_invalid_output_path": (["-u", TEST_URLS[9], "-o", "csv", "-op",
                                  HUMBLE_MAIN_FILE], "Error:"),
    "test_l10n_analysis": (["-u", TEST_URLS[9], "-l", "es"],
                           "Advertencias a revisar"),
    "test_l10n_grades": (["-grd", "-l", "es"], "No te obsesiones"),
    "test_license": (["-lic"], "copyright"),
    "test_missing_output_format": (["-u", TEST_URLS[9], "-op",
                                    HUMBLE_OUTPUT_PATHS[0]], "Error:"),
    "test_no_headers": (["-u", TEST_URLS[4], "-if", PATHS["NO_HEADERS"]],
                        "contain"),
    "test_no_security_headers": (["-u", TEST_URLS[4], "-if",
                                  PATHS["NO_SEC_HEADERS"]], "are present"),
    "test_non_existent_output_path": (["-u", TEST_URLS[9], "-o", "txt", "-op",
                                       HUMBLE_OUTPUT_PATHS[1]], "Error:"),
    "test_outdated_humble": ([], "humble"),
    "test_owasp_compliance": (["-u", TEST_URLS[9], "-c"],
                              "non-recommended values"),
    "test_owasp_perfect_compliance": (["-u", TEST_URLS[9], "-c", "-if",
                                       PATHS["PERFECT_OWASP"]], "Nothing"),
    "test_proxy_unreachable": (["-u", TEST_URLS[9], "-p", TEST_URLS[7]],
                               "reachable"),
    "test_redirects": (["-u", TEST_URLS[9], "-df"], "Analysis Grade:"),
    "test_incomplete_request_headers": (
        ["-u", TEST_URLS[9], "-H", "Cache-Control:"], "malformed"),
    "test_malformed_request_headers": (
        ["-u", TEST_URLS[9], "-H", "Cache-Control no-cache"], "malformed"),
    "test_request_exception": (["-u", TEST_URLS[12]], "Request", 25),
    "test_request_headers": (
        ["-u", TEST_URLS[9], "-H", "Cache-Control: no-cache", "-H",
         "If-Modified-Since: Wed, 21 Oct 2020 00:00:00 GMT"],
        "Analysis Grade:",
    ),
    "test_request_invalid_header": (
        ["-u", TEST_URLS[9], "-H", ""], "least"),
    "test_response_headers": (["-u", TEST_URLS[9], "-r"],
                              "HTTP Response Headers"),
    "test_russian_block": (["-u", TEST_URLS[8]], "withdraws"),
    "test_russian_block_unicode": (["-u", TEST_URLS[14]], "withdraws"),
    "test_security_guidelines": (["-g"], "headers-in-wordpress"),
    "test_server_error_response": (["-u", TEST_URLS[11]], "Server"),
    "test_server_error_unusual": (["-u", TEST_URLS[15]], "Server"),
    "test_server_error_cdn": (["-u", TEST_URLS[16]], "Server"),
    "test_skipped_headers": (["-u", TEST_URLS[9], "-s", "ETAG", "NEL"],
                             "expressly excluded"),
    "test_testssl_error": ([], "Error"),
    "test_testssl_nopath": (["-u", TEST_URLS[9], "-e"], "requires"),
    "test_unicode_error": (["-u", TEST_URLS[9], "-if", PATHS["UNICODE"]],
                           "unicode"),
    "test_unreliable_analysis": (["-u", TEST_URLS[10]], "Not"),
    "test_unsupported_header": (["-u", TEST_URLS[9], "-s", "testhumbleheader"],
                                "testhumbleheader"),
    "test_unsupported_python_version": ([], "humble"),
    "test_updates": (["-v"], "Keeping your security tools"),
    "test_updates_error": (["-v"], "error"),
    "test_url_malformed": (["-u", TEST_URLS[21]], "Error"),
    "test_url_statistics": (["-u", TEST_URLS[5], "-if", PATHS["ALL_HEADERS"],
                             "-a"], "Empty headers"),
    "test_url_insufficient_statistics": (["-u", TEST_URLS[6], "-if",
                                          PATHS["ALL_HEADERS"], "-a"],
                                         "reliable"),
    "test_url_non_existent_statistics": (["-u", TEST_URLS[17], "-a"], "Error:"),
    "test_user_agent": (["-u", TEST_URLS[9], "-ua", "4"],
                        "Selected the User-Agent"),
    "test_user_agent_list": (["-ua", "0"], "source: "),
    "test_user_agent_only": (["-ua", "4"], "requires"),
    "test_user_agent_wrong": (["-u", TEST_URLS[9], "-ua", "999999"],
                              "available"),
    "test_valid_output_path": (["-u", TEST_URLS[9], "-o", "csv", "-op", "."],
                               "saved"),
    "test_testssl_uri_no_scheme": (["-u", TEST_URLS[19], "-e",
                                    HUMBLE_WRONG_TESTSSL_DIR], "scheme"),
    "test_testssl_uri_invalid_scheme": (["-u", TEST_URLS[13], "-e",
                                         HUMBLE_WRONG_TESTSSL_DIR],
                                        "unsupported"),
    "test_testssl_uri_no_host": (["-u", TEST_URLS[20], "-e",
                                  HUMBLE_WRONG_TESTSSL_DIR], "not valid"),
    "test_wrong_testssl": (["-u", TEST_URLS[9], "-e",
                            HUMBLE_WRONG_TESTSSL_DIR], "not found"),
}

TESTSSL_CMD = ["/non_existant_home_for_humble_test/testssl.sh", "-f", "-g",
               "-p", "-U", "-s", "--hints", "https://google.com"]

# Required to access and mock internal functions in 'humble.py'
_spec = importlib.util.spec_from_file_location("humble", HUMBLE_MAIN_FILE)
humble_module = importlib.util.module_from_spec(_spec)


class _Args:
    """Provides a default language to ensure messages load during testing."""

    lang = None


class PythonVersion(NamedTuple):
    """Python version fields for `test_unsupported_python_version`."""

    major: int
    minor: int


def get_detail(id_mode, *, replace=False):
    """Print a message, optionally removing newlines."""
    if match := next(
        (i for i, ln in enumerate(l10n_main) if ln.startswith(id_mode)),
        None,
    ):
        next_ln = l10n_main[match + 1]
        return next_ln.replace("\n", "") if replace else next_ln
    return None


def get_l10n_content():
    """Assign the lookup file to handle localized messages and errors."""
    if args.lang == "en":
        l10n_file = HUMBLE_L10N_FILE[0]
    elif args.lang == "es":
        l10n_file = HUMBLE_L10N_FILE[1]
    l10n_path = HUMBLE_TESTS_DIR / HUMBLE_L10N_DIR / l10n_file
    with l10n_path.open(encoding="utf-8") as l10n_content:
        return l10n_content.readlines()


def print_results():
    """Show the description of each unit test.

    Descriptions are retrieved via `get_detail` function using tags derived
    from `TEST_CFGS` keys plus extended ones for complex standalone unit tests.

    Tags correspond to entries in the following localization files:

    - `<HUMBLE_PROJECT_ROOT>/l10n/details.txt`
    - `<HUMBLE_PROJECT_ROOT>/l10n/details_es.txt`
    """
    print()
    dynamic_tags = [f"[{key}]" for key in TEST_CFGS]
    all_tags = dynamic_tags + EXTENDED_TAGS
    descriptions = [(tag, get_detail(tag, replace=True)) for tag in all_tags]
    max_len = max(len(tag.strip("[]")) for tag in all_tags)
    for tag, detail in descriptions:
        label = tag.strip("[]").ljust(max_len + 1)
        print(f"{label}:{detail}")
    print()


def run_test(args, expected_text, timeout=15):
    """Run unit test and check for expected console output."""
    test_args = [TEST_URLS[9] if a is None else a for a in args]

    try:
        result = subprocess.run(
            [sys.executable, HUMBLE_MAIN_FILE, *test_args],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        pytest.fail(get_detail("[test_timeout]", replace=True))
    parse_expected_text(output, expected_text)


def parse_expected_text(output, expected_text):
    """Validate output against expected results after each test."""
    exp_msg = get_detail("[test_expected]", replace=True)
    not_found_msg = get_detail("[test_notfound]", replace=True)
    if isinstance(expected_text, list | tuple | set):
        if all(e not in output for e in expected_text):
            pytest.fail(f"{exp_msg} {expected_text} {not_found_msg}")
        return
    if expected_text not in output:
        pytest.fail(f"{exp_msg} '{expected_text}' {not_found_msg}")


def test_humble_scenarios(cfg_key):
    """Execute dynamic validation tests managed via TEST_CFGS.

    Skips `test_wrong_testssl` on Windows due to the Unix-environment
    requirement (Cygwin, MSYS2, or Windows Subsystem for Linux) for testssl.sh
    """
    if cfg_key == "test_wrong_testssl" and system().lower() == "windows":
        pytest.skip("'test_wrong_testssl' skipped on Windows")
    run_test(*TEST_CFGS[cfg_key])


def pytest_generate_tests(metafunc):
    """Hooks into pytest configuration to generate standalone test entries.

    Tests in `TEST_CFGS` that have dedicated functions are ignored to avoid
    duplicate runs.
    """
    if "cfg_key" in metafunc.fixturenames:
        ignored_scenarios = {
            "test_cicd_error",
            "test_file_access_errors",
            "test_testssl_error",
            "test_updates_error",
            "test_outdated_humble",
            "test_unsupported_python_version",
        }
        target_keys = [k for k in TEST_CFGS if k not in ignored_scenarios]
        metafunc.parametrize("cfg_key", target_keys)


def pytest_runtest_logreport(report):
    """Clean up the displayed test node identity in console reports."""
    if "test_humble_scenarios[" in report.nodeid:
        start = report.nodeid.find("[") + 1
        end = report.nodeid.find("]")
        cfg_key = report.nodeid[start:end]
        report.nodeid = report.nodeid.split("::")[0] + f"::{cfg_key}"


def test_cicd_error(capsys):
    """Verify an error is displayed in CI/CD results."""
    with suppress(SystemExit):
        _spec.loader.exec_module(humble_module)
    humble_module.l10n_main = l10n_main
    humble_module.args = args
    with (
        patch.object(humble_module, "get_cicd_labels", side_effect=Exception),
        patch.object(humble_module, "get_detail", return_value=ASSERT_STR[1]),
    ):
        with pytest.raises(SystemExit) as wrapped_exit:
            humble_module.print_cicd_totals("any_file.tmp")
        assert wrapped_exit.value.code == 1
    captured = capsys.readouterr()
    assert ASSERT_STR[0] in captured.out.lower()


def test_file_access_errors(capsys):
    """Verify an error is displayed related to file access.

    Test whether the export or history files cannot be accessed or created.
    """
    with suppress(SystemExit):
        _spec.loader.exec_module(humble_module)
    humble_module.l10n_main, humble_module.args = l10n_main, args
    with patch("pathlib.Path.open", side_effect=OSError), \
         patch.object(humble_module, "delete_lines"):
        _, res = humble_module.validate_file_access("f.txt", context="history")
        assert res[0] in ("Not available", "No disponible")
        with patch.object(humble_module, "get_detail",
                          return_value=HUMBLE_TEMP_HISTORY):
            humble_module.validate_file_access("f.txt", context="basic")
            out = capsys.readouterr().out.lower()
            assert str(HUMBLE_TEMP_HISTORY).lower() in out
        with patch.object(humble_module, "get_detail",
                          return_value=ASSERT_STR[1]):
            with pytest.raises(SystemExit) as wrapped_exit:
                humble_module.validate_file_access("f.txt", context="export")
            assert wrapped_exit.value.code == 1
            assert ASSERT_STR[0] in capsys.readouterr().out.lower()


def test_testssl_error(capsys):
    """Verify an error is displayed for TLS/SSL check exceptions."""
    humble_module.l10n_main = l10n_main
    humble_module.args = args
    with patch.object(humble_module, "Popen", side_effect=OSError):
        with pytest.raises(SystemExit) as wrapped_exit:
            humble_module.testssl_analysis(TESTSSL_CMD)
        assert wrapped_exit.value.code == 1
    captured = capsys.readouterr()
    assert ASSERT_STR[0] in captured.out.lower()


def test_outdated_humble(capsys):
    """Verify an error is displayed related to outdated versions.

    Test whether the local version of `humble.py` is more than 30 days older
    than the GitHub version.
    """
    with suppress(SystemExit):
        _spec.loader.exec_module(humble_module)
    humble_module.l10n_main = l10n_main
    humble_module.args = args
    mock_github_version = date(2026, 3, 6)
    mock_local_version = date(2026, 1, 1)
    mock_days_diff = (mock_github_version - mock_local_version).days
    humble_module.check_updates_diff(mock_days_diff, mock_github_version,
                                     mock_local_version)
    captured = capsys.readouterr()
    assert mock_github_version.isoformat() in captured.out


def test_python_version():
    """Returns an error message related to Python version.

    Test whether the current Python version does not meet the minimum
    requirement.
    """
    if sys.version_info[:2] < REQUIRED_PYTHON_VERSION:
        pytest.fail(
            f"{get_detail('[test_pythonm]', replace=True)} "
            f"{sys.version_info.major}.{sys.version_info.minor}",
        )


def test_unsupported_python_version(capsys):
    """Verify an error is displayed related to Python version.

    Test whether the Python version is below the minimum supported version.
    """
    mocked_python_version = PythonVersion(3, 10)
    with suppress(SystemExit):
        _spec.loader.exec_module(humble_module)
    humble_module.l10n_main = l10n_main
    humble_module.args = args
    with patch("sys.version_info", mocked_python_version):
        with pytest.raises(SystemExit) as wrapped_exit:
            humble_module.check_python_version()
        assert wrapped_exit.value.code == 1
    captured = capsys.readouterr()
    assert "humble" in captured.out.lower()


def test_updates_error(capsys):
    """Verify an error message is displayed if the GitHub update check fails."""
    with suppress(SystemExit):
        _spec.loader.exec_module(humble_module)
    humble_module.l10n_main = l10n_main
    humble_module.args = args
    with patch("requests.get", side_effect=RequestException):
        with pytest.raises(SystemExit) as wrapped_exit:
            humble_module.check_updates(date(2026, 1, 1))
        assert wrapped_exit.value.code == 1
    captured = capsys.readouterr()
    assert ASSERT_STR[0] in captured.out.lower()


def test_missing_arguments():
    """Consolidates multiple checks for missing required arguments.

    Test multiple missing argument scenarios within a single unit test.
    """
    expected = ["Error:", "error:", "TXT", "HTML", "Analysis"]
    run_test(["-H", "Cache-Control: no-cache"], expected)
    run_test(["-if", "humble_test.txt", "-r"], expected)
    run_test(["-if", "humble_test.txt"], expected)
    run_test(["-l", "es"], expected)
    run_test(["-of", "humble_test.txt"], expected)
    run_test(["-of", "humble_test.html", "-o", "html", "-u", TEST_URLS[9]],
             expected)
    run_test(["-b"], expected)
    run_test(["-s"], expected)


def test_print_detail_s():
    """Verify `print_detail_s` functions returns `None` for unknown IDs.

    Ensures that if this function is called with an ID not present in
    `l10n_main` it returns `None` instead of crashing.
    """
    with suppress(SystemExit):
        _spec.loader.exec_module(humble_module)
    humble_module.l10n_main = l10n_main
    humble_module.args = args
    result = humble_module.print_detail_s("[nonexistent_id]")
    assert result is None


def test_proxy_wrong():
    """Consolidate missing argument checks across proxy-related features."""
    expected = ["Error:", "error:"]
    run_test(["-p", "https://"], expected)
    run_test(["-p", "http://127.0.0.1:test"], expected)


def test_skip_file(tmp_path, monkeypatch):
    """Verify 'humble.skip' parsing and the exclusion of its headers.

    Uses a modified copy of the file in a temporary directory; the
    original bundled 'humble.skip' is never modified.
    """
    with suppress(SystemExit):
        _spec.loader.exec_module(humble_module)
    humble_module.l10n_main, humble_module.args = l10n_main, args
    monkeypatch.chdir(tmp_path)
    assert humble_module.check_skip_file() == []
    skip_content = (HUMBLE_PROJECT_ROOT / "humble.skip").read_text(
        encoding="utf-8").replace("# Vary", "Vary").replace(
        "# X-XSS-Protection", "X-XSS-Protection")
    (tmp_path / "humble.skip").write_text(skip_content, encoding="utf-8")
    assert humble_module.check_skip_file() == ["Vary", "X-XSS-Protection"]
    run_test(["-u", TEST_URLS[5]], "excluded from this analysis")


def test_response_headers_none(capsys):
    """Verify the error shown when an analysis receives no response headers."""
    with suppress(SystemExit):
        _spec.loader.exec_module(humble_module)
    humble_module.l10n_main, humble_module.args = l10n_main, args
    args.output = None
    humble_module.headers = {}
    humble_module.print_response_headers()
    expected = get_detail("[no_enb_headers]", replace=True).strip()
    assert expected in capsys.readouterr().out


def delete_export_files(extension, ko_msg):
    """Remove temporary files from export unit tests."""
    msgs = []
    for export_file in HUMBLE_TESTS_DIR.iterdir():
        name_lower = export_file.name.lower()
        if (name_lower.startswith(HUMBLE_TEMP_PREFIX) and
                name_lower.endswith(extension)):
            try:
                export_file.unlink()
            except OSError as cleanup_err:
                error_detail = get_detail(ko_msg, replace=True)
                msgs.append((error_detail,
                             f"({type(cleanup_err).__name__}) {export_file}"))
    return msgs


def delete_pytest_caches(dir_path):
    """Remove `PYTEST_CACHE_DIRS` items following the run of unit tests."""
    msgs = []
    path_obj = Path(dir_path)
    if path_obj.is_dir():
        try:
            shutil.rmtree(path_obj)
        except OSError as rmtree_err:
            error_detail = get_detail("[test_fcache]", replace=True)
            msgs.append((error_detail,
                         f"({type(rmtree_err).__name__}) {path_obj}"))
    return msgs


def set_temp_content(current_time):
    """Define the files and folders to be purged upon completion of tests."""
    info_msgs = [(get_detail("[test_tests]", replace=True), current_time)]
    delete_extensions = [
        (".csv", "[test_fcsv]"),
        (".txt", "[test_ftxt]"),
        (".html", "[test_fhtml]"),
        (".json", "[test_fjson]"),
        (".json", "[test_fjson_brief]"),
        (".pdf", "[test_fpdf]"),
        (".xlsx", "[test_fxlsx]"),
        (".xml", "[test_fxml]"),
    ]
    for extension, ko_msg in delete_extensions:
        info_msgs.extend(delete_export_files(extension, ko_msg))
    for cache_dir in PYTEST_CACHE_DIRS:
        info_msgs.extend(delete_pytest_caches(cache_dir))
    return info_msgs


def delete_temp_content():
    """Remove the files and folders after all tests have been run."""
    current_time = datetime.now().astimezone().strftime("%Y/%m/%d - %H:%M:%S")
    info_msgs = set_temp_content(current_time)
    error_msgs = [(msg, val) for msg, val in info_msgs
                  if msg.startswith("Failed")]
    info_msgs = [(msg, val) for msg, val in info_msgs
                 if not msg.startswith("Failed")]
    max_msg_len = len(get_detail("[test_tests]", replace=True))
    for message, value in error_msgs:
        print(f"[ERROR] {message.ljust(max_msg_len + 1)}: {value}")
    if error_msgs:
        print()
    for message, value in info_msgs:
        print(f"[INFO] {message.ljust(max_msg_len + 1)}: {value}")


def cleanup_analysis_history():
    """Truncate the test analysis history file.

    After all unit tests complete, retaining only the first twenty-five lines to
    ensure file size stability while preserving data required for testing.
    """
    original_lines = []
    with suppress(Exception), \
         HUMBLE_TEMP_HISTORY.open(encoding="utf-8") as history_file:
        original_lines.extend(next(history_file) for _ in range(25))
    if not original_lines:
        return
    with suppress(Exception), \
         HUMBLE_TEMP_HISTORY.open("w", encoding="utf-8") as original_file:
        original_file.writelines(original_lines)
        original_file.flush()
        fsync(original_file.fileno())


local_version = date.fromisoformat("2026-07-13")
parser = ArgumentParser(
    formatter_class=lambda prog: RawDescriptionHelpFormatter(
        prog, max_help_position=34,
    ),
    description=(
        f"{HUMBLE_DESC} | {TEST_URLS[0]} | v.{local_version}"
    ),
)

parser.add_argument("-l", dest="lang", choices=["en", "es"], help="Defines the\
 language for displaying errors and messages")

args = _Args()
l10n_main = []


@pytest.fixture(scope="session", autouse=True) # noqa: vulture
def delete_temp_coverage():
    """Set up session globals and clean up temporary files after testing."""
    args.lang = "en"
    l10n_main[:] = get_l10n_content()
    yield
    cleanup_analysis_history()
    delete_temp_content()


if __name__ == "__main__":
    import io
    import re

    args = parser.parse_args(args=None if sys.argv[1:] else ["--help"])
    l10n_main = get_l10n_content()
    captured_output = io.StringIO()
    with patch("sys.stdout", captured_output):
        code = pytest.main([__file__, "--tb=no", "-rA", "-q", "-v", "-p",
                            "no:cacheprovider"])
    raw_text = captured_output.getvalue()
    cleaned_text = re.sub(r"test_humble_scenarios\[(.*?)\]", r"\1", raw_text)
    print(cleaned_text, end="")
    print_results()
    delete_temp_content()
    for cache_dir in PYTEST_CACHE_DIRS:
        delete_pytest_caches(cache_dir)
    sys.exit(code)
