# Unit Tests

In ideal conditions, the entire unit test <a href="https://github.com/rfc-st/humble/#unit-tests" target="_blank">suite</a> is expected to complete in less than a minute. Several tests rely on a loopback-only HTTP server that the suite starts automatically on an ephemeral port: no configuration is required, and those tests need no external network access.
<br/>
<br/>
The suite combines two kinds of unit tests:
<br/>

- **Scenario tests**: defined in the `TEST_CFGS` dictionary and executed as real `humble.py` processes via `test_humble_scenarios`, validating the console output of full command-line invocations.
- **Dedicated test functions**: standalone tests (e.g. `test_testssl_command`, `test_response_headers_none`) for cases requiring mocks, fixtures or direct access to `humble.py` internals.

Each `TEST_CFGS` entry uses the following structure:
<br/>

- **Key**: The name of the unit test.
- **Value**: A tuple containing the command-line arguments for the test and the expected console output.

Scenario keys already covered by a dedicated test function are excluded from parametrization via `pytest_generate_tests`, avoiding duplicate runs.
<br/>
<br/>
Unit test descriptions are retrieved via `print_results` and `get_detail` functions, using tags derived from `TEST_CFGS` keys plus the `EXTENDED_TAGS` entries for dedicated test functions. Tags correspond to entries in the following localization files:
<br/>

- `<HUMBLE_PROJECT_ROOT>/l10n/details.txt`
- `<HUMBLE_PROJECT_ROOT>/l10n/details_es.txt`

<br/>
::: test_humble
<br />
<aside class="md-source-file">
<span class="md-source-file__fact">
Last updated on
<span class="git-revision-date-localized-plugin git-revision-date-localized-plugin-datetime"><em>August 28, 2026</em></span>
</span>
</aside>