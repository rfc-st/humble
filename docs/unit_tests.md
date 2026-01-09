# Unit Tests

In ideal conditions, the entire unit test <a href="https://github.com/rfc-st/humble/#unit-tests" target="_blank">suite</a> is expected to complete in under one minute on Linux and under two minutes on Windows.
<br/>
<br/>
Unit tests are defined in the `TEST_CFGS` dictionary using the following structure:
<br/>

- **Key**: The name of the unit test.
- **Value**: A tuple containing the command-line arguments for the test and the expected console output.


Unit test descriptions are retrieved via `print_results` and `get_detail` functions, using tags derived from `TEST_CFGS` keys plus extended ones for complex standalone tests. Tags correspond to entries in the following localization files:
<br/>

- `<HUMBLE_PROJECT_ROOT>/l10n/details.txt`
- `<HUMBLE_PROJECT_ROOT>/l10n/details_es.txt`

<br/>
Functions and unit tests of **test_humble.py**, in alphabetical order (work in progress):

::: test_humble
<br />
<aside class="md-source-file">
<span class="md-source-file__fact">
Last updated on
<span class="git-revision-date-localized-plugin git-revision-date-localized-plugin-datetime"><em>January 09, 2026</em></span>
</span>
</aside>