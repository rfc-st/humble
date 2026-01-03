# Unit Tests

All the <a href="https://github.com/rfc-st/humble/#unit-tests" target="_blank">unit tests</a> should complete in less than one minute, under ideal conditions.
<br/>
<br/>
Unit tests are defined in the `TEST_CFGS` dictionary using the following structure:
<br/>

- Key: The name of the unit test.
- Value: A tuple containing the command-line arguments for the test and the expected console output.


Unit test descriptions are maintained in the `TEST_SUMMS` tuple. Each item is passed to the `get_detail function`, which retrieves the corresponding description from the localization files located at:
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
<span class="git-revision-date-localized-plugin git-revision-date-localized-plugin-datetime"><em>January 03, 2026</em></span>
</span>
</aside>