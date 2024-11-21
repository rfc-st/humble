<h1><p align="center">humble</p></h1>
<h4><p align="center">A humble, and fast, security-oriented HTTP headers analyzer</p></h4>
<br />

<p align=center>
<a target="_blank" href="https://www.python.org/downloads/" title="Minimum Python version required to run this tool"><img src="https://img.shields.io/badge/Python-%3E%3D3.8-blue?labelColor=343b41"></a>
<a target="_blank" href="LICENSE" title="License of this tool"><img src="https://img.shields.io/badge/License-MIT-blue.svg?labelColor=343b41"></a>
<a target="_blank" href="https://github.com/rfc-st/humble/releases" title="Latest release of this tool"><img src="https://img.shields.io/github/v/release/rfc-st/humble?display_name=release&label=Latest%20Release&labelColor=343b41"></a>
<a target="_blank" href="https://github.com/rfc-st/humble/commits/master" title="Latest commit of this tool"><img src="https://img.shields.io/badge/Latest_Commit-2024--11--21-blue.svg?labelColor=343b41"></a>
<a target="_blank" href="https://github.com/rfc-st/humble/actions?query=workflow%3ACodeQL" title="Results of the last analysis of this tool with CodeQL"><img src="https://github.com/rfc-st/humble/workflows/CodeQL/badge.svg"></a>
<a target="_blank" href="https://pkg.kali.org/pkg/humble" title="Official tool in Kali Linux"><img src="https://img.shields.io/badge/Kali%20Linux-Tool-blue?labelColor=343b41"></a>
<br />
<a target="_blank" href="#" title="Featured on:"><img src="https://img.shields.io/badge/Featured%20on:-343b41"></a>
<a target="_blank" href="https://artemis-scanner.readthedocs.io/en/latest/search.html?q=humble&check_keywords=yes&area=default" title="Artemis vulnerability scanner"><img src="https://img.shields.io/badge/Artemis-blue"></a>
<a target="_blank" href="https://defectdojo.github.io/django-DefectDojo/integrations/parsers/file/humble/" title="DefectDojo"><img src="https://img.shields.io/badge/DefectDojo-blue"></a>
<a target="_blank" href="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/special-http-headers" title="HackTricks"><img src="https://img.shields.io/badge/HackTricks-blue"></a>
<a target="_blank" href="https://owasp.org/www-project-secure-headers/#div-technical" title="OWASP Secure Headers Project"><img src="https://img.shields.io/badge/OWASP-blue"></a>
<a target="_blank" href="https://www.bestpractices.dev/projects/9543" title="OpenSSF best practices analysis"><img src="https://www.bestpractices.dev/projects/9543/badge"></a>
<br />
<br />
<br />
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_fast.JPG" alt="A quick analysis with 'humble'!" width=90% height=90%>
<br />
<br />
<i>"千里之行，始於足下 - 老子"</i>
<br />
<i>("A journey of a thousand miles begins with a single step. - Lao Tzu")</i>
<br />
<br />
<i>"And if you don't keep your feet, there's no knowing where you might be swept off to. - Bilbo Baggins"</i>
<br />
<br />

### Table of contents

[Features](#features)<br />
[Screenshots](#screenshots)<br />
[Installation & Update](#installation--update)<br />
[Installation & Maintenance (Docker)](#installation--maintenance-docker)<br />
[Usage](#usage)<br />
[Advanced Usage](#advanced-usage)<br />
[Checks: Missing Headers](#checks-missing-headers)<br />
[Checks: Fingerprint Headers](#checks-fingerprint-headers)<br />
[Checks: Deprecated Headers and Insecure Values](#checks-deprecated-headersprotocols-and-insecure-values)<br />
[Checks: Empty Values](#checks-empty-values)<br />
[Guidelines included](#guidelines-included-to-enable-security-http-headers)<br />
[To-Do](#to-do)<br />
[Further Reading](#further-reading)<br />
[Contribute](#contribute)<br />
[Acknowledgements](#acknowledgements)<br />
[License](#license)<br />
<br />

## Features

:heavy_check_mark: 14 [checks](#checks-missing-headers) of missing HTTP response headers.<br />
:heavy_check_mark: 1186 [checks](#checks-fingerprint-headers) of fingerprinting through HTTP response headers.<br />
:heavy_check_mark: 113 [checks](#checks-deprecated-headersprotocols-and-insecure-values) of deprecated HTTP response headers/protocols or with insecure/wrong values.<br />
:heavy_check_mark: SSL/TLS checks: requires the **amazing** https://testssl.sh/.<br />
:heavy_check_mark: Browser support references for enabled HTTP security headers: provided by https://caniuse.com/.<br />
:heavy_check_mark: Two types of analysis: brief and detailed, along with HTTP response headers.<br />
:heavy_check_mark: Can exclude specific HTTP response headers from the analysis.<br />
:heavy_check_mark: Can export each analysis to CSV, HTML5, JSON, PDF 1.4 and TXT (and in a filename and path of your choice).<br />
:heavy_check_mark: Can analyze '_raw response files_': text files with HTTP response headers and values. Ex: curl option '<a href="https://curl.se/docs/manpage.html" target="_blank">--dump-header<a>'.<br />
:heavy_check_mark: Highlights <a href="https://developer.mozilla.org/en-US/docs/MDN/Writing_guidelines/Experimental_deprecated_obsolete" target="_blank">experimental<a> headers in each analysis.<br />
:heavy_check_mark: Each detailed analysis may include up to dozens of official links, references and technical articles.<br />
:heavy_check_mark: l10n: can display each analysis, the messages and almost all errors in English or Spanish.<br />
:heavy_check_mark: Saves each analysis, showing at the end the improvements or deficiencies in relation to the last one.<br />
:heavy_check_mark: Can display analysis statistics: either against a specific URL or all of them.<br />
:heavy_check_mark: Can display fingerprint statistics: either against a specific term or the Top 20.<br />
:heavy_check_mark: Code reviewed via <a href="https://pypi.org/project/bandit/" target="_blank">Bandit<a>, <a href="https://marketplace.visualstudio.com/items?itemName=ms-python.flake8" target="_blank">Flake8<a>, <a href="https://github.com/joerick/pyinstrument" target="_blank">pyinstrument<a>, <a href="https://marketplace.visualstudio.com/items?itemName=SonarSource.sonarlint-vscode" target="_blank">SonarLint<a>, <a href="https://marketplace.visualstudio.com/items?itemName=sourcery.sourcery" target="_blank">Sourcery<a> and <a href="https://pypi.org/project/vermin/" target="_blank">vermin<a>.<br />
:heavy_check_mark: Tested, one by one, on thousands of URLs.<br />
:heavy_check_mark: Tested on Docker 26.1, Kali Linux 2021.1, macOS 14.2.1 and Windows 10 20H2.<br />
:heavy_check_mark: <a href="https://github.com/rfc-st/humble/blob/master/additional/fingerprint.txt" target="_blank">Almost<a> all the code under one of the most permissive licenses: <a href="https://github.com/rfc-st/humble/blob/master/LICENSE" target="_blank">MIT<a>.<br />
:heavy_check_mark: Regularly <a href="https://github.com/rfc-st/humble/commits/master" target="_blank">updated</a>.<br />
:heavy_check_mark: Minimal <a href="https://github.com/rfc-st/humble/blob/master/requirements.txt" target="_blank">dependencies</a> required.<br />
:heavy_check_mark: Featured on <a href="https://owasp.org/www-project-secure-headers/#div-technical" target="_blank">OWASP</a>, <a href="https://pkg.kali.org/pkg/humble" target="_blank">Kali Linux</a>, <a href="https://artemis-scanner.readthedocs.io/en/latest/search.html?q=humble&check_keywords=yes&area=default">Artemis</a>, <a href="https://defectdojo.github.io/django-DefectDojo/integrations/parsers/file/humble/">DefectDojo</a> and <a href="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/special-http-headers">HackTricks</a>.<br />
:heavy_check_mark: Developed entirely in my spare time, no strings attached: feel <b>free</b> to try it out and integrate it into your projects!.<br />
:heavy_check_mark: And with the <a href="https://github.com/rfc-st/humble/blob/master/screenshots/humble_IA.PNG">approval</a> <a href="https://github.com/rfc-st/humble/blob/master/screenshots/humble_IA_4.JPG">of</a> <a href="https://github.com/rfc-st/humble/blob/master/screenshots/humble_IA_2.JPG">several</a> <a href="https://github.com/rfc-st/humble/blob/master/screenshots/humble_IA_3.JPG">AI</a> :smile:!.<br />

## Screenshots

.: (Windows) - Brief analysis.<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_b.PNG" alt="(Windows) - Brief analysis">
</p>
<br />
.: (Linux) - Brief analysis along with HTTP response headers.<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_br.PNG" alt="(Linux) - Brief analysis along with HTTP response headers">
</p>
<br />
.: (Linux) - Detailed analysis, in Spanish.<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble.PNG" alt="(Linux) - Detailed analysis in Spanish" width=70% height=70%>
</p>
<br />
.: (Linux) - Analysis of a "raw response file". <a href="https://github.com/rfc-st/humble/raw/master/samples/github_input_file.txt">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_input.PNG" alt="(Linux) - Analysis of a raw response file" width=70% height=70%>
</p>
<br />
.: (Linux) - SSL/TLS checks.<br />
<p></p>

```bash
Options used: -f -g -p -U -s --hints
```

<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_encryption_s.PNG" alt="(Linux) - SSL/TLS checks (requires https://testssl.sh/ and Linux/Unix client)" width=70% height=70%>
</p>
<br />
.: (Linux) - List of HTTP fingerprint headers based on a specific term.<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_fng.jpg" alt="(Linux) - List of HTTP fingerprint headers based on a specific term" width=70% height=70%>
</p>
<br />
.: (Linux) - Brief analysis saved as CSV. <a href="https://github.com/rfc-st/humble/raw/master/samples/humble_https_facebook_com_20241004_173935_en.csv">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_csv_s.PNG" alt="(Linux) - Brief analysis saved as CSV" width=70% height=70%>
</p>
<br />
.: (Windows) - Detailed analysis saved as PDF. <a href="https://github.com/rfc-st/humble/raw/master/samples/humble_https_cnn_com_20241031_182215_en.pdf">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_pdf_s.PNG" alt="(Windows) - Detailed analysis saved as PDF" width=70% height=70%>
</p>
<br />
.: (Linux) - Detailed analysis saved as HTML. <a href="https://htmlpreview.github.io/?https://github.com/rfc-st/humble/blob/master/samples/humble_https_facebook_com_20241116_200517_en.html">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_html_s.PNG" alt="(Linux) - Detailed analysis saved as HTML" width=70% height=70%>
</p>
<br />
.: (Linux) - Brief analysis saved as JSON. <a href="http://jsonblob.com/1307422565780545536">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_json_s.PNG" alt="(Linux) - Brief analysis saved as JSON" width=70% height=70%>
</p>
<br />
.: (Linux) - Analysis history file: Date, URL, Missing, Fingerprint, Deprecated/Insecure, Empty headers & Total warnings (the four previous totals).<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_ah.PNG" alt="(Linux) - Analysis history file: Date, URL, Missing, Fingerprint, Deprecated/Insecure, Empty headers & Total warnings (the four previous totals)">
</p>
<br />
.: (Linux) - Statistics of the analysis performed against a specific URL.<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_analytics.jpg" alt="(Linux) - Statistics of the analysis performed against a specific URL">
</p>
<br />
.: (Linux) - Statistics of the analysis performed against all URLs, in Spanish.<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_global_analytics.jpg" alt="(Linux) - Statistics of the analysis performed against all URLs in Spanish">
</p>
<br />

## Installation & Update

> [!NOTE]
> Python 3.8 or higher is required.

```bash
# Requirements: python3 and python3-pip
(Windows) https://www.python.org/downloads/windows/
(Linux) if not installed by default, install them via, e.g. Synaptic, apt, dnf, yum ...
(macOS) https://www.python.org/downloads/macos/

# Requirement: Git
(Windows) https://git-scm.com/download/win
(Linux) https://git-scm.com/download/linux
(macOS) https://git-scm.com/download/mac

# Setting up a virtual environment in Python (pending how to do it in Windows)
Note: '/home/bluesman/humble_venv' is a example path for the virtual environment.

$ python3 -m venv /home/bluesman/humble_venv
$ source /home/bluesman/humble_venv/bin/activate
$ cd /home/bluesman/humble_venv/
$ git clone https://github.com/rfc-st/humble.git
$ cd humble
$ pip3 install -r requirements.txt

# Good practice: deactivate the virtual environment after you have finished using 'humble'
$ deactivate

# Activate the virtual environment to analyze URLs again with 'humble'
$ cd /home/bluesman/humble_venv/
$ source /home/bluesman/humble_venv/bin/activate
$ cd humble

# Updating (weekly): activate the virtual environment and from 'humble' folder
$ git pull

# Updating (Release): activate the virtual environment, download the source code
# .zip file of the most recent Asset and unzip it in the 'humble' folder, overwriting files.
https://github.com/rfc-st/humble/releases
```

## Installation & Maintenance (Docker)

> [!NOTE]
> Python 3.8 will be used to [build](https://github.com/rfc-st/humble/blob/master/Dockerfile) the image.

```bash
# Install Docker, and make sure it's running.
# E.g. (Linux): https://www.kali.org/docs/containers/installing-docker-on-kali/
# E.g. (macOs): https://docs.docker.com/desktop/install/mac-install/
# E.g. (Windows): https://docs.docker.com/desktop/install/windows-install/

# Build the image, providing the TAG as the latest Release of 'humble': '1.42' in this example.
# https://github.com/rfc-st/humble/releases
# (Windows may require elevated console privileges)
$ docker build -t humble:1.42 .

# Run the analysis specifying the above TAG, along with the specific options for 'humble'.
# '-it', required: allocate a pseudo-TTY and keep the input interactive
# '-rm', required: automatically remove the container and associated anonymous volumes when it exits

# (Linux/macOS)
$ docker run -it --rm --name humble humble:1.42 /bin/bash -c "python3 humble.py -u https://facebook.com -b"

# (Windows)
$ docker run -it --rm --name humble humble:1.42 python3 humble.py -u https://facebook.com -b

# Removing (and untagging) previous images of 'humble' after upgrading to the latest release.
$ docker rmi humble:1.42
```

## Usage

```console
(Windows) $ py humble.py
(Linux)   $ python3 humble.py
(macOS)   $ python3 humble.py

usage: humble.py [-h] [-a] [-b] [-df] [-e [TESTSSL_PATH]] [-f [FINGERPRINT_TERM]] [-g] [-grd] [-if INPUT_FILE] [-l {es}] [-lic] [-o {csv,html,json,pdf,txt}] [-of OUTPUT_FILE]
                 [-op OUTPUT_PATH] [-r] [-s [SKIP_HEADERS ...]] [-u URL] [-ua USER_AGENT] [-v]

'humble' (HTTP Headers Analyzer) | https://github.com/rfc-st/humble | v.2024-11-01

options:
  -h, --help                  show this help message and exit
  -a                          Shows statistics of the performed analysis; if the '-u' parameter is ommited they will be global
  -b                          Shows overall findings; if omitted detailed ones will be shown
  -df                         Do not follow redirects; if omitted the last redirection will be the one analyzed
  -e [TESTSSL_PATH]           Shows TLS/SSL checks; requires the PATH of https://testssl.sh/
  -f [FINGERPRINT_TERM]       Shows fingerprint statistics; if 'FINGERPRINT_TERM' (e.g., 'Google') is omitted the top 20 results will be shown
  -g                          Shows guidelines for enabling security HTTP response headers on popular servers/services
  -grd                        Shows the checks to grade an analysis, along with advice for improvement
  -if INPUT_FILE              Analyzes 'INPUT_FILE': must contain HTTP response headers and values separated by ': '; E.g. 'server: nginx'.
  -l {es}                     Defines the language for displaying analysis, errors and messages; if omitted, will be shown in English
  -lic                        Shows the license for 'humble', along with permissions, limitations and conditions.
  -o {csv,html,json,pdf,txt}  Exports analysis to 'humble_scheme_URL_port_yyyymmdd_hhmmss_language.ext' file; csv/json will have a brief analysis
  -of OUTPUT_FILE             Exports analysis to 'OUTPUT_FILE'; if omitted the default filename of the parameter '-o' will be used
  -op OUTPUT_PATH             Exports analysis to 'OUTPUT_PATH'; must be absolute. If omitted the PATH of 'humble.py' will be used
  -r                          Shows HTTP response headers and a detailed analysis; '-b' parameter will take priority
  -s [SKIP_HEADERS ...]       Skips 'deprecated/insecure' and 'missing' checks for the indicated 'SKIP_HEADERS' (separated by spaces)
  -u URL                      Scheme, host and port to analyze. E.g. https://google.com
  -ua USER_AGENT              User-Agent ID from 'additional/user_agents.txt' file to use. '0' will show all and '1' is the default
  -v, --version               Checks for updates at https://github.com/rfc-st/humble

examples:
  -u URL -a                   Shows statistics of the analysis performed against the URL
  -u URL -b                   Analyzes URL and reports overall findings
  -u URL -b -o csv            Analyzes URL and exports overall findings to CSV format
  -u URL -l es                Analyzes URL and reports (in Spanish) detailed findings
  -u URL -o pdf               Analyzes URL and exports detailed findings to PDF format
  -u URL -o html -of test     Analyzes URL and exports detailed findings to HTML format and 'test' filename
  -u URL -o pdf -op D:/Tests  Analyzes URL and exports detailed findings to PDF format and 'D:/Tests' path
  -u URL -r                   Analyzes URL and reports detailed findings along with HTTP response headers
  -u URL -s ETag NEL          Analyzes URL and skips 'deprecated/insecure' and 'missing' checks for 'ETag' and 'NEL' headers
  -u URL -ua 4                Analyzes URL using the fourth User-Agent of 'additional/user_agents.txt' file
  -a -l es                    Shows statistics (in Spanish) of the analysis performed against all URLs
  -f Google                   Shows HTTP fingerprint headers related to the term 'Google'
```

## Advanced Usage

.: (Linux) - Show only the analysis summary.<br />

```
$ python3 humble.py -u https://www.spacex.com | grep -A 8 "\!." | sed $'1i \n'
```
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_adv_linux.jpg" alt="Show only the analysis summary (Linux)">


.: (Windows) - Show only the analysis summary, in Spanish. PowerShell >= 7 required.<br />

```
$ py humble.py -u https://www.spacex.com -l es | Select-String -Pattern '!.' -Context 1,8 -NoEmphasis
```
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_adv_windows.jpg" alt="Show only the analysis summary (Windows, in Spanish. PowerShell >= 7 required)">


.: (Linux) - Show only the URL, date and analysis summary.<br />

```
$ python3 humble.py -u https://www.spacex.com | grep -A7 -E "0. Info|\!." | grep -v "^\[1\." | sed 's/[--]//g' | sed -e '/./b' -e :n -e 'N;s/\n$//;tn' | sed $'1i \n'
```
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_adv_linux_2.jpg" alt="Show URL, date and the analysis summary (Linux)">


.: (Linux) - Show only the deprecated headers/protocols and insecure values.<br />

```
$ python3 humble.py -u https://www.spacex.com | sed -n '/\[3/,/^\[4/ { /^\[4/!p }' | sed '$d' | sed $'1i \n'
```
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_adv_linux_3.jpg" alt="Show only the deprecated headers/protocols and insecure values (Linux)">


.: (Linux) - Check for HTTP client errors (4XX).<br />

```
$ python3 humble.py -u https://my.prelude.software/demo/index.pl | grep -A1 -B5 'Note : \|Nota : ' --color=never
```
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_adv_linux_4.jpg" alt="Check for HTTP client errors (4XX) (Linux)">


.: (Linux) - Analyze multiple URLs and save the results as PDFs.<br />

```
$ datasets=('https://facebook.com' 'https://github.com' 'https://www.spacex.com'); for dataset in "${datasets[@]}"; do python3 humble.py -u "$dataset" -o pdf; done
```
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_adv_linux_5.jpg" alt="Analyze multiple URLs and save the results as PDFs">


## Checks: Missing Headers

Check <a href="https://github.com/rfc-st/humble/blob/master/additional/missing.txt">this</a> file.

## Checks: Fingerprint headers

Check <a href="https://github.com/rfc-st/humble/blob/master/additional/fingerprint.txt">this</a> file.

## Checks: Deprecated headers/protocols and insecure values

Check <a href="https://github.com/rfc-st/humble/blob/master/additional/insecure.txt">this</a> file.
> [!NOTE]
> _humble_ tries to be **strict**: both in checking HTTP response headers and their values; some of these headers may be <a href="https://developer.mozilla.org/en-US/docs/MDN/Writing_guidelines/Experimental_deprecated_obsolete">experimental</a> and you may not agree with all the results after analysis.
> 
> And that's **OK**! :smiley:; you should **never** blindly trust the results of security tools: there should be further work to decide whether the risk is non-existent, potential or real depending on the analyzed URL (its exposure, environment, etc).

## Checks: Empty values

Any HTTP response header.

## Guidelines included to enable security HTTP headers
* Amazon Web Services
* Apache HTTP Server
* Cloudflare
* LiteSpeed Web Server
* Microsoft Internet Information Services
* Nginx
* Node.js
* WordPress

## To-Do
- [ ] Add more Header/Value checks (only security-oriented)
- [ ] A new detailed analysis of all CSP directives/values (W3C Level <a href="https://www.w3.org/TR/CSP2/">2</a> & <a href="https://www.w3.org/TR/CSP3/">3</a>)
- [ ] Google Style Python Docstrings and documentation via <a href="https://www.sphinx-doc.org/en/master/">Sphinx</a>

## Further reading

https://caniuse.com/<br />
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers<br />
https://github.com/search?q=http+headers+analyze<br />
https://github.com/search?q=http+headers+secure<br />
https://github.com/search?q=http+headers+security<br />
https://owasp.org/www-project-secure-headers/<br />
https://securityheaders.com/<br />
https://scotthelme.co.uk/<br />
https://webtechsurvey.com/common-response-headers<br />
https://www.w3.org<br />

## Contribute
* Read <a href="https://github.com/rfc-st/humble/blob/master/CONTRIBUTING.md">this</a> first!.
* Report a <a href="https://github.com/rfc-st/humble/issues/new?assignees=&labels=&template=bug_report.md&title=">Bug</a>.
* Create a <a href="https://github.com/rfc-st/humble/issues/new?assignees=&labels=&template=feature_request.md&title=">Feature request</a>.
* Report a <a href="https://github.com/rfc-st/humble/security/policy">Security Vulnerability</a>.
* Send me your suggestions: rafael.fcucalon@gmail.com
* Or use that email to tell me about integrations of this tool in others!
* And to recommend me a good Blues! :sunglasses:

Thanks for downloading _'humble'_, for trying it and for your time!.

## Acknowledgements
* <a href="https://pypi.org/project/bandit/">Bandit</a>, <a href="https://github.com/tartley/colorama">colorama</a>, <a href="https://marketplace.visualstudio.com/items?itemName=ms-python.flake8">Flake8</a>, <a href="https://github.com/py-pdf/fpdf2">fpdf2</a>, <a href="https://github.com/joerick/pyinstrument">pyinstrument</a>, <a href="https://github.com/psf/requests">requests</a>, <a href="https://marketplace.visualstudio.com/items?itemName=SonarSource.sonarlint-vscode">SonarLint</a>, <a href="https://marketplace.visualstudio.com/items?itemName=sourcery.sourcery">Sourcery</a>, <a href="https://github.com/drwetter/testssl.sh">testssl.sh</a>, <a href="https://github.com/john-kurkowski/tldextract">tldextract</a> and <a href="https://pypi.org/project/vermin/">Vermin</a> authors/teams: you rock :metal:!.
* <a href="https://stackoverflow.com/users/8665970/aniket-navlur">Aniket Navlur</a> for <a href="https://stackoverflow.com/questions/19596750/is-there-a-way-to-clear-your-printed-text-in-python/52590238#52590238">this</a> gem.
* <a href="https://github.com/Azathothas">Azathothas</a> for reporting <a href="https://github.com/rfc-st/humble/issues/4">this</a> bug.
* <a href="https://github.com/bulaktm">bulaktm</a> for <a href="https://github.com/rfc-st/humble/issues/5">this</a> suggestion.
* <a href="https://github.com/confuciussayuhm">confuciussayuhm </a> for <a href="https://github.com/rfc-st/humble/pull/23">this</a> suggestion.
* <a href="https://github.com/cr4zyfish">cr4zyfish </a> for some of <a href="https://github.com/rfc-st/humble/issues/19">these</a> suggestions.
* <a href="https://parrotsec.org/team/">danterolle</a> for <a href="https://github.com/rfc-st/humble/commit/88a4e5e930083801b0ea2f4ab5f51730f72c9ebf">this</a>.
* <a href="https://www.linkedin.com/in/david-boronat/">David</a> for believing in the usefulness of this tool.
* <a href="https://www.linkedin.com/in/eduardo-boronat/">Eduardo</a> for the first Demo and the example <i>"(Linux) - Analyze multiple URLs and save the results as PDFs"</i>.
* <a href="https://github.com/gl4nce">gl4nce</a> for <a href="https://github.com/rfc-st/humble/issues/6">this</a> suggestion.
* İDRİS BUDAK for reporting the need to <a href="https://github.com/rfc-st/humble/commit/f85dd7811859fd2e403a0ecd848b21db20949841">this</a> check.
* <a href="https://www.linkedin.com/in/jdelamo/">Julio</a> for testing on macOS.
* <a href="https://github.com/kazet">kazet</a> for <a href="https://github.com/rfc-st/humble/pull/18">this</a> suggestion.
* <a href="https://github.com/manuel-sommer">manuel-sommer</a> for <a href="https://github.com/rfc-st/humble/issues/8">this</a>, <a href="https://github.com/rfc-st/humble/issues/10">this</a> and <a href="https://github.com/rfc-st/humble/issues/13">this</a>!.
* <a href="https://github.com/MikeAnast">MikeAnast</a> for <a href="https://github.com/rfc-st/humble/pull/22">several</a> suggestions.
* <a href="https://github.com/n3bojs4">n3bojs4</a>, <a href="https://github.com/ehlewis">ehlewis</a> and <a href="https://github.com/dkadev">dkadev</a> for <a href="https://github.com/rfc-st/humble/issues/7">this</a> and <a href="https://github.com/rfc-st/humble/pull/16">this</a>.
* <a href="https://www.kali.org/about-us/">sophie</a> for keeping 'humble' updated in <a href="https://www.kali.org/">Kali Linux</a> and for <a href="https://github.com/rfc-st/humble/commit/88a4e5e930083801b0ea2f4ab5f51730f72c9ebf">this</a>.
* <a href="https://github.com/stanley101music">stanley101music</a> for <a href="https://github.com/rfc-st/humble/issues/14">this</a>, <a href="https://github.com/rfc-st/humble/issues/15">this</a> and <a href="https://github.com/rfc-st/humble/issues/17">this</a>!.
* <a href="https://github.com/vincentcox">vincentcox</a> for <a href="https://github.com/rfc-st/humble/issues/19#issuecomment-2466643368">this</a> and <a href="https://github.com/rfc-st/humble/pull/24">this</a>.

## License

MIT © 2020-2024 Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)<br/>
Original Creator - Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)
