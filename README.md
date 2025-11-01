<h1><p align="center">humble</p></h1>
<h4><p align="center">A humble, and fast, security-oriented HTTP headers analyzer</p></h4>
<br />

<p align=center>
<a target="_blank" href="https://devguide.python.org/versions/" title="Minimum Python version required to run this tool"><img src="https://img.shields.io/badge/Python-%3E%3D3.11-blue?labelColor=343b41"></a>
<a target="_blank" href="LICENSE" title="License of this tool"><img src="https://img.shields.io/badge/License-MIT-blue.svg?labelColor=343b41"></a>
<a target="_blank" href="https://github.com/rfc-st/humble/releases" title="Latest release of this tool"><img src="https://img.shields.io/github/v/release/rfc-st/humble?display_name=release&label=Latest%20Release&labelColor=343b41"></a>
<a target="_blank" href="https://github.com/rfc-st/humble/commits/master" title="Latest commit of this tool"><img src="https://img.shields.io/badge/Latest_Commit-2025--11--01-blue.svg?labelColor=343b41"></a>
<a target="_blank" href="https://pkg.kali.org/pkg/humble" title="Official tool in Kali Linux"><img src="https://img.shields.io/badge/Kali%20Linux-Tool-blue?labelColor=343b41"></a>
<br />
<a target="_blank" href="#" title="Featured on:"><img src="https://img.shields.io/badge/Featured%20on:-343b41"></a>
<a target="_blank" href="https://artemis-scanner.readthedocs.io/en/latest/search.html?q=humble&check_keywords=yes&area=default" title="Artemis vulnerability scanner"><img src="https://img.shields.io/badge/Artemis-blue"></a>
<a target="_blank" href="https://blog.csdn.net/gitblog_01072/article/details/141745712" title="Chinese Software Developer Network"><img src="https://img.shields.io/badge/CSDN-blue"></a>
<a target="_blank" href="https://docs.defectdojo.com/en/connecting_your_tools/parsers/file/humble/" title="DefectDojo vulnerability management tool"><img src="https://img.shields.io/badge/DefectDojo-blue"></a>
<a target="_blank" href="https://github.com/HackTricks-wiki/hacktricks/blob/master/src/network-services-pentesting/pentesting-web/special-http-headers.md" title="HackTricks"><img src="https://img.shields.io/badge/HackTricks-blue"></a>
<a target="_blank" href="https://headerscan.com/humble/" title="Security Header Scanner"><img src="https://img.shields.io/badge/HeaderScan-blue"></a>
<a target="_blank" href="https://www.linux-magazin.de/ausgaben/2022/11/tooltipps/" title="Linux Magazin"><img src="https://img.shields.io/badge/Linux%20Magazin-blue"></a>
<a target="_blank" href="https://merginit.com/blog/18082025-http-security-header-checker-tools" title="MerginIT"><img src="https://img.shields.io/badge/MerginIT-blue"></a>
<a target="_blank" href="https://owasp.org/www-project-secure-headers/#div-technical" title="OWASP Secure Headers Project"><img src="https://img.shields.io/badge/OWASP-blue"></a>
<a target="_blank" href="https://qiita.com/prograti/items/8eea5d60056f6df0d160#humble" title="Security Tools in Kali Linux"><img src="https://img.shields.io/badge/Qiita-blue"></a>
<br />
<a target="_blank" href="https://github.com/rfc-st/humble/blob/master/screenshots/humble_bandit.PNG" title="Results of the last analysis of this tool with bandit"><img src="https://img.shields.io/badge/bandit-passing-32bd50?labelColor=343b41"></a>
<a target="_blank" href="https://github.com/rfc-st/humble/actions/workflows/codeql-analysis.yml?query=workflow%3ACodeQL" title="CodeQL security analysis passed"><img src="https://github.com/rfc-st/humble/workflows/CodeQL/badge.svg"></a>
<a target="_blank" href="https://www.bestpractices.dev/projects/9543" title="OpenSSF best practices analysis"><img src="https://www.bestpractices.dev/projects/9543/badge"></a>
<a target="_blank" href="https://github.com/rfc-st/humble/blob/master/CODE_OF_CONDUCT.md" title="Code Of Conduct 3.0"><img src="https://img.shields.io/badge/Code_of_Conduct-3.0-blue.svg?labelColor=343b41"></a>
<br />
<br />
<br />
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_fast.PNG" alt="A quick analysis with 'humble'!">
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
[Installation & Update (Source code)](#installation--update-source-code)<br />
[Installation & Maintenance (Docker)](#installation--maintenance-docker)<br />
[Installation & Update (Kali Linux)](#installation--update-kali-linux)<br />
[Usage](#usage)<br />
[Advanced Usage (Linux)](#advanced-usage-linux)<br />
[Unit tests](#unit-tests)<br />
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

:heavy_check_mark: Covers 61 [enabled](#checks-enabled-headers) security-related HTTP response headers.<br />
:heavy_check_mark: 15 [checks](#checks-missing-headers) for missing security-related HTTP response headers (the ones I consider essential).<br />
:heavy_check_mark: 1239 [checks](#checks-fingerprint-headers) for fingerprinting through HTTP response headers.<br />
:heavy_check_mark: 155 [checks](#checks-deprecated-headersprotocols-and-insecure-values) for deprecated HTTP response headers/protocols or with insecure/wrong values.<br />
:heavy_check_mark: 28 [checks](https://github.com/rfc-st/humble/blob/master/additional/insecure.txt#L46-L73) related to Content Security Policy [Level 3](https://www.w3.org/TR/CSP3/).<br />
:heavy_check_mark: Can check for compliance with the OWASP <a href="https://owasp.org/www-project-secure-headers/#div-bestpractices" target="_blank">Secure Headers Project<a> Best Practices.<br />
:heavy_check_mark: Can exclude specific HTTP response headers from the analysis.<br />
:heavy_check_mark: Can analyze _raw response files_: text files with HTTP response headers and values. Ex: curl option '<a href="https://curl.se/docs/manpage.html#-D" target="_blank">--dump-header<a>'.<br />
:heavy_check_mark: Can export each analysis to CSV, CSS3 & HTML5, JSON, PDF 1.4, TXT, XLSX (Excel 2007 onwards) and XML; and in a filename and path of your choice.<br />
:heavy_check_mark: Can check for outdated SSL/TLS protocols and vulnerabilities: requires the **amazing** <a href="https://testssl.sh/" target="_blank">testssl.sh<a>.<br />
:heavy_check_mark: Can provide brief and detailed analysis along with HTTP response headers.<br />
:heavy_check_mark: Can use proxies for the analysis.<br />
:heavy_check_mark: Allows specifying custom HTTP request headers.<br />
:heavy_check_mark: Can output only analysis summary, totals and grade as JSON for <a href="https://www.redhat.com/en/topics/devops/what-is-ci-cd" target="_blank">CI/CD<a>.<br />
:heavy_check_mark: Shows browser support for enabled HTTP security headers, with data from <a href="https://caniuse.com/" target="_blank">Can I use<a>.<br />
:heavy_check_mark: Highlights <a href="https://developer.mozilla.org/en-US/docs/MDN/Writing_guidelines/Experimental_deprecated_obsolete" target="_blank">experimental<a> headers in each analysis.<br />
:heavy_check_mark: Provides hundreds of relevant links to security resources, standards and technical blogs based on each analysis.<br />
:heavy_check_mark: Supports displaying analysis, messages, and most errors in English or Spanish.<br />
:heavy_check_mark: Saves each analysis, highlighting improvements or deficiencies compared to the previous one.<br />
:heavy_check_mark: Can display analysis statistics for a specific URL or across all of them.<br />
:heavy_check_mark: Can display fingerprint statistics for a specific term or the Top 20.<br />
:heavy_check_mark: Can display guidelines for enabling security HTTP response headers on popular frameworks, servers, and services.<br />
:heavy_check_mark: Provides basic [unit tests](#unit-tests) to verify compatibility with your environment; requires <a href="https://pypi.org/project/pytest/" target="_blank">pytest<a>.<br />
:heavy_check_mark: Code reviewed via <a href="https://pypi.org/project/bandit/" target="_blank">Bandit<a>, <a href="https://marketplace.visualstudio.com/items?itemName=ms-python.flake8" target="_blank">Flake8<a>, <a href="https://github.com/joerick/pyinstrument" target="_blank">pyinstrument<a>, <a href="https://marketplace.visualstudio.com/items?itemName=SonarSource.sonarlint-vscode" target="_blank">SonarQube for IDE<a> and <a href="https://marketplace.visualstudio.com/items?itemName=sourcery.sourcery" target="_blank">Sourcery<a>.<br />
:heavy_check_mark: Tested, one by one, on thousands of URLs.<br />
:heavy_check_mark: Tested on Docker 26.1, Kali Linux 2021.1, macOS 14.2.1 and Windows 10 20H2.<br />
:heavy_check_mark: <a href="https://github.com/rfc-st/humble/blob/master/additional/fingerprint.txt" target="_blank">Almost<a> all the <a href="https://github.com/rfc-st/humble/blob/master/additional/owasp_best_practices.txt" target="_blank">code<a> available under one of the most permissive licenses: <a href="https://github.com/rfc-st/humble/blob/master/LICENSE" target="_blank">MIT<a>.<br />
:heavy_check_mark: Regularly <a href="https://github.com/rfc-st/humble/commits/master" target="_blank">updated</a>.<br />
:heavy_check_mark: Minimal <a href="https://github.com/rfc-st/humble/blob/master/requirements.txt" target="_blank">dependencies</a> required.<br />
:heavy_check_mark: Developed entirely in my spare time, <b>no strings attached</b>: feel free to try it out and integrate it into your projects!.<br />
:heavy_check_mark: And <a href="https://github.com/rfc-st/humble/blob/master/screenshots/humble_IA_6.jpg">with</a> <a href="https://github.com/rfc-st/humble/blob/master/screenshots/humble_IA.PNG">the</a> <a href="https://github.com/rfc-st/humble/blob/master/screenshots/humble_IA_4.JPG">approval</a> <a href="https://github.com/rfc-st/humble/blob/master/screenshots/humble_IA_2.JPG">of</a> <a href="https://github.com/rfc-st/humble/blob/master/screenshots/humble_IA_3.JPG">several</a> <a href="https://github.com/rfc-st/humble/blob/master/screenshots/humble_IA_5.JPG">AI</a> :smile:!.<br />

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
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble.PNG" alt="(Linux) - Detailed analysis in Spanish">
</p>
<br />
.: (Linux) - Analysis of a "raw response file". <a href="https://github.com/rfc-st/humble/raw/master/samples/github_input_file.txt">Example.</a><br />
<p></p>

```bash
Raw response file generation: curl --dump-header github_input_file.txt https://github.com
```

<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_input.PNG" alt="(Linux) - Analysis of a raw response file">
</p>
<br />
.: (Linux) - SSL/TLS checks.<br />
<p></p>

```bash
Options used: -f -g -p -U -s --hints
```

<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_encryption_s.PNG" alt="(Linux) - SSL/TLS checks (requires https://testssl.sh/ and Linux/Unix client)">
</p>
<br />
.: (Linux) - Custom HTTP request header.<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_request_header.PNG" alt="(Linux) - Custom HTTP request header">
</p>
<br />
.: (Linux) - Compliance with OWASP <a href="https://owasp.org/www-project-secure-headers/#div-bestpractices" target="_blank">'Secure Headers Project'<a> best practices.
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_compliance_owasp.PNG" alt="(Linux) - Compliance with OWASP 'Secure Headers Project' best practices">
</p>
<br />
.: (Windows) - JSON summary for CI/CD.<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_cicd.PNG" alt="(Windows) - JSON summary for CI/CD">
</p>
<br />
.: (Linux) - List of HTTP fingerprint headers based on a specific term.<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_fng.jpg" alt="(Linux) - List of HTTP fingerprint headers based on a specific term">
</p>
<br />
.: (Windows) - Guidelines for enabling security HTTP response headers.<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_guidelines.JPG" alt="(Windows) - Guidelines for enabling security HTTP response headers">
</p>
<br />
.: (Linux) - Brief analysis saved as CSV. <a href="https://github.com/rfc-st/humble/raw/master/samples/humble_https_facebook.com_20250426_191942_en.csv">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_csv_s.PNG" alt="(Linux) - Brief analysis saved as CSV">
</p>
<br />
.: (Windows) - Detailed analysis saved as PDF. <a href="https://github.com/rfc-st/humble/raw/master/samples/humble_https_samsung_com_20241122_213022_en.pdf">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_pdf_s.PNG" alt="(Windows) - Detailed analysis saved as PDF">
</p>
<br />
.: (Linux) - Detailed analysis saved as HTML. <a href="https://htmlpreview.github.io/?https://github.com/rfc-st/humble/blob/master/samples/humble_https_en.wikipedia.org_20250816_205605_en.html">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_html_s.PNG" alt="(Linux) - Detailed analysis saved as HTML">
</p>
<br />
.: (Linux) - Detailed analysis saved as JSON. <a href="https://github.com/rfc-st/humble/raw/master/samples/humble_https_google.com_20251005_205346_en.json">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_json_s.PNG" alt="(Linux) - Brief analysis saved as JSON">
</p>
<br />
.: (Linux) - Detailed analysis saved as XLSX. <a href="https://github.com/rfc-st/humble/raw/master/samples/humble_https_google.com_20250823_184837_en.xlsx">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_xlsx_s.PNG" alt="(Linux) - Brief analysis saved as XSLX">
</p>
<br />
.: (Linux) - Brief analysis saved as XML. <a href="https://github.com/rfc-st/humble/raw/master/samples/humble_https_en.wikipedia.org_20250711_175924_en.xml">Example.</a><br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_xml_s.PNG" alt="(Linux) - Brief analysis saved as XML">
</p>
<br />
.: (Linux) - Analysis history file: Date, URL, Enabled, Missing, Fingerprint, Deprecated/Insecure, Empty headers & Total warnings (the four previous totals).<br />
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
.: (Windows) - Checking for updates<br />
<p></p>
<p align="center">
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_update.PNG" alt="(Windows) - Checking for updates">
</p>
<br />


## Installation & update (Source code)

> [!NOTE]
> Python 3.11 or higher is required.

```bash
# Install python3 and python3-pip:
# (Windows) https://www.python.org/downloads/windows/
# (Linux) if not available, install them: e.g. Synaptic, apt, dnf, yum ...
# (macOS) https://www.python.org/downloads/macos/

# Install Git:
# (Windows) https://git-scm.com/download/win
# (Linux) https://git-scm.com/download/linux
# (macOS) https://git-scm.com/download/mac

# Set up a virtual environment (pending how to do it in Windows), download 'humble' and its dependencies
# '/home/bluesman/humble_venv' is a example path for the virtual environment
$ python3 -m venv /home/bluesman/humble_venv
$ source /home/bluesman/humble_venv/bin/activate
$ cd /home/bluesman/humble_venv/
$ git clone https://github.com/rfc-st/humble.git
$ cd humble
$ pip3 install -r requirements.txt

# Analyze! :). Linux and Windows examples
$ python3 humble.py -u https://google.com
$ py humble.py -u https://google.com

# Good practice: deactivate the virtual environment after you have finished using 'humble'
$ deactivate

# Activate the virtual environment to analyze again with 'humble'
$ cd /home/bluesman/humble_venv/
$ source /home/bluesman/humble_venv/bin/activate
$ cd humble

# Updating 'humble' (weekly): activate the virtual environment and from 'humble' folder
$ git pull

# Updating 'humble' (Release): activate the virtual environment, download the latest source code file
# and decompress it in the 'humble' folder, overwriting files
https://github.com/rfc-st/humble/releases
```

## Installation & maintenance (Docker)

> [!NOTE]
> Python 3.11 will be used to [build](https://github.com/rfc-st/humble/blob/master/Dockerfile) the image.

```bash
# Install Docker and ensure it is running:
# E.g. (Linux): https://www.kali.org/docs/containers/installing-docker-on-kali/
# E.g. (macOs): https://docs.docker.com/desktop/install/mac-install/
# E.g. (Windows): https://docs.docker.com/desktop/install/windows-install/

# Clone the repository or download the latest release
$ git clone https://github.com/rfc-st/humble.git
https://github.com/rfc-st/humble/releases

# Build the Docker image inside the 'humble' folder: providing the TAG as the latest Release of 'humble' (e.g. 1.53)
# https://github.com/rfc-st/humble/releases (On Windows, this may require running the terminal with admin privileges)
$ docker build -t humble:1.53 .

# Run the analysis specifying the above TAG, along with the specific options for 'humble':
# '-it', required: allocate a pseudo-TTY and keep input interactive.
# '-rm', required: automatically remove the container after it exits.

# (Linux/macOS)
# E.g. Analyze https://google.com (brief analysis)
$ docker run -it --rm --name humble humble:1.53 /bin/bash -c "python3 humble.py -u https://google.com -b"

# (Windows)
# E.g. Analyze https://google.com (detailed analysis)
$ docker run -it --rm --name humble humble:1.53 python3 humble.py -u https://google.com

# (Optional) Remove and untag the previous 'humble' image after upgrading
$ docker rmi humble:1.53
```

## Installation & update (Kali Linux)

> [!NOTE]
> Python 3.11 or higher is required.

```bash
# Verify that the output contains 'Homepage: https://github.com/rfc-st/humble'
$ apt show humble

# Install 'humble'
$ sudo apt install humble

# Analyze! :)
$ humble -u https://google.com

# Updating 'humble' (monthly)
$ sudo apt update
$ sudo apt install --only-upgrade humble
```

## Usage

```console
(Windows) $ py humble.py
(Linux)   $ python3 humble.py
(macOS)   $ python3 humble.py

usage: humble.py [-h] [-a] [-b] [-c] [-cicd] [-df] [-e [TESTSSL_PATH]] [-f [FINGERPRINT_TERM]] [-g] [-grd] [-H REQUEST_HEADER] [-if INPUT_FILE] [-l {es}] [-lic]
                 [-o {csv,html,json,pdf,txt,xlsx,xml}] [-of OUTPUT_FILE] [-op OUTPUT_PATH] [-p PROXY] [-r] [-s [SKIP_HEADERS ...]] [-u URL] [-ua USER_AGENT] [-v]

'humble' (HTTP Headers Analyzer) | https://github.com/rfc-st/humble | v.2025-10-10

options:
  -h, --help                           show this help message and exit
  -a                                   Shows statistics of the performed analysis; if the '-u' parameter is ommited they will be global
  -b                                   Shows overall findings; if omitted detailed ones will be shown
  -c                                   Checks URL response HTTP headers for compliance with OWASP 'Secure Headers Project' best practices
  -cicd                                Shows only analysis summary, totals and grade in JSON; suitable for CI/CD
  -df                                  Do not follow redirects; if omitted the last redirection will be the one analyzed
  -e [TESTSSL_PATH]                    Shows only TLS/SSL checks; requires the PATH of testssl (https://testssl.sh/)
  -f [FINGERPRINT_TERM]                Shows fingerprint statistics; if 'FINGERPRINT_TERM' (E.g., 'Google') is omitted the top 20 results will be shown
  -g                                   Shows guidelines for enabling security HTTP response headers on popular frameworks, servers and services
  -grd                                 Shows the checks to grade an analysis, along with advice for improvement
  -H REQUEST_HEADER                    Adds REQUEST_HEADER to the request; must be in double quotes and can be used multiple times, e.g. -H "Host: example.com"
  -if INPUT_FILE                       Analyzes 'INPUT_FILE': must contain HTTP response headers and values separated by ': '; E.g., 'server: nginx'
  -l {es}                              Defines the language for displaying analysis, errors and messages; if omitted, will be shown in English
  -lic                                 Shows the license for 'humble', along with permissions, limitations and conditions
  -o {csv,html,json,pdf,txt,xlsx,xml}  Exports analysis to 'humble_scheme_URL_port_yyyymmdd_hhmmss_language.ext' file
  -of OUTPUT_FILE                      Exports analysis to 'OUTPUT_FILE'; if omitted the default filename of the parameter '-o' will be used
  -op OUTPUT_PATH                      Exports analysis to 'OUTPUT_PATH'; must be absolute. If omitted the PATH of 'humble.py' will be used
  -p PROXY                             Use a proxy for the analysis. E.g., 'http://127.0.0.1:8080'. If no port is specified '8080' will be used
  -r                                   Shows HTTP response headers and a detailed analysis; '-b' parameter will take priority
  -s [SKIP_HEADERS ...]                Skips 'deprecated/insecure' and 'missing' checks for the indicated 'SKIP_HEADERS' (separated by spaces)
  -u URL                               Scheme, host and port to analyze. E.g., https://google.com or https://google.com:443
  -ua USER_AGENT                       User-Agent ID from 'additional/user_agents.txt' file to use. '0' will show all and '1' is the default
  -v, --version                        Checks for updates at https://github.com/rfc-st/humble

examples:
  -u URL -a                            Shows statistics of the analysis performed against the URL
  -u URL -b                            Analyzes the URL and reports overall findings
  -u URL -b -o csv                     Analyzes the URL and exports overall findings to CSV format
  -u URL -l es                         Analyzes the URL and reports (in Spanish) detailed findings
  -u URL -o pdf                        Analyzes the URL and exports detailed findings to PDF format
  -u URL -o html -of test              Analyzes the URL and exports detailed findings to HTML format and 'test' filename
  -u URL -o pdf -op D:/Tests           Analyzes the URL and exports detailed findings to PDF format and 'D:/Tests' path
  -u URL -p http://127.0.0.1:8080      Analyzes the URL using 'http://127.0.0.1:8080' as the proxy
  -u URL -r                            Analyzes the URL and reports detailed findings along with HTTP response headers
  -u URL -s ETag NEL                   Analyzes the URL and skips 'deprecated/insecure' and 'missing' checks for 'ETag' and 'NEL' headers
  -u URL -ua 4                         Analyzes the URL using the fourth User-Agent of 'additional/user_agents.txt' file
  -a -l es                             Shows statistics (in Spanish) of the analysis performed against all URLs
  -f Google                            Shows HTTP fingerprint headers related to the term 'Google'

want to contribute?:
  How to                               https://github.com/rfc-st/humble/blob/master/CONTRIBUTING.md
  Code of Conduct                      https://github.com/rfc-st/humble/blob/master/CODE_OF_CONDUCT.md
  Acknowledgements                     https://github.com/rfc-st/humble/#acknowledgements
```

## Advanced usage (Linux)

.: Show only the deprecated headers/protocols and insecure values.<br />

```
$ python3 humble.py -u https://en.wikipedia.org/ | sed -n '/\[4/,/^\[5/ { /^\[5/!p }' | sed '$d' | sed $'1i \n'
```
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_adv_linux_3.jpg" alt="Show only the deprecated headers/protocols and insecure values (Linux)">


.: Check for HTTP client errors (4XX).<br />

```
$ python3 humble.py -u https://my.prelude.software/demo/index.pl | grep -A1 -B5 'Note : \|Nota : ' --color=never
```
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_adv_linux_4.jpg" alt="Check for HTTP client errors (4XX) (Linux)">


.: Analyze multiple URLs and save the results as PDFs; thanks <a href="https://www.linkedin.com/in/eduardo-boronat/">Eduardo</a> for this example!.<br />

```
$ datasets=('https://facebook.com' 'https://github.com' 'https://www.spacex.com'); for dataset in "${datasets[@]}"; do python3 humble.py -u "$dataset" -o pdf; done
```
<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_adv_linux_5.jpg" alt="Analyze multiple URLs and save the results as PDFs">

## Unit tests
.: (Linux) - All tests passed successfully.<br />
```
$ cd <humble dir>
$ cd tests
$ python3 basic_tests.py -u <URL>
```

<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_basic_tests_ok.PNG" alt="(Linux) - All tests passed successfully">

.: (Windows) - Some tests failed, in Spanish.<br />
```
$ cd <humble dir>
$ cd tests
$ py basic_tests.py -u <URL> -l es
```

<img src="https://github.com/rfc-st/humble/blob/master/screenshots/humble_basic_tests_ko.PNG" alt="(Windows) - Some tests failed">

## Checks: enabled headers

Check <a href="https://github.com/rfc-st/humble/blob/master/additional/security.txt">this</a> file.

## Checks: missing headers

Check <a href="https://github.com/rfc-st/humble/blob/master/additional/missing.txt">this</a> file.

## Checks: fingerprint headers

Check <a href="https://github.com/rfc-st/humble/blob/master/additional/fingerprint.txt">this</a> file.

## Checks: deprecated headers/protocols and insecure values

Check <a href="https://github.com/rfc-st/humble/blob/master/additional/insecure.txt">this</a> file.
> [!NOTE]
> _humble_ tries to be **strict**: both in checking HTTP response headers and their values; some of these headers may be <a href="https://developer.mozilla.org/en-US/docs/MDN/Writing_guidelines/Experimental_deprecated_obsolete">experimental</a> and you may not agree with all the results after analysis.
> 
> And that's **OK**! :smiley:; you should **never** blindly trust the results of security tools: there should be further work to decide whether the risk is non-existent, potential or real depending on the analyzed URL (its exposure, environment, etc).

## Checks: empty values

Any HTTP response header.

## Guidelines included to enable security HTTP headers
* Amazon Web Services
* Angular
* Apache HTTP Server
* Cloudflare
* LiteSpeed Web Server
* Microsoft Internet Information Services
* Nginx
* Node.js
* Spring
* WordPress

## To-Do
- [ ] Add more Header/Value checks (only security-oriented)

## Further reading
* Web browsers' experimental features, roadmaps, technology previews and trials:<br />
<a href="https://chromestatus.com/roadmap">Google Chrome</a><br />
<a href="https://developer.microsoft.com/en-us/microsoft-edge/origin-trials/trials">Microsoft Edge</a><br />
<a href="https://wiki.mozilla.org/Origin_Trials">Mozilla Firefox</a><br />
<a href="https://blogs.opera.com/desktop/category/developer-2/">Opera</a><br />
<a href="https://webkit.org/blog/">Safari</a><br />

* Similar tools on GitHub:<br />
<a href="https://github.com/search?q=http+headers+analyze">'HTTP Headers Analyze'</a><br />
<a href="https://github.com/search?q=http+headers+secure">'HTTP Headers Secure'</a><br />
<a href="https://github.com/search?q=http+headers+security">'HTTP Headers Security'</a><br />
<a href="https://owasp.org/www-project-secure-headers/#div-technical">OWASP Secure Headers Project</a><br />

* References and standards:<br />
<a href="https://caniuse.com/">Can I use?</a><br />
<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers">Mozilla Developer Network</a><br />
<a href="https://www.w3.org/TR/">World Wide Web Consortium</a><br />

* Additional information:<br />
<a href="https://webtechsurvey.com/common-response-headers">Common response headers</a><br />
<a href="https://securityheaders.com/">Security Headers (HTTP response header analyzer)</a><br />
<a href="https://scotthelme.co.uk/">Scott Helme (Security Researcher)</a><br />

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
* <a href="https://pypi.org/project/bandit/">Bandit</a>, <a href="https://github.com/tartley/colorama">colorama</a>, <a href="https://marketplace.visualstudio.com/items?itemName=ms-python.flake8">Flake8</a>, <a href="https://github.com/py-pdf/fpdf2">fpdf2</a>, <a href="https://github.com/joerick/pyinstrument">pyinstrument</a>, <a href="https://github.com/rubik/radon">Radon</a>, <a href="https://github.com/psf/requests">requests</a>, <a href="https://marketplace.visualstudio.com/items?itemName=SonarSource.sonarlint-vscode">SonarQube for IDE</a>, <a href="https://marketplace.visualstudio.com/items?itemName=sourcery.sourcery" target="_blank">Sourcery<a>, <a href="https://github.com/drwetter/testssl.sh">testssl.sh</a>, <a href="https://github.com/john-kurkowski/tldextract">tldextract</a> and <a href="https://github.com/jmcnamara/XlsxWriter">xlsxwriter
</a> authors/teams: you rock :metal:!.
* <a href="https://github.com/1nabillion">1nabillion</a> for <a href="https://github.com/rfc-st/humble/issues/31">this</a>.
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
* <a href="https://github.com/ilLuSion-007">ilLuSion-007</a> for <a href="https://github.com/rfc-st/humble/pull/32">this</a>.
* <a href="https://github.com/javelinsoft">javelinsoft</a> for <a href="https://github.com/rfc-st/humble/commit/1f50e7109411b5b15c9a75ccb7760a8f16db7c65">this</a>.
* <a href="https://www.linkedin.com/in/jdelamo/">Julio</a> for testing on macOS and for <a href="https://github.com/rfc-st/humble/commit/e5f16f51dbb8b8e7d5d4b41797055899f399a69b">this</a> suggestion.
* <a href="https://github.com/kazet">kazet</a> for <a href="https://github.com/rfc-st/humble/pull/18">this</a> suggestion.
* <a href="https://github.com/manuel-sommer">manuel-sommer</a> for <a href="https://github.com/rfc-st/humble/issues/8">this</a>, <a href="https://github.com/rfc-st/humble/issues/10">this</a> and <a href="https://github.com/rfc-st/humble/issues/13">this</a>!.
* <a href="https://github.com/mfabbri">mfabbri</a> for <a href="https://github.com/rfc-st/humble/issues/25">this</a>.
* <a href="https://github.com/mgrottenthaler">mgrottenthaler</a> for <a href="https://github.com/rfc-st/humble/issues/27">this</a> and <a href="https://github.com/rfc-st/humble/issues/33">this</a>.
* <a href="https://github.com/MikeAnast">MikeAnast</a> for <a href="https://github.com/rfc-st/humble/pull/22">several</a> suggestions.
* <a href="https://github.com/multipartninja">multipartninja</a> for <a href="https://github.com/rfc-st/humble/issues/35">this</a>.
* <a href="https://github.com/n3bojs4">n3bojs4</a>, <a href="https://github.com/ehlewis">ehlewis</a> and <a href="https://github.com/dkadev">dkadev</a> for <a href="https://github.com/rfc-st/humble/issues/7">this</a> and <a href="https://github.com/rfc-st/humble/pull/16">this</a>.
* <a href="https://www.kali.org/about-us/">Sophie Brun</a> for keeping 'humble' updated in <a href="https://pkg.kali.org/pkg/humble">Kali Linux</a> and for <a href="https://github.com/rfc-st/humble/commit/88a4e5e930083801b0ea2f4ab5f51730f72c9ebf">this</a>.
* <a href="https://github.com/stanley101music">stanley101music</a> for <a href="https://github.com/rfc-st/humble/issues/14">this</a>, <a href="https://github.com/rfc-st/humble/issues/15">this</a> and <a href="https://github.com/rfc-st/humble/issues/17">this</a>!.
* <a href="https://github.com/vincentcox">vincentcox</a> for <a href="https://github.com/rfc-st/humble/issues/19#issuecomment-2466643368">this</a> and <a href="https://github.com/rfc-st/humble/pull/24">this</a>.

## License

MIT © 2020-2025 Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)<br/>
Original Creator - Rafa 'Bluesman' Faura (rafael.fcucalon@gmail.com)
