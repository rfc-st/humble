# humble.py
Welcome to **humble.py** documentation!.

## What is *humble.py*?
It is a humble, and **fast**, security-oriented HTTP response headers analyzer.

It is the result of many weekends, in my **spare time** (for six years, and hopefully for many more), dedicated to questioning, studying, researching, and programming on standards, exploits, regulations, and vulnerabilities; learning and reading countless articles related to HTTP response headers and their security.

It started as a small personal project, with no intention of becoming important. Over time, it was accepted into <a href="https://pkg.kali.org/pkg/humble" target="_blank">Kali Linux</a>, has been referenced in blogs and social media and has been used as a basis and reference for final degree projects.

Requires Python <a href="https://www.python.org/downloads/" target="_blank">3.11</a> or higher along with a few <a href="https://github.com/rfc-st/humble/blob/master/requirements.txt" target="_blank">dependencies</a> and <a href="https://testssl.sh/" target="_blank">testssl.sh</a> (if you want to analyze obsolete SSL/TLS protocols and vulnerabilities of a URL).

## What does it offer?
In my experience, HTTP response headers are consistently overlooked in security audits. Yet after several years in cybersecurity, I've seen firsthand how proper header configuration can prevent serious vulnerabilities and avoid problems before they escalate.

**humble.py** delivers quick, honest security analysis of HTTP response headers, identifying configuration deficiencies while providing actionable technical references and best practices.

You have nothing to lose by trying it; are you up for it? :).

And, if I may, a word of advice: use the information provided by this tool wisely. I believe there is *far* more merit in helping others, learning and teaching than in attacking, harming or taking advantage. Please, do not just be a <a href="https://en.wikipedia.org/wiki/Script_kiddie" target="_blank">Script kiddie</a>: if this really interests you learn, research and become a Security Analyst!.

## Who Made It?
Rafa *'Bluesman'* Faura Cucalón; you can read about me on <a href="https://www.linkedin.com/in/rafaelfaura/" target="_blank">LinkedIn</a>.

## Features
- Covers 61 <a href="https://github.com/rfc-st/humble/#checks-enabled-headers" target="_blank">enabled</a> security-related HTTP response headers.
- 15 <a href="https://github.com/rfc-st/humble/#checks-missing-headers" target="_blank">checks</a> for missing security-related HTTP response headers.
- 1239 <a href="https://github.com/rfc-st/humble/#checks-fingerprint-headers" target="_blank">checks</a> for fingerprinting through HTTP response headers.
- 157 <a href="https://github.com/rfc-st/humble/#checks-deprecated-headersprotocols-and-insecure-values" target="_blank">checks</a> for deprecated HTTP response headers/protocols or with insecure/wrong values.
- 28 <a href="https://github.com/rfc-st/humble/blob/master/additional/insecure.txt#L46-L73" target="_blank">checks</a> related to Content Security Policy <a href="https://www.w3.org/TR/CSP3/" target="_blank">Level 3</a>.
- Can check for compliance with the OWASP <a href="https://owasp.org/www-project-secure-headers/#div-bestpractices" target="_blank">Secure Headers Project</a> Best Practices.
- Can exclude specific HTTP response headers from the analysis.
- Can analyze raw response files: text files with HTTP response headers and values.
- Can export each analysis to CSV, CSS3 & HTML5, JSON, PDF 1.4, TXT, XLSX (Excel 2007 onwards) and XML; and in a filename and path of your choice.
- Can check for outdated SSL/TLS protocols and vulnerabilities: requires <a href="https://testssl.sh/" target="_blank">testssl.sh</a>.
- Can provide brief and detailed analysis along with HTTP response headers.
- Can use proxies for the analysis.
- Allows specifying custom HTTP request headers.
- Can output only analysis summary, totals and grade as JSON; suitable for <a href="https://www.redhat.com/en/topics/devops/what-is-ci-cd" target="_blank">CI/CD</a>.
- Print browser support for enabled HTTP security headers, with data from <a href="https://caniuse.com/" target="_blank">Can I use</a>.
- Highlights <a href="https://developer.mozilla.org/en-US/docs/MDN/Writing_guidelines/Experimental_deprecated_obsolete" target="_blank">experimental</a> headers in each analysis.
- Provides hundreds of relevant links to security resources, standards and technical blogs based on each analysis.
- Supports displaying analysis, messages, and most errors in English or Spanish.
- Saves each analysis, highlighting improvements or deficiencies compared to the previous one.
- Can display analysis statistics for a specific URL or across all of them.
- Can display fingerprint statistics for a specific term or the Top 20.
- Can display guidelines for enabling security HTTP response headers on popular frameworks, servers, and services.
- Provides dozens of <a href="https://github.com/rfc-st/humble/#unit-tests" target="_blank">unit tests</a> to verify compatibility with your environment; requires <a href="https://pypi.org/project/pytest/"  target="_blank">pytest</a> and <a href="https://pypi.org/project/pytest-cov/" target="_blank">pytest-cov</a>.
- Code reviewed via <a href="https://pypi.org/project/bandit/" target="_blank">Bandit</a>, <a href="https://marketplace.visualstudio.com/items?itemName=ms-python.flake8" target="_blank">Flake8</a>, <a href="https://github.com/joerick/pyinstrument" target="_blank">pyinstrument</a>, <a href="https://marketplace.visualstudio.com/items?itemName=SonarSource.sonarlint-vscode" target="_blank">SonarQube for IDE</a> and <a href="https://marketplace.visualstudio.com/items?itemName=sourcery.sourcery" target="_blank">Sourcery</a>.
- Tested, one by one, on thousands of URLs.
- Tested on Docker 26.1, Kali Linux 2021.1, macOS 14.2.1 and Windows 10 20H2.
- <a href="https://github.com/rfc-st/humble/blob/master/additional/fingerprint.txt" target="_blank">Almost</a> all the <a href="https://github.com/rfc-st/humble/blob/master/additional/owasp_best_practices.txt" target="_blank">code</a> available under one of the most permissive licenses: <a href="https://github.com/rfc-st/humble/blob/master/LICENSE" target="_blank">MIT</a>.
- And more!.

## How can I test it?
- Start by taking a look at its <a href="https://github.com/rfc-st/humble/" target="_blank">repository</a>.
- And its <a href="https://humble.readthedocs.io/en/latest/references.html" target="_blank">documentation</a> on its classes and functions (Work in progress).
- Then, if you think it could be useful, run the <a href="https://github.com/rfc-st/humble?tab=readme-ov-file#unit-tests" target="_blank">unit tests</a> to check compatibility with your environment.

Whatever you decide about **humble.py**, thank you for your time!.

## Notes
About <a href="https://marketplace.visualstudio.com/items?itemName=sourcery.sourcery" target="_blank">Sourcery</a> checks:

To maintain compatibility with the minimum required Python version for this tool (particularly with respect to f-strings), and because I consider some of Sourcery’s checks offer little benefit, certain ones are explicitly ignored through inline comments.

## Last but not least
For those who maintain some essential tools for developing and testing **humble.py**, and to everyone who has contributed ideas, suggestions, or reported bugs: <a href="https://github.com/rfc-st/humble/?tab=readme-ov-file#acknowledgements" target="_blank">thank you</a>!.

And a special greeting to Alba, Aleix, Alejandro (x3), Álvaro, Ana, Carlos (x3), David (x3), Eduardo, Eloy, Fernando, Gabriel, Íñigo, Joanna, Juan Carlos, Juán, Julián, Julio, Iván, Lourdes, Luis Joaquín, María Antonia, Marta, Miguel, Miguel Ángel (x2), Montse, Naiara, Pablo, Sergio, Ricardo, and Rubén!.
<br />
<br />
<aside class="md-source-file">
<span class="md-source-file__fact">
Last updated on
<span class="git-revision-date-localized-plugin git-revision-date-localized-plugin-datetime"><em>December 27, 2025</em></span>
</span>
</aside>