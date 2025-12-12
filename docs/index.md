# humble.py
Welcome to **humble.py** documentation!.

## What is *humble.py*?
It is a humble, and **fast**, security-oriented HTTP response headers analyzer.

It is the result of many weekends spent coding, studying, and researching standards, regulations, exploits, bypasses, and countless articles about HTTP response header security.

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
- Covers 61 enabled security-related HTTP response headers.
- 15 checks for missing security-related HTTP response headers.
- 1239 checks for fingerprinting through HTTP response headers.
- 155 checks for deprecated HTTP response headers/protocols or with insecure/wrong values.
- 28 checks related to Content Security Policy Level 3.
- Can check for compliance with the OWASP Secure Headers Project Best Practices.
- Can exclude specific HTTP response headers from the analysis.
- Can analyze raw response files: text files with HTTP response headers and values.
- Can export each analysis to CSV, CSS3 & HTML5, JSON, PDF 1.4, TXT, XLSX and XML.
- Can check for outdated SSL/TLS protocols and vulnerabilities with testssl.sh.
- Can provide brief and detailed analysis along with HTTP response headers.
- Can use proxies for the analysis.
- Allows specifying custom HTTP request headers.
- Can output only analysis summary, totals and grade as JSON for CI/CD.
- Shows browser support for enabled HTTP security headers, with data from Can I use.
- Highlights experimental headers in each analysis.
- Provides hundreds of relevant links to security resources, standards and technical blogs.
- Supports displaying analysis, messages, and most errors in English or Spanish.
- Saves each analysis, highlighting improvements or deficiencies compared to the previous one.
- Can display analysis statistics for a specific URL or across all of them.
- Can display fingerprint statistics for a specific term or the Top 20.
- Can display guidelines for enabling security HTTP response headers on popular frameworks, servers, and services.
- Provides unit tests to verify compatibility with your environment.
- Almost all the code available under MIT license.
- And more!.

## How can I test it?
Start by taking a look at its <a href="https://github.com/rfc-st/humble/" target="_blank">repository</a>.

And the available <a href="https://humble.readthedocs.io/en/latest/references.html" target="_blank">documentation</a> on its classes and functions (Work in progress).

After that, I advise that you try it out to see if you can use it in your <a href="https://github.com/rfc-st/humble/?tab=readme-ov-file#unit-tests" target="_blank">environment</a>.

**Thank you** in advance; I hope you find **humble.py** useful!.

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
<span class="git-revision-date-localized-plugin git-revision-date-localized-plugin-datetime"><em>December 12, 2025</em></span>
</span>
</aside>