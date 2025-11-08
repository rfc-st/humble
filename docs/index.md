# humble.py

Welcome to **humble.py** documentation!

## What is *humble.py*?

It is a humble, and **fast**, security-oriented HTTP headers analyzer.

It is the result of many weekends over the years, filled with excitement: programming, studying, reviewing, and reading standards, regulations, exploits, bypasses, articles, and blogs on related HTTP response headers and their security.

It started as a small personal project, with no intention of becoming important. Over time, it was accepted into [Kali Linux](https://pkg.kali.org/pkg/humble), has been referenced in blogs and social media, and has been used as a basis and reference for final degree projects.

## Who Made It?

Rafa *'Bluesman'* Faura Cucalón; you can read about me on [LinkedIn](https://www.linkedin.com/in/rafaelfaura/).

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
- Provides basic unit tests to verify compatibility with your environment.
- Almost all the code available under MIT license.
- And more!.


## How can I test it?
Start by taking a look at its [repository](https://github.com/rfc-st/humble/).

And the available [documentation](reference.md) on its classes and functions (Work in progress).

**Thank you** in advance; I hope you find *humble* useful!.