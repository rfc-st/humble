# 'humble' (HTTP Headers Analyzer)

[github.com/rfc-st/humble](https://github.com/rfc-st/humble) | v.2026-10-15

## 0. Info

- **Date**: `2026/10/15 - 21:42:01`
- **URL**: `https://google.com`
- **Final URL**: `https://www.google.com/ (1 redirect)`
- **Final IP**: `142.251.155.119`
- **Final Code**: `200`

> Note : The final URL redirect was analyzed; use the '-df' parameter to change this behavior.

- **File**: `humble_https_google.com_20261015_214202_en.md`

## HTTP Response Headers

    Accept-CH: Sec-CH-Prefers-Color-Scheme, Downlink, RTT, Sec-CH-UA-Form-Factors, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version, Sec-CH-UA-Arch, Sec-CH-UA-Model, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version-List, Sec-CH-UA-WoW64
    Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
    Cache-Control: private, max-age=0
    Content-Encoding: br
    Content-Length: 84551
    Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-ElhBfd2cN_tyCjMaohGKJQ' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
    Content-Type: text/html; charset=UTF-8
    Cross-Origin-Opener-Policy: same-origin-allow-popups; report-to="gws"
    Date: Thu, 15 Oct 2026 19:42:02 GMT
    Expires: -1
    Link: </shared_dict/homepage/13ccab04a8b8ba7fba9f1089f228e55e9ccdc66d9a25bee1a8426ae5dc382c82.dict>; rel="compression-dictionary"
    P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
    Permissions-Policy: unload=()
    Report-To: {"group":"gws","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gws/other"}]}
    Server: gws
    Set-Cookie: SEARCH_SAMESITE=CgQIhaIB; expires=Tue, 13-Apr-2027 19:42:02 GMT; path=/; domain=.google.com; SameSite=strict, AEC=Aaa9EJpHndXZY5NKTDuEwvvmVjh32_o6jUGP5yTBAu4b9o4HPFOZe3LoMl4; expires=Tue, 13-Apr-2027 19:42:02 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax, __Secure-ENID=Co8CCAISwQEBAQxeRR7vhQcFfaKUnTNld3WqDJDYPV9YBy1D5kRdEsQTuC78b41iMeFwpeGDqU6KEcpyEF19Ul386vukiC5OvTNMCKYYXbm1DcrQI4xdQ2rP9963lpKpHF-74JBaCJlIoP0Mu1DR-ZqfUjPFvwZ--Y4_ZjSwuUZeQOKcV0JZZWjFd3Qyy8URrauENkZXC1i_fOGNTuFtD1-GKbJBdloP5X_QblZqWD9jVsxIMSgeVoUqgtXtgWX_vXlHUBQ6cvYoKAIyRQF9bMSqlWx7ne-7zP9_aqzLjahZHtq5HEX4FqJJh7bMZqOn1FKXV-7bJmJHIbiRFLf3zcM1guzPqlMhLaEnf89NknD0Dg; expires=Mon, 15-Nov-2027 12:00:20 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
    Strict-Transport-Security: max-age=31536000
    X-Frame-Options: SAMEORIGIN
    X-XSS-Protection: 0

## 1. Enabled HTTP Security Headers

    Cache-Control: private, max-age=0
    Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-ElhBfd2cN_tyCjMaohGKJQ' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
    Content-Type: text/html; charset=UTF-8
    Cross-Origin-Opener-Policy: same-origin-allow-popups; report-to="gws"
    P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
    (*) Permissions-Policy: unload=()
    Report-To: {"group":"gws","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gws/other"}]}
    Set-Cookie: SEARCH_SAMESITE=CgQIhaIB; expires=Tue, 13-Apr-2027 19:42:02 GMT; path=/; domain=.google.com; SameSite=strict, AEC=Aaa9EJpHndXZY5NKTDuEwvvmVjh32_o6jUGP5yTBAu4b9o4HPFOZe3LoMl4; expires=Tue, 13-Apr-2027 19:42:02 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax, __Secure-ENID=Co8CCAISwQEBAQxeRR7vhQcFfaKUnTNld3WqDJDYPV9YBy1D5kRdEsQTuC78b41iMeFwpeGDqU6KEcpyEF19Ul386vukiC5OvTNMCKYYXbm1DcrQI4xdQ2rP9963lpKpHF-74JBaCJlIoP0Mu1DR-ZqfUjPFvwZ--Y4_ZjSwuUZeQOKcV0JZZWjFd3Qyy8URrauENkZXC1i_fOGNTuFtD1-GKbJBdloP5X_QblZqWD9jVsxIMSgeVoUqgtXtgWX_vXlHUBQ6cvYoKAIyRQF9bMSqlWx7ne-7zP9_aqzLjahZHtq5HEX4FqJJh7bMZqOn1FKXV-7bJmJHIbiRFLf3zcM1guzPqlMhLaEnf89NknD0Dg; expires=Mon, 15-Nov-2027 12:00:20 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
    Strict-Transport-Security: max-age=31536000
    X-Frame-Options: SAMEORIGIN
    X-Xss-Protection: 0

## 2. Missing HTTP Security Headers

- **Clear-Site-Data**: Clears browsing data (cookies, storage, cache) associated with the requesting website. [Ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Clear-Site-Data)
- **Cross-Origin-Embedder-Policy**: Prevents documents and workers from loading non-same-origin requests unless allowed. [Ref](https://mdn.io/Cross-Origin-Embedder-Policy)
- **Cross-Origin-Resource-Policy**: Protect servers against certain cross-origin or cross-site embedding of the returned source. [Ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cross-Origin_Resource_Policy)
- **Content-Security-Policy**: Detect and mitigate Cross Site Scripting (XSS) and data injection attacks, among others. [Ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)
- **Integrity-Policy**: Blocks certain resource types without Subresource Integrity metadata. [Ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Integrity-Policy)
- **NEL** (\*): Enables web applications to declare a reporting policy to report errors. [Ref](https://scotthelme.co.uk/network-error-logging-deep-dive/)
- **Referrer-Policy**: Controls how much referrer information should be included with requests. [Ref](https://scotthelme.co.uk/a-new-security-header-referrer-policy/)
- **X-Content-Type-Options**: Indicate that MIME types in the "Content-Type" headers should be followed. [Ref](https://mdn.io/X-Content-Type-Options)
- **X-Permitted-Cross-Domain-Policies**: Limit which data external resources (e.g. Adobe Flash/PDF documents), can access on the domain. [Ref](https://owasp.github.io/www-project-secure-headers/response-headers/)

## 3. Fingerprint HTTP Response Headers

These headers can expose IPs, hostnames, software or their versions:

- **Server** (Generic HTTP Server/Content Delivery Network): `'gws'`

## 4. Deprecated HTTP Response Headers/Protocols and Insecure Values

The following headers/protocols are deprecated or their values may be considered unsafe:

- **Accept-CH** (Deprecated Values): These values are deprecated: 'sec-ch-ua-full-version' [Ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept-CH)
- **Cache-Control** (Recommended Values): Enable 'no-store' if there are sensitive data in the URL analyzed. [Ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control)
- **Content-Security-Policy-Report-Only** (Ignored Directives): Avoid deprecated or ignored directives: 'report-uri' [Ref](https://mdn.io/Content-Security-Policy-Report-Only)
- **Content-Security-Policy-Report-Only** (Ignored Header): Use 'report-to' exclusively to report policy violations. [Ref](https://mdn.io/Content-Security-Policy-Report-Only)
- **Expires** (Ignored Header): Header ignored by the directives 'max-age' or 's-maxage' in the header that controls the cache. [Ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Expires)
- **P3P** (Deprecated Header): This header is deprecated. Use cookies, consents and regulations (e.g. GDPR) instead. [Ref](https://webhint.io/docs/user-guide/hints/hint-no-p3p/)
- **Report-To** (Deprecated Header): This header is deprecated. Use instead "Reporting-Endpoints". [Ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Report-To)
- **Set-Cookie** (Insecure Attributes): Review the cookie 'SEARCH\_SAMESITE'. 'Secure' and 'HttpOnly' must be set on any cookie associated with sensitive data. [Ref](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
- **Strict-Transport-Security** (Recommended Values): Add 'includeSubDomains' and 'max-age' (with 31536000 -one year- as minimum). [Ref](https://www.getpagespeed.com/server-setup/security/nginx-hsts) [Ref](https://mdn.io/Strict-Transport-Security)

## 5. Empty HTTP Response Headers Values

Empty HTTP headers (and are therefore considered disabled):

Nothing to report, all seems OK!

## 6. Browser Compatibility for Enabled HTTP Security Headers

Only for the headers in section 1; deprecated ones and those not in 'Can I Use' are excluded.

- [Cache-Control](https://caniuse.com/mdn-http_headers_cache-control)
- [Content-Security-Policy-Report-Only](https://caniuse.com/?search=Content-Security-Policy-Report-Only)
- [Content-Type](https://caniuse.com/mdn-http_headers_content-type)
- [Cross-Origin-Opener-Policy](https://caniuse.com/mdn-http_headers_cross-origin-opener-policy)
- [Permissions-Policy](https://caniuse.com/mdn-http_headers_permissions-policy)
- [Set-Cookie](https://caniuse.com/mdn-http_headers_set-cookie)
- [Strict-Transport-Security](https://caniuse.com/?search=Strict-Transport-Security)
- [X-Frame-Options](https://caniuse.com/mdn-http_headers_x-frame-options)

## 7. Analysis Results

Done in 0.31 seconds! (changes with respect to the last analysis in parentheses)

- Enabled headers: **11** (No changes)
- Missing headers: **9** (No changes)
- Fingerprint headers: **1** (No changes)
- Deprecated/Insecure headers: **9** (No changes)
- Empty headers: **0** (No changes)
- Findings to review: **19** (No changes)
- Analysis Grade: **D** (Review 'Deprecated/Insecure headers')
- '(\*)' meaning: Experimental HTTP response directive or header
- '(\*)' ref: [mdn.io/Experimental\_deprecated\_obsolete](https://mdn.io/Experimental_deprecated_obsolete)
- '(Not available)' meaning: The history file, analysis\_h.txt, could not be accessed
