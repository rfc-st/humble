# Regex

A regular expression (regex) describes the *shape* of a piece of text instead of its exact characters: "four digits, a hyphen, two digits", or "the word `nonce-` when no quote comes before it". Python's <a href="https://docs.python.org/3/library/re.html" target="_blank">`re`</a> module then answers whether a text has that shape, where, and which parts of it are worth keeping.

`humble` needs them because almost everything it reads is text it does not control: header values sent by any server, the HTML of the response, the values typed by the user and its own analysis when it is converted to another format. Several checks ask questions that a plain comparison cannot answer, such as "is this hash wrapped in quotes?" or "which comma separates two cookies and which one belongs to a date?".

The patterns shared by the checks and the exports live in a single tuple of `humble.py`, `RE_PATTERN`, and the code refers to them by position (e.g. `RE_PATTERN[17]`). This page explains each position: the function that needs it, what it does, the values it looks for and why `humble` needs that search.
<br/>
<br/>
Reading aid for the symbols used below:
<br/>

- `\d`, `\s`, `\w`: a digit, a whitespace character, a letter/digit/underscore. `\S` is "anything but whitespace".
- `[abc]`, `[^abc]`: one character of the set, one character **not** in the set.
- `*`, `+`, `?`, `{2,7}`: zero or more, one or more, optional, between two and seven of the previous item.
- `.*?`: as few characters as possible (a "lazy" match). `*+`: as many as possible and never give them back (a "possessive" match).
- `^`, `$`: start and end of the text (of each line with `(?m)`). `\b`: the edge of a word.
- `( )`: a group whose text is kept. `(?: )`: a group that is not kept. `a|b`: `a` or `b`.
- `(?i: )`: ignore upper and lower case inside the group.
- `(?= )`, `(?! )`: what follows must, or must not, be this. `(?<! )`: what precedes must not be this.
- `\(`, `\.`, `\[`: the literal character, without its special meaning.

## Quick index

| Position | Used for |
| --- | --- |
| [`RE_PATTERN[0]`](#re_pattern0) | Service of a fingerprint header (`-f` with a term) |
| [`RE_PATTERN[1]`](#re_pattern1) | IP addresses in `Content-Security-Policy` |
| [`RE_PATTERN[2]`](#re_pattern2) | Path traversal in `-of` and `-op` |
| [`RE_PATTERN[3]`](#re_pattern3) | Services of the fingerprint statistics (`-f`) |
| [`RE_PATTERN[4]`](#re_pattern4) | Date of the latest version (`-v`) |
| [`RE_PATTERN[5]`](#re_pattern5) | Section titles of an analysis (`-o json`, `-o xml`) |
| [`RE_PATTERN[6]`](#re_pattern6) | Quoted nonces in `Content-Security-Policy` |
| [`RE_PATTERN[7]`](#re_pattern7) | Response header names in the PDF export |
| [`RE_PATTERN[8]`](#re_pattern8) | `<meta http-equiv>` tags of the response body |
| [`RE_PATTERN[9]`](#re_pattern9) | Not used at present |
| [`RE_PATTERN[10]`](#re_pattern10) | Enabled security headers in the PDF export |
| [`RE_PATTERN[11]`](#re_pattern11) | Note lines of the analysis |
| [`RE_PATTERN[12]`](#re_pattern12) | Hexadecimal nonces |
| [`RE_PATTERN[13]`](#re_pattern13) | Base64 nonces |
| [`RE_PATTERN[14]`](#re_pattern14) | Boundary between cookies in `Set-Cookie` |
| [`RE_PATTERN[15]`](#re_pattern15) | Not used at present |
| [`RE_PATTERN[16]`](#re_pattern16) | Directive names of `Content-Security-Policy` in the HTML export |
| [`RE_PATTERN[17]`](#re_pattern17) | Quoted hashes in `Content-Security-Policy` |
| [`RE_PATTERN[18]`](#re_pattern18) | Unquoted hashes in `Content-Security-Policy` |
| [`RE_PATTERN[19]`](#re_pattern19) | Directive name of each part of `Content-Security-Policy` |
| [`RE_PATTERN[20]`](#re_pattern20) | Padding before a comma in response header values |
| [`RE_PATTERN[21]`](#re_pattern21) | Totals of the analysis results (`-cicd`) |
| [`RE_PATTERN[22]`](#re_pattern22) | Empty `<pre>` elements in the HTML export |
| [`RE_PATTERN[23]`](#re_pattern23) | Unquoted nonces in `Content-Security-Policy` |
| [`RE_PATTERN[24]`](#re_pattern24) | Consecutive blank lines in the HTML export |
| [`RE_PATTERN[25]`](#re_pattern25) | First list of `Connection-Allowlist` |

## Patterns

### RE_PATTERN[0]

```text
\((.*?)\)
```

- **Needed by:** [`fng_statistics_term_groups`][humble.fng_statistics_term_groups] (`-f` option with a term).
- **What it does:** finds the first text between parentheses of a line and keeps it. `.*?` is lazy, so it stops at the first `)`.
- **Values it looks for:** the service that follows each header in `additional/fingerprint.txt`; in `Akamai-GRN (Akamai Edge)` it keeps `Akamai Edge`.
- **Why `humble` needs it:** the statistics of a term group the fingerprint headers by service, and the term is searched in that service.
- **Matches:** `Akamai-GRN (Akamai Edge)`

### RE_PATTERN[1]

```text
(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})
```

- **Needed by:** [`csp_check_values`][humble.csp_check_values] and [`csp_check_ip`][humble.csp_check_ip].
- **What it does:** finds anything shaped like an IPv4 address (four groups of one to three digits separated by dots) or like an IPv6 address (two to seven groups of up to four hexadecimal digits, each followed by a colon).
- **Values it looks for:** candidates only: it does not verify ranges. Each candidate is then validated with Python's `ipaddress` module, and `127.0.0.1` is left out.
- **Why `humble` needs it:** `Content-Security-Policy` sources should be host names, so an IP address in the policy is reported.
- **Matches:** `default-src https://203.0.113.10`, `img-src [2001:db8::1]`

### RE_PATTERN[2]

```text
\.\./|/\.\.|\\\.\.|\\\.\\|%2e%2e%2f|%252e%252e%252f|%c0%ae%c0%ae%c0%af|%uff0e%uff0e%u2215|%uff0e%uff0e%u2216
```

- **Needed by:** [`check_input_traversal`][humble.check_input_traversal] (`-of` and `-op` options).
- **What it does:** looks for any of nine sequences used to climb out of a directory. The comparison is case-sensitive.
- **Values it looks for:** `../`, `/..`, `\..` and `\.\`, plus encoded forms of `../`: URL-encoded (`%2e%2e%2f`), double URL-encoded (`%252e%252e%252f`), overlong UTF-8 (`%c0%ae%c0%ae%c0%af`) and Unicode-encoded (`%uff0e%uff0e%u2215`, `%uff0e%uff0e%u2216`).
- **Why `humble` needs it:** the file name and the path of an export are typed by the user; `humble` stops with an error instead of writing outside the intended directory.
- **Matches:** `../reports`, `reports\..\etc`, `%2e%2e%2fetc`

### RE_PATTERN[3]

```text
\(([^)]+)\)
```

- **Needed by:** [`fng_statistics_top`][humble.fng_statistics_top] (`-f` option without a term).
- **What it does:** finds every text between parentheses of a line and keeps it. Unlike [`RE_PATTERN[0]`](#re_pattern0) the parentheses cannot be empty.
- **Values it looks for:** the services of `additional/fingerprint.txt`; in `Server (Generic HTTP Server/Content Delivery Network)` it keeps `Generic HTTP Server/Content Delivery Network`.
- **Why `humble` needs it:** the services are counted to print the Top 20 of the fingerprint statistics.
- **Matches:** `Server (Generic HTTP Server/Content Delivery Network)`

### RE_PATTERN[4]

```text
\d{4}-\d{2}-\d{2}
```

- **Needed by:** [`get_github_version`][humble.get_github_version] (`-v` option).
- **What it does:** finds the first text shaped like `YYYY-MM-DD`: four digits, a hyphen, two digits, a hyphen and two digits.
- **Values it looks for:** the date that identifies a version of `humble`, read from the copy of `humble.py` published in the repository.
- **Why `humble` needs it:** that date is compared with the local one to tell whether a newer version is available.
- **Matches:** `local_version = date.fromisoformat("2026-11-28")`

### RE_PATTERN[5]

```text
(?m)^\[(.*?)\]\n
```

- **Needed by:** [`parse_analysis`][humble.parse_analysis] (`-o json` and `-o xml` options).
- **What it does:** finds each line made only of a text between square brackets and keeps that text. `(?m)` makes `^` match at the start of every line.
- **Values it looks for:** the section titles of an analysis, such as `[0. Info]` or `[2. Missing HTTP Security Headers]`.
- **Why `humble` needs it:** the analysis is split at those titles, giving each section name followed by its lines, which is the structure both exports are built from.
- **Matches:** `[0. Info]\n` (`\n` stands for a line break)

### RE_PATTERN[6]

```text
'(?i:nonce)-([^']+)'
```

- **Needed by:** [`csp_check_ignored`][humble.csp_check_ignored] and [`csp_check_nonces`][humble.csp_check_nonces].
- **What it does:** finds a nonce written as `Content-Security-Policy` requires, between single quotes, and keeps its value. The word `nonce` is accepted in any case.
- **Values it looks for:** sources such as `'nonce-4f2a9c1b7d8e3a6f'`, keeping `4f2a9c1b7d8e3a6f`.
- **Why `humble` needs it:** each value is checked for length and format (see [`RE_PATTERN[12]`](#re_pattern12) and [`RE_PATTERN[13]`](#re_pattern13)), and `'strict-dynamic'` is reported as ignored when the policy has neither a nonce nor a hash.
- **Matches:** `script-src 'nonce-4f2a9c1b7d8e3a6f'`, `'NONCE-abc123'`

### RE_PATTERN[7]

```text
\(humble_pdf_style\)([^:]+):
```

- **Needed by:** [`format_pdf_lines`][humble.format_pdf_lines] and [`set_pdf_chunks`][humble.set_pdf_chunks] (`-o pdf` option).
- **What it does:** finds the internal marker `(humble_pdf_style)` followed by a text and a colon.
- **Values it looks for:** the lines of the response headers (`-r` option), which [`print_response_headers`][humble.print_response_headers] marks when the analysis is exported to PDF.
- **Why `humble` needs it:** a plain text line carries no color; the marker tells the PDF export which header names to color, and it is removed before the line is written.
- **Matches:** `(humble_pdf_style)Server: nginx`

### RE_PATTERN[8]

```text
<meta\s+http-equiv=["\']((?:[^"\'<\n]|["\'](?!\s+content=))*+)["\']\s+content=["\']((?:[^"\'<\n]|["\'](?!\s*/?>))*+)["\']\s*/?>
```

- **Needed by:** the main flow of `humble.py`, right after the response is received and only when its body is HTML (it is not inside a function). Upper and lower case are ignored.
- **What it does:** finds each `<meta http-equiv="..." content="...">` tag and keeps two values: the name and the content. Both may use single or double quotes, the content may contain quotes itself (`'self'`), and `http-equiv` must come before `content`. The possessive `*+` keeps the search fast on hostile HTML.
- **Values it looks for:** headers declared in the page instead of in the response, such as `Content-Security-Policy`, `Content-Security-Policy-Report-Only`, `Content-Type` and `X-UA-Compatible`.
- **Why `humble` needs it:** browsers honor some of those tags, ignore others and restrict what they may contain, so their values are checked along with the real headers.
- **Matches:** `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`, `<META HTTP-EQUIV='X-UA-Compatible' CONTENT='IE=edge' />`

### RE_PATTERN[9]

```text
\(humble_sec_style\)([^:]+)
```

- **Needed by:** no function at present; the position is kept so the following ones do not change.
- **What it does:** finds the internal marker `(humble_sec_style)` and keeps the text that follows it up to the first colon.
- **Values it looks for:** the name of an enabled security header in a marked line (see [`RE_PATTERN[10]`](#re_pattern10)).
- **Matches:** `(humble_sec_style)Strict-Transport-Security: max-age=31536000`

### RE_PATTERN[10]

```text
\(humble_sec_style\)
```

- **Needed by:** [`format_pdf_lines`][humble.format_pdf_lines] and [`set_pdf_chunks`][humble.set_pdf_chunks] (`-o pdf` option).
- **What it does:** finds the internal marker `(humble_sec_style)`.
- **Values it looks for:** the lines of the enabled security headers, which [`print_enabled_headers`][humble.print_enabled_headers] marks when the analysis is exported to HTML or PDF.
- **Why `humble` needs it:** the marker tells the PDF export which lines to print in green, and it is removed before the line is written.
- **Matches:** `(humble_sec_style)X-Content-Type-Options: nosniff`

### RE_PATTERN[11]

```text
(?: Nota +: | Note +: )
```

- **Needed by:** [`format_html_totals`][humble.format_html_totals] (`-o html` option) and [`format_md_info`][humble.format_md_info] (`-o md` option).
- **What it does:** finds the label of a note in Spanish or in English: a space, `Nota` or `Note`, one or more spaces, a colon and a space.
- **Values it looks for:** the note lines of the analysis, e.g. the one that warns that the URL returned an error.
- **Why `humble` needs it:** a note may mention a header name without being a finding, so the HTML export does not highlight it in red; the Markdown export writes it as a quote.
- **Matches:** `" Note : The URL returns an error"`, `" Nota : La URL devuelve un error"`

### RE_PATTERN[12]

```text
^[0-9a-fA-F]+$
```

- **Needed by:** [`csp_check_nonces`][humble.csp_check_nonces].
- **What it does:** checks that a whole text, from `^` to `$`, is made only of hexadecimal digits.
- **Values it looks for:** nonces written in hexadecimal, taken from the policy with [`RE_PATTERN[6]`](#re_pattern6).
- **Why `humble` needs it:** the length of a nonce is measured according to how it is written; a hexadecimal one shorter than the minimum is reported as insecure by [`csp_hex_nonce`][humble.csp_hex_nonce].
- **Matches:** `4f2a9c1b7d8e3a6f`

### RE_PATTERN[13]

```text
^[A-Za-z0-9+/=_-]+$
```

- **Needed by:** [`csp_check_nonces`][humble.csp_check_nonces].
- **What it does:** checks that a whole text is made only of the characters of the Base64 and Base64url alphabets, padding included.
- **Values it looks for:** nonces written in Base64, taken from the policy with [`RE_PATTERN[6]`](#re_pattern6).
- **Why `humble` needs it:** a nonce that passes is decoded by [`csp_base64_nonce`][humble.csp_base64_nonce], which reports it as insecure when it cannot be decoded or holds fewer bytes than the minimum.
- **Matches:** `dGhpcyBpcyBhIG5vbmNl`, `q83vEjRWeJA_-w==`

### RE_PATTERN[14]

```text
, (?=[^;,]+?=)
```

- **Needed by:** [`parse_cookie_attributes`][humble.parse_cookie_attributes].
- **What it does:** finds a comma and a space only when what follows is a `name=` that starts before any other `;` or `,`. The `(?= )` part looks ahead without taking any text.
- **Values it looks for:** the boundary between two cookies in a `Set-Cookie` value that holds several of them.
- **Why `humble` needs it:** all the cookies of a response arrive joined by `, `, and a date such as `Expires=Sun, 14 Jun 2026` holds a comma too; splitting only at real boundaries lets each cookie be checked with its own attributes.
- **Matches:** `sid=1; Secure, lang=en; Path=/`

### RE_PATTERN[15]

```text
'(?i:nonce)-[^']+'
```

- **Needed by:** no function at present; the position is kept so the following ones do not change.
- **What it does:** the same search as [`RE_PATTERN[6]`](#re_pattern6), a nonce between single quotes, without keeping its value.
- **Matches:** `'nonce-4f2a9c1b7d8e3a6f'`

### RE_PATTERN[16]

```text
(^|[\s;])({dir})($|[\s;])
```

- **Needed by:** [`format_html_csp`][humble.format_html_csp] (`-o html` option), through the compiled pattern `RE_CSP_DIRS`.
- **What it does:** it is a template: `{dir}` is replaced by the list of valid directive names (`default-src|script-src|...`). The result finds one of those names only when it is a whole word, i.e. between the start of the text, a space or a semicolon and a space, a semicolon or the end.
- **Values it looks for:** the directive names in the lines of the analysis that show a `Content-Security-Policy` value.
- **Why `humble` needs it:** the HTML export highlights each directive so a long policy is easier to read; requiring whole words avoids marking a name inside a longer one or inside a URL.
- **Matches:** `default-src 'self'; script-src-elem 'none'`

### RE_PATTERN[17]

```text
'(?i:(sha256|sha384|sha512))-([^']*)'
```

- **Needed by:** [`csp_check_ignored`][humble.csp_check_ignored] and [`csp_check_hashes`][humble.csp_check_hashes].
- **What it does:** finds a hash written between single quotes and keeps two values: the algorithm, in any case, and the text after the hyphen, which may be empty.
- **Values it looks for:** sources such as `'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='`.
- **Why `humble` needs it:** [`csp_valid_hash`][humble.csp_valid_hash] decodes each one and reports those whose length does not match their algorithm, since browsers ignore them; and `'strict-dynamic'` is reported as ignored when the policy has neither a hash nor a nonce.
- **Matches:** `script-src 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='`, `'SHA384-'`

### RE_PATTERN[18]

```text
(?<!')\b(?i:sha256|sha384|sha512)-[A-Za-z0-9+/=_-]+(?!')
```

- **Needed by:** [`csp_check_hashes`][humble.csp_check_hashes].
- **What it does:** finds a hash that is **not** between single quotes: `(?<!')` requires that no quote comes before the algorithm and `(?!')` that none closes the value.
- **Values it looks for:** sources such as `sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`, with one or both quotes missing.
- **Why `humble` needs it:** without its quotes a browser does not read the value as a hash, so the protection it was meant to give is lost without any visible error.
- **Matches:** `script-src sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=`, `script-src sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='`

### RE_PATTERN[19]

```text
^([a-zA-Z0-9\-]+)
```

- **Needed by:** [`csp_check_unknown`][humble.csp_check_unknown].
- **What it does:** keeps the letters, digits and hyphens found at the very start of a text, stopping at the first character that is none of them.
- **Values it looks for:** the directive name of each part of a `Content-Security-Policy`, once the policy is split at its semicolons; in `script-src 'self'` it keeps `script-src`.
- **Why `humble` needs it:** each name is compared with the valid and the deprecated directives, and the unknown ones (often a typo) are reported.
- **Matches:** `script-src 'self'`, `upgrade-insecure-requests`

### RE_PATTERN[20]

```text
\s{2,},
```

- **Needed by:** [`strip_response_headers`][humble.strip_response_headers].
- **What it does:** finds two or more whitespace characters followed by a comma; the whole match is replaced by one space.
- **Values it looks for:** padding left before a comma in the value of any response header.
- **Why `humble` needs it:** header values are cleaned of extraneous whitespace once, before any check runs, so checks and exports work on the same clean value.
- **Matches:** `max-age=31536000  , includeSubDomains`

### RE_PATTERN[21]

```text
^(.*?):\s+(\d+)\s+\((.*?)\)$
```

- **Needed by:** [`parse_cicd_sections`][humble.parse_cicd_sections] and [`parse_cicd_totals`][humble.parse_cicd_totals] (`-cicd` option).
- **What it does:** requires a whole line shaped as "label, colon, spaces, number, spaces, text between parentheses" and keeps three values: the label, the number and that text.
- **Values it looks for:** the totals of the analysis results; in `Missing headers:               9 (First Analysis)` it keeps `Missing headers`, `9` and `First Analysis`.
- **Why `humble` needs it:** the `-cicd` option prints those totals, and their change since the last analysis, as JSON for a pipeline. The grade line holds a letter instead of a number, so it does not match and is read apart.
- **Matches:** `Missing headers:               9 (First Analysis)`, `Findings to review:           31 (First Analysis)`

### RE_PATTERN[22]

```text
<pre(?:\s[^>]*)?>\s*</pre>
```

- **Needed by:** [`clean_html_final`][humble.clean_html_final] (`-o html` option).
- **What it does:** finds a `<pre>` element, with or without attributes, that holds nothing or only whitespace.
- **Values it looks for:** empty blocks of preformatted text left in the HTML file while it is built.
- **Why `humble` needs it:** they are removed from the final file so they do not add blank gaps to the report.
- **Matches:** `<pre></pre>`, `<pre class="x">   </pre>`

### RE_PATTERN[23]

```text
(?<!')(?i:nonce)-
```

- **Needed by:** [`csp_check_nonces`][humble.csp_check_nonces].
- **What it does:** finds `nonce-`, in any case, when the character before it is not a single quote.
- **Values it looks for:** nonces written without their opening quote, such as `nonce-4f2a9c1b7d8e3a6f`.
- **Why `humble` needs it:** as with hashes, a browser does not read an unquoted value as a nonce, so it is reported.
- **Matches:** `script-src nonce-4f2a9c1b7d8e3a6f`

### RE_PATTERN[24]

```text
(^[^\S\n]*\n)(?:[^\S\n]*(?:\n|$))+
```

- **Needed by:** [`decrease_html_spacing`][humble.decrease_html_spacing] (`-o html` option), with `^` and `$` matching at every line.
- **What it does:** finds a blank line followed by one or more blank lines and keeps only the first one. `[^\S\n]` means "whitespace other than a line break", so lines holding only spaces count as blank.
- **Values it looks for:** runs of two or more blank lines, from the `[0. Info]` section onwards.
- **Why `humble` needs it:** each run becomes a single blank line, which reduces the spacing between the sections of the HTML report.
- **Matches:** `first\n\n\nsecond` (`\n` stands for a line break)

### RE_PATTERN[25]

```text
^[^",]*(?:"[^"]*"[^",]*)*
```

- **Needed by:** [`conall_parse`][humble.conall_parse], called by [`conall_check_values`][humble.conall_check_values].
- **What it does:** takes the text from the start up to the first comma that is not inside double quotes. It always matches.
- **Values it looks for:** the first list of a `Connection-Allowlist` value; in `("https://a.example" "https://b.example/x,y"), ("https://c.example")` it takes `("https://a.example" "https://b.example/x,y")`, since the first comma is inside a quoted pattern.
- **Why `humble` needs it:** browsers only use that first list, so it is the one whose patterns and parameters are checked.

<br />
<aside class="md-source-file">
<span class="md-source-file__fact">
Last updated on
<span class="git-revision-date-localized-plugin git-revision-date-localized-plugin-datetime"><em>November 28, 2026</em></span>
</span>
</aside>