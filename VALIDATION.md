# Validation

Validated on October 3, 2026, using Python 3.13.9.

- **40 unittest tests passed.** These include subcases covering all 32 finding rules and multiple safe alternatives, plus file traversal, non-execution of source, local input propagation, alias and scope handling, report redaction, policy validation, baselines, resource limits and CLI exit codes.
- **End-to-end demo:** 9 files across Python, TypeScript/TSX, PHP, Java, C#, Go, Ruby, environment configuration and a package manifest. Produced 11 findings and 35 navigation entries in HTML, JSON and SARIF.
- **HTML structure:** 11 finding cards and 35 map rows; expected filter controls present; the inline-script content security policy hash matched the generated script.
- **5 isolated JavaScript checks passed:** initial visibility, combined severity/status filters, case-insensitive search, map category selection and map search. The exact generated report script ran against small document stubs, without a browser.
- **Report serialization:** JSON and SARIF parsed successfully; SARIF rule indexes, locations, execution status and navigation properties were checked. Full validation against an external SARIF JSON schema was not performed.

## Unverified

Visual browser rendering was not verified: the browser tool's URL policy blocked local-file previews. No layout, accessibility, or cross-browser compatibility claim is made.

The tests use synthetic cases and do not establish production precision, recall, or absence of missed vulnerabilities. Other Python versions and operating systems have not been exercised. See the README for analysis limits and supported language depth.
