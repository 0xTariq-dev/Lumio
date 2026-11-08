# Third-party notices

Veridict's own code is licensed under the MIT License; see the repository
`LICENSE` file. Third-party packages retain their respective licenses.

## Worker packages

The worker's direct packages use these declared licenses:

| Package | License |
| --- | --- |
| FastAPI | MIT |
| Microsandbox | Apache-2.0 |
| Uvicorn | BSD-3-Clause |
| Scrapling | BSD-3-Clause |
| curl-cffi | MIT |
| Playwright | Apache-2.0 |
| Patchright | Apache-2.0 |
| BrowserForge | Apache-2.0 |
| pypdf 7.0.0 | BSD-3-Clause |

## rea-agents 6.8.0

The URL guest includes `rea-agents` 6.8.0, licensed under MIT, for passive
CDP observation of the same Playwright Chromium session. Its locked runtime
dependency graph includes:

| Package | License |
| --- | --- |
| frida 17.23.2 | LGPL-2.0 WITH WxWindows-exception-3.1 |
| openpgp 6.3.2 | LGPL-3.0+ |

The package's `THIRD_PARTY_NOTICES.md`, npm dependency inventory, and license
files are retained under `/opt/rea-runtime/node_modules/rea-agents/`. The guest
runtime pins `zod` 4.6.6, `glob` 14.0.2, and `minimatch` 11.0.1 to versions that
passed the dependency audit.

## certifi 2026.10.23

The worker's Scrapling/curl-cffi static-fetch dependency chain includes
unmodified `certifi` 2026.10.23, licensed under the Mozilla Public License 2.0
(MPL-2.0).

- Source: <https://github.com/certifi/python-certifi>
- License: <https://www.mozilla.org/en-US/MPL/2.0/>
- The certifi distribution's license notice is included with its installed
  package in the guest image under `certifi-*.dist-info/licenses/LICENSE`.
- No certifi source files have been modified by Veridict.

The transitive `apify-fingerprint-datapoints` package is Apache-2.0 licensed.
The worker guest image also installs the rest of its third-party packages from
the hash-pinned `guest/requirements.lock`. Their license files are retained in
the installed package metadata.
