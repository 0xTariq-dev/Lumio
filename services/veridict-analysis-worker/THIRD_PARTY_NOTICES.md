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
