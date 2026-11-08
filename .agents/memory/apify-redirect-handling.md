---
name: Apify redirect handling
description: A caution for using the Apify web-fetch integration when testing redirect behavior.
---

Treat `mcpApify_apifyWebFetch` as a content fetcher, not a reliable no-follow redirect inspector. A fetch of a public URL that returned `Location: http://127.0.0.1/` came back with that loopback URL as the loaded URL and a 502 from the fetch layer.

**Why:** The integration followed a redirect despite its documented no-follow behavior. Using it to test private-redirect protection can send a request to a local address from the fetch environment and does not validate the application's own policy.

**How to apply:** For redirect-policy tests, inspect first-hop headers with an HTTP client that does not follow redirects (for example, curl without `-L`). Use the isolated, authorized scanner only for the actual redirect test.
