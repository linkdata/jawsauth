[![build](https://github.com/linkdata/jawsauth/actions/workflows/go.yml/badge.svg)](https://github.com/linkdata/jawsauth/actions/workflows/go.yml)
[![coverage](https://github.com/linkdata/jawsauth/blob/coverage/main/badge.svg)](https://html-preview.github.io/?url=https://github.com/linkdata/jawsauth/blob/coverage/main/report.html)
[![goreport](https://goreportcard.com/badge/github.com/linkdata/jawsauth)](https://goreportcard.com/report/github.com/linkdata/jawsauth)
[![Docs](https://godoc.org/github.com/linkdata/jawsauth?status.svg)](https://godoc.org/github.com/linkdata/jawsauth)

# jawsauth

OIDC-verified authentication for [JaWS](https://github.com/linkdata/jaws) sessions.

- Requires an OIDC-compliant provider.
- Uses OIDC discovery from the configured issuer.
- Verifies `id_token` and stores identity claims in session data.
