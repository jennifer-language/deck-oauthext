# @jennifer/oauthext

[![test](https://github.com/jennifer-language/deck-oauthext/actions/workflows/test.yml/badge.svg)](https://github.com/jennifer-language/deck-oauthext/actions/workflows/test.yml)
[![Documentation](https://img.shields.io/badge/docs-github%20pages-blue)](https://jennifer-language.github.io/deck-oauthext/)
[![release](https://img.shields.io/github/v/release/jennifer-language/deck-oauthext)](https://github.com/jennifer-language/deck-oauthext/releases/latest)

Vendor-specific OAuth2 for the bundled `oauth` module of
[Jennifer](https://jennifer-lang.dev/): `Config` presets for Google and
Microsoft Entra ID, and Google service-account logins from a JSON key file
(the RFC 7523 JWT bearer grant), which open Google Cloud and Workspace APIs to
a program with no user. The presets were `oauth.google` / `oauth.microsoft` in
the bundled module up to Jennifer 0.25.

**[Documentation](https://jennifer-language.github.io/deck-oauthext/)**

## Install

```sh
jvc add @jennifer/oauthext
```

This vendors the deck to `vendor/<scope>/oauthext/`. Without `jvc`, unpack the
`src/` subtree of a release archive (`<scope>-oauthext-<version>.tar.gz`) there.

## Usage

```jennifer
import "oauth.j" as oauth;
import "@jennifer/oauthext/" as oauthext;

def tok as oauth.Token init oauthext.googleServiceAccount(
    fs.readString("service-account.json"),
    "https://www.googleapis.com/auth/cloud-platform");

def cfg as oauth.Config init oauthext.microsoft("common", $clientId, "",
    "https://outlook.office.com/IMAP.AccessAsUser.All offline_access");
```

## Requirements

Jennifer 0.26.0 or newer, the default `jennifer` binary (the deck needs
`net`; the stock `jennifer-tiny` has no network driver). RS256 signing for
service accounts is in the default binary.

## Development

```sh
tools/check-all.sh                   # the full gate, as CI runs it
jennifer test src/oauthext_test.j      # the test overlay
tools/check-docs.sh                  # docs against the code
tools/pack.sh dist                   # build the release archive
```

## Licence

LGPL-3.0-only, see [LICENSE](LICENSE). Copyright (C) 2026 mplx &lt;mplx@jennifer-lang.dev&gt;.

`tools/check-headers.sh` checks every source file's SPDX header against
`deck.toml`.
