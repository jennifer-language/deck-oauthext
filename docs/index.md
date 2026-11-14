<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# @jennifer/oauthext

Vendor-specific OAuth2 for the bundled [`oauth`](https://jennifer-lang.dev/modules/oauth.html)
module. `oauth` keeps the standard mechanics: the client-credentials (with a
secret or a client assertion), refresh, device, authorization-code with PKCE
and JWT-bearer grants, endpoint discovery, and token storage. What belongs to one provider
lives here, so a new provider is a deck change, never a change to the
interpreter:

- **Presets**: `oauth.Config` values for Google and Microsoft Entra ID, for
  the browser sign-in, the device flow and refresh (mail through IMAP and
  SMTP, Microsoft Graph, Google APIs as a user), including Entra's
  multi-tenant endpoints, which `oauth.discover` cannot read.
- **Google service accounts**: a server logs in as a service account from its
  JSON key file, with no user and no browser. This opens every Google Cloud
  API (Cloud Storage, BigQuery, Pub/Sub) and, with domain-wide delegation,
  Google Workspace.

The presets were `oauth.google` and `oauth.microsoft` in the bundled module up
to Jennifer 0.25; [Moving from oauth](migrating.md) shows the change.

## Conventions

Snippets assume these imports, and add the `use` lines and other imports
they need:

```jennifer
import "oauth.j" as oauth;
import "@jennifer/oauthext/" as oauthext;
```

The trailing slash resolves to the entry module.

The deck needs the `net` capability (the requests go through `http`), so it
runs on the default `jennifer` binary, not `jennifer-tiny`.

## Errors

A problem with the deck's own input is an `Error` of kind `"oauthext"` whose
message starts with `oauthext: `: a key file that is not a service-account key
or lacks a field, a private key that is not one PKCS#8 PEM key or cannot sign,
a token endpoint that is not https (plain http only on this machine, with no
`user@` part), a tenant that is not a name, an empty scope, a subject or
`client_email` that is not an e-mail address. A key file is checked completely before
any request is sent. A refusal from the token endpoint keeps the `oauth`
module's `oauth.OAuthError` (kind `"oauth"`), with Google's error code and
description in the message (`invalid_grant: Invalid JWT Signature.`) and as the
`errorCode` and `description` fields, and so does a request that fails:
an endpoint that cannot be reached, stalls or sends an oversized reply.

```jennifer
use io;

try {
    def tok as oauth.Token init oauthext.googleServiceAccount($keyJson, $scope);
} catch (e) {
    io.printf("%s: %s\n", $e.kind, $e.message);
}
```
