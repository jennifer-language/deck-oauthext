<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# Google service accounts

A service account is a Google identity for a program. It logs in with a key
pair instead of a password: Google keeps the public key, and you download the
private key as a JSON key file. To get a token the program signs a short-lived
JWT with that key and trades it at Google's token endpoint (RFC 7523, the JWT
bearer grant).

```jennifer
def tok as oauth.Token init oauthext.googleServiceAccount(
    fs.readString("/etc/myapp/service-account.json"),
    "https://www.googleapis.com/auth/devstorage.read_only");
def r as http.Response init http.get(
    "https://storage.googleapis.com/storage/v1/b/my-bucket/o",
    {"Authorization": "Bearer " + $tok.accessToken});
```

The token lasts about an hour (`expiresAt`) and comes with no refresh token.
When `oauth.isExpired($tok)` says it has run out, call `googleServiceAccount`
again.

## The key file

`oauthext.serviceAccount(keyJson)` reads and checks it; `googleServiceAccount`
does so first, so a bad file fails before any request. The deck requires:

- `"type": "service_account"`: an OAuth client file or a user's credentials
  file is refused;
- `client_email`, the account;
- `private_key`, one PKCS#8 PEM key (`-----BEGIN PRIVATE KEY-----`), nothing
  before or after it;
- `private_key_id`, sent as the assertion's `kid` so Google picks the key;
- `token_uri`, where the assertion is redeemed. It must be https, or plain
  http on this machine (`127.0.0.1`, `localhost`, `[::1]`) for an emulator,
  with no `user@` part, which could make a local-looking URL go elsewhere.

`project_id` is read when present. The key file is a credential: keep it out of
the repository, readable only by the program's user.

## Scopes

`scope` lists the OAuth scopes the token is for, separated by spaces, for
example `https://www.googleapis.com/auth/cloud-platform` for all of Google
Cloud. The account also needs IAM roles on the resources; the scope only limits
what the token may be used for.

## Acting for a user

With Google Workspace domain-wide delegation, an administrator lets a service
account act for the domain's users. `googleServiceAccountAs` names the user in
the assertion's `sub`:

```jennifer
def tok as oauth.Token init oauthext.googleServiceAccountAs($keyJson,
    "https://www.googleapis.com/auth/gmail.readonly", "ada@example.com");
```

## The assertion

`oauthext.serviceAccountAssertion(sa, scope, subject)` gives the signed
assertion on its own, for a token endpoint you call yourself. It is RS256 with
`kid` = `private_key_id`, `iss` = `client_email`, `aud` = `token_uri`,
`iat` = now, `exp` = now + `SERVICE_ACCOUNT_LIFETIME` (3600, Google's maximum)
and `scope`, plus `sub` when a subject is given. It is built with the bundled
module's `oauth.jwtAssertion` and redeemed with `oauth.jwtBearer`.

```jennifer
def sa as oauthext.ServiceAccount init oauthext.serviceAccount($keyJson);
def assertion as string init oauthext.serviceAccountAssertion($sa,
    "https://www.googleapis.com/auth/cloud-platform", "");
```
