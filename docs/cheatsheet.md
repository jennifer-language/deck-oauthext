<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# oauthext cheatsheet

Every export of `@jennifer/oauthext`. The guides are listed in
[the introduction](index.md).

```jennifer
import "oauth.j" as oauth;
import "@jennifer/oauthext/" as oauthext;
```

The presets return the bundled module's `oauth.Config`, and the logins its
`oauth.Token`; use them with `oauth.deviceStart`, `oauth.refresh`,
`oauth.isExpired`, `oauth.save` and the rest. Errors about the deck's own input
are kind `"oauthext"`; a refusal from the token endpoint stays kind `"oauth"`.

## Presets

| Function | Returns | Does |
|---|---|---|
| `oauthext.google(clientId as string, clientSecret as string, scope as string)` | `oauth.Config` | Google's token, device and authorization endpoints |
| `oauthext.microsoft(tenant as string, clientId as string, clientSecret as string, scope as string)` | `oauth.Config` | a Microsoft Entra ID tenant's v2.0 token, device and authorization endpoints; the tenant is `common`, `organizations`, `consumers`, a GUID or a domain, anything else is an error |

## Google service accounts

| Function | Returns | Does |
|---|---|---|
| `oauthext.googleServiceAccount(keyJson as string, scope as string)` | `oauth.Token` | read the key file, sign an assertion for `scope` and trade it for a token (about an hour, no refresh token) |
| `oauthext.googleServiceAccountAs(keyJson as string, scope as string, subject as string)` | `oauth.Token` | the same, acting for the user `subject` (domain-wide delegation); `""` for the account itself |
| `oauthext.serviceAccount(keyJson as string)` | `ServiceAccount` | read and check a key file: `type` `service_account`, `client_email`, a PKCS#8 `private_key`, `private_key_id`, an https `token_uri` (or http on this machine) |
| `oauthext.serviceAccountAssertion(sa as ServiceAccount, scope as string, subject as string)` | `string` | the signed RS256 assertion: `kid` the key id, `iss` the account, `aud` the token endpoint, `scope` as a claim, one hour |

## Constants

| Constant | Value | Meaning |
|---|---|---|
| `oauthext.GOOGLE_TOKEN_URL` | `"https://oauth2.googleapis.com/token"` | Google's token endpoint |
| `oauthext.GOOGLE_AUTHORIZE_URL` | `"https://accounts.google.com/o/oauth2/v2/auth"` | Google's authorization endpoint |
| `oauthext.GOOGLE_DEVICE_URL` | `"https://oauth2.googleapis.com/device/code"` | Google's device-authorization endpoint |
| `oauthext.SERVICE_ACCOUNT_LIFETIME` | `3600` | seconds a service-account assertion is valid, Google's maximum |

## Types

### `ServiceAccount`

| Field | Meaning |
|---|---|
| `clientEmail as string` | the account, `name@project.iam.gserviceaccount.com` |
| `privateKey as string` | its PKCS#8 PEM private key |
| `privateKeyId as string` | the key's id, the assertion's `kid` |
| `tokenUri as string` | the token endpoint the assertion is for |
| `projectId as string` | the Google Cloud project, `""` if the file names none |
