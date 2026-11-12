<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# Google and Microsoft presets

A preset is an `oauth.Config` with the provider's token, device and
authorization endpoints filled in. Use it with the bundled module's flows:
`oauth.deviceStart` and `oauth.deviceWait` for a user signing in from a
terminal, `oauth.authorize` / `awaitCode` / `exchangeCode` for a browser
sign-in, `oauth.refresh` to keep a token alive, `oauth.clientCredentials` for
an application acting as itself.

For Google, or an Entra ID tenant named by its GUID, `oauth.discover` gives
the same endpoints from the provider's metadata. The Microsoft preset is still
needed for `common`, `organizations`, `consumers` and a tenant named by a
domain: their metadata names a placeholder issuer or the tenant's GUID, which
`discover` refuses because it is not the issuer asked for.

## Google

Gmail, Calendar and most Google APIs need the browser sign-in: Google's device
flow allows only a short list of scopes (`openid`, `email`, `profile`,
`drive.file`, `drive.appdata` and some YouTube ones). Use an OAuth client of
the type "Desktop app"; Google accepts any loopback port as its redirect.

```jennifer
def cfg as oauth.Config init oauthext.google($clientId, $clientSecret,
    "https://mail.google.com/");
def srv as httpd.Server init httpd.listen("127.0.0.1:0");
def req as oauth.AuthRequest init oauth.authorizeWith($cfg,
    "http://" + httpd.address($srv) + "/callback",
    {"access_type": "offline", "prompt": "consent"});
io.printf("open %s\n", $req.url);
def tok as oauth.Token init oauth.exchangeCode($cfg, $req, oauth.awaitCode($req, $srv));
httpd.shutdown($srv);
```

Google issues a refresh token only when asked for offline access
(`access_type=offline`), and on a later sign-in only with `prompt=consent`;
without them `tok.refreshToken` is empty and `oauth.refresh` has nothing to
trade.

For the scopes the device flow allows, an OAuth client of the type "TVs and
Limited Input devices" signs in from a terminal:

```jennifer
def cfg as oauth.Config init oauthext.google($clientId, $clientSecret, "openid email");
def dev as oauth.DeviceAuth init oauth.deviceStart($cfg);
io.printf("visit %s and enter %s\n", $dev.verificationUri, $dev.userCode);
def tok as oauth.Token init oauth.deviceWait($cfg, $dev);
```

For a program with no user at all, use a [service account](service-accounts.md)
instead.

## Microsoft

```jennifer
def cfg as oauth.Config init oauthext.microsoft("common", $clientId, "",
    "https://outlook.office.com/IMAP.AccessAsUser.All offline_access");
```

The tenant is `common` (work, school and personal accounts), `organizations`,
`consumers`, the tenant's GUID or one of its domains
(`contoso.onmicrosoft.com`). Anything else is refused, since it becomes part of
the endpoint URL. A public client (device flow) has no secret: pass `""`. Ask
for `offline_access` to get a refresh token.

## Mail

A token for the mail scopes - Google's through the browser sign-in,
Microsoft's through either flow - signs in to IMAP and SMTP through SASL
XOAUTH2 with the bundled `sasl` module:

```jennifer
def xoauth as string init sasl.bearer("ada@example.com", $tok.accessToken);
```
