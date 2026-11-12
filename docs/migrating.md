<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# Moving from oauth

Up to Jennifer 0.25 the bundled `oauth` module carried the two presets as
`oauth.google` and `oauth.microsoft`. From 0.26.0 they are in this deck, with
the same parameters, and the bundled module has only the standard grants.

Add the deck and change the prefix:

```sh
jvc add @jennifer/oauthext
```

```jennifer
import "oauth.j" as oauth;
import "@jennifer/oauthext/" as oauthext;

# before: oauth.google($id, $secret, $scope)
def cfg as oauth.Config init oauthext.google($id, $secret, $scope);
# before: oauth.microsoft($tenant, $id, $secret, $scope)
def ms as oauth.Config init oauthext.microsoft($tenant, $id, $secret, $scope);
```

`oauthext.microsoft` now refuses a tenant that is not `common`,
`organizations`, `consumers`, a GUID or a domain.

Without the deck, `oauth.discover` reads a provider's endpoints from its
metadata (`oauth.discover("https://accounts.google.com", $id, $secret,
$scope)`), or write them into the `Config` yourself:

```jennifer
def cfg as oauth.Config init oauth.Config{
    tokenUrl: "https://oauth2.googleapis.com/token",
    deviceUrl: "https://oauth2.googleapis.com/device/code",
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    clientId: $id,
    clientSecret: $secret,
    scope: $scope
};
```

A Google service account built by hand from `oauth.jwtAssertion` and
`oauth.jwtBearer` keeps working; `oauthext.googleServiceAccount` does the same
in one call, with the key file checked first.
