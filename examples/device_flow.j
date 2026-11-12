#!/usr/bin/env -S jennifer run
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.26.0

/**
 * Sign in to Microsoft 365 from a terminal with the device flow and print the
 * SASL XOAUTH2 string for IMAP:
 * MS_CLIENT_ID=... MS_USER=ada@example.com jennifer run examples/device_flow.j
 *
 * MS_TENANT defaults to `common`. With the variables unset it prints how to
 * run it, so CI runs it without an account or a network.
 */
use io;
use os;

import "oauth.j" as oauth;
import "sasl.j" as sasl;
import "../src/oauthext.j" as oauthext;

def clientId as string init os.getEnv("MS_CLIENT_ID");
def user as string init os.getEnv("MS_USER");
def tenant as string init os.getEnv("MS_TENANT");
if ($tenant == "") {
    $tenant = "common";
}

if ($clientId == "" or $user == "") {
    io.printf("set MS_CLIENT_ID to an Entra ID app's client id and MS_USER to the mailbox\n");
} else {
    try {
        def cfg as oauth.Config init oauthext.microsoft(
            $tenant,
            $clientId,
            "",
            "https://outlook.office.com/IMAP.AccessAsUser.All offline_access");
        def dev as oauth.DeviceAuth init oauth.deviceStart($cfg);
        io.printf("visit %s and enter %s\n", $dev.verificationUri, $dev.userCode);
        def tok as oauth.Token init oauth.deviceWait($cfg, $dev);
        io.printf("XOAUTH2: %s\n", sasl.bearer($user, $tok.accessToken));
    } catch (e) {
        io.printf("%s: %s\n", $e.kind, $e.message);
    }
}
