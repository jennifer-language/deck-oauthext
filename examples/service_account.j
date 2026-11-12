#!/usr/bin/env -S jennifer run
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.26.0

/**
 * Log in as a Google service account and list a Cloud Storage bucket:
 * GOOGLE_APPLICATION_CREDENTIALS=key.json BUCKET=my-bucket jennifer run examples/service_account.j
 *
 * With the variables unset it prints how to run it, so CI runs it without a
 * key or a network.
 */
use fs;
use io;
use json;
use os;
use regex;
use strings;

import "http.j" as http;
import "uri.j" as uri;
import "oauth.j" as oauth;
import "../src/oauthext.j" as oauthext;

def keyPath as string init os.getEnv("GOOGLE_APPLICATION_CREDENTIALS");
def bucket as string init os.getEnv("BUCKET");

if ($keyPath == "" or $bucket == "") {
    io.printf("set GOOGLE_APPLICATION_CREDENTIALS to a service-account key file and BUCKET to a bucket\n");
} else {
    try {
        def tok as oauth.Token init oauthext.googleServiceAccount(
            fs.readString($keyPath),
            "https://www.googleapis.com/auth/devstorage.read_only");
        def r as http.Response init http.get(
            "https://storage.googleapis.com/storage/v1/b/" + uri.encode($bucket) + "/o",
            {"Authorization": "Bearer " + $tok.accessToken});
        if ($r.status != 200) {
            # the server's text: a short excerpt, without control characters
            def excerpt as string init $r.body;
            if (len($excerpt) > 200) {
                $excerpt = strings.substring($excerpt, 0, 200) + "...";
            }
            io.printf(
                "HTTP %d: %s\n",
                $r.status,
                regex.replace('[\x00-\x1f\x7f-\x9f]', $excerpt, "?"));
        } else {
            def items as json.Value init json.decode($r.body);
            if (json.has($items, "/items")) {
                for (def i in 0..json.length($items, "/items")) {
                    io.printf("%s\n", json.asString($items, "/items/{$i}/name"));
                }
            }
        }
    } catch (e) {
        io.printf("%s: %s\n", $e.kind, $e.message);
    }
}
