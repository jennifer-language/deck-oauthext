# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.26.0

/**
 * White-box tests for oauthext: jennifer test src/oauthext_test.j
 *
 * Service-account keys are made fresh with `crypto.keypair("rsa2048")`, which
 * gives the PKCS#8 PEM a Google key file holds, so no private key is checked
 * in. The token endpoint is a loopback `httpd` fake.
 */
use crypto;
use httpd;
use maps;
use task;
use testing;
use time;

import "jwt.j" as jwt;
import "uri.j" as uri;

/** A key file and the public key that verifies what it signs. */
def struct TestKey {
    file as string,
    publicKey as bytes
};

/** One request as the fake token endpoint saw it. */
def struct Posted {
    method as string,
    contentType as string,
    form as map of string to string
};

/**
 * A service-account key file with a fresh key.
 *
 * @param tokenUri {string} its token_uri
 * @return {TestKey} the file and its public key
 */
func keyFile(tokenUri as string) {
    def kp as crypto.Keypair init crypto.keypair("rsa2048");
    def k as json.Value init json.map();
    $k = json.set($k, "/type", "service_account");
    $k = json.set($k, "/project_id", "demo-project");
    $k = json.set($k, "/private_key_id", "0123abcd");
    $k = json.set($k, "/private_key", convert.stringFromBytes("utf-8", $kp.private));
    $k = json.set($k, "/client_email", "robot@demo-project.iam.gserviceaccount.com");
    $k = json.set($k, "/client_id", "1234567890");
    $k = json.set($k, "/token_uri", $tokenUri);
    return TestKey{file: json.encode($k), publicKey: $kp.public};
}

/**
 * The key file with one field set to a string.
 *
 * @param file {string} the key file
 * @param name {string} the field
 * @param value {string} its new value
 * @return {string} the changed file
 */
func withString(file as string, name as string, value as string) {
    return json.encode(json.set(json.decode($file), "/" + $name, $value));
}

/**
 * The key file with one field set to a number.
 *
 * @param file {string} the key file
 * @param name {string} the field
 * @param value {int} its new value
 * @return {string} the changed file
 */
func withNumber(file as string, name as string, value as int) {
    return json.encode(json.set(json.decode($file), "/" + $name, $value));
}

/**
 * The message `serviceAccount` throws for a key file, `""` if it accepts it.
 *
 * @param file {string} the key file
 * @return {string} the message
 */
func refusal(file as string) {
    try {
        serviceAccount($file);
    } catch (e) {
        testing.assertEqual($e.kind, "oauthext");
        return $e.message;
    }
    return "";
}

/**
 * Answer one token request with this status and body.
 *
 * @param srv {httpd.Server} the server
 * @param status {int} the HTTP status
 * @param body {string} the JSON body
 * @return {Posted} what was posted
 */
func tokenEndpoint(srv as httpd.Server, status as int, body as string) {
    def req as httpd.Request init httpd.accept($srv);
    def seen as Posted init Posted{
        method: httpd.method($req),
        contentType: httpd.header($req, "Content-Type"),
        form: uri.parseQuery(convert.stringFromBytes("utf-8", httpd.body($req)))
    };
    httpd.setHeader($req, "Content-Type", "application/json");
    httpd.respond($req, $status, $body);
    return $seen;
}

func testGooglePreset() {
    def c as oauth.Config init google("id", "secret", "https://mail.google.com/");
    testing.assertEqual($c.tokenUrl, "https://oauth2.googleapis.com/token");
    testing.assertEqual($c.deviceUrl, "https://oauth2.googleapis.com/device/code");
    testing.assertEqual($c.authorizeUrl, "https://accounts.google.com/o/oauth2/v2/auth");
    testing.assertEqual($c.clientId, "id");
    testing.assertEqual($c.clientSecret, "secret");
    testing.assertEqual($c.scope, "https://mail.google.com/");
}

func testMicrosoftPreset() {
    def c as oauth.Config init microsoft("contoso.onmicrosoft.com", "id", "", "offline_access");
    testing.assertEqual(
        $c.tokenUrl,
        "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token");
    testing.assertEqual(
        $c.deviceUrl,
        "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/devicecode");
    testing.assertEqual(
        $c.authorizeUrl,
        "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize");
    testing.assertEqual($c.clientSecret, "");
    for (def ok in ["common", "organizations", "consumers", "72f988bf-86f1-41af-91ab-2d7cd011db47"]) {
        testing.assertContains(microsoft($ok, "id", "", "s").tokenUrl, "/" + $ok + "/oauth2/");
    }
}

func testMicrosoftRefusesATenantThatIsNotAName() {
    for (def bad in [
        "",
        "common/../x",
        "a/b",
        "a b",
        "-x",
        "x.",
        "a?b",
        "a#b",
        "%2e%2e",
        strings.repeat("a", 254)
    ]) {
        def msg as string init "";
        try {
            microsoft($bad, "id", "", "s");
        } catch (e) {
            $msg = $e.kind + ": " + $e.message;
        }
        testing.assertContains($msg, "oauthext: oauthext: the tenant must be");
    }
}

func testServiceAccountReadsAKeyFile() {
    def k as TestKey init keyFile("https://oauth2.googleapis.com/token");
    def sa as ServiceAccount init serviceAccount($k.file);
    testing.assertEqual($sa.clientEmail, "robot@demo-project.iam.gserviceaccount.com");
    testing.assertEqual($sa.privateKeyId, "0123abcd");
    testing.assertEqual($sa.tokenUri, "https://oauth2.googleapis.com/token");
    testing.assertEqual($sa.projectId, "demo-project");
    testing.assertTrue(strings.startsWith($sa.privateKey, "-----BEGIN PRIVATE KEY-----"));
    # project_id is optional
    def bare as string init json.encode(json.remove(json.decode($k.file), "/project_id"));
    testing.assertEqual(serviceAccount($bare).projectId, "");
}

func testServiceAccountRefusesBadKeyFiles() {
    def f as string init keyFile("https://oauth2.googleapis.com/token").file;
    def noEmail as string init json.encode(json.remove(json.decode($f), "/client_email"));
    testing.assertContains(refusal('{'), "oauthext: the service-account key is not valid JSON: ");
    testing.assertContains(refusal('{"type":"service_account","type":"x"}'), "not valid JSON: ");
    testing.assertEqual(refusal("[1]"), "oauthext: the service-account key is not a JSON object");
    testing.assertEqual(
        refusal(withString($f, "type", "authorized_user")),
        "oauthext: the key file is not a service-account key (type \"authorized_user\")");
    testing.assertEqual(refusal($noEmail), "oauthext: the service-account key has no client_email");
    testing.assertEqual(
        refusal(withNumber($f, "client_email", 42)),
        "oauthext: client_email is not a string");
    testing.assertEqual(
        refusal(withString($f, "client_email", "")),
        "oauthext: client_email is empty");
    testing.assertEqual(
        refusal(withString($f, "client_email", "robot")),
        "oauthext: client_email is not an e-mail address: \"robot\"");
    testing.assertEqual(
        refusal(withString(
            $f,
            "private_key",
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")),
        "oauthext: private_key is not one PKCS#8 PEM private key");
    testing.assertEqual(
        refusal(withString($f, "private_key_id", "a b")),
        "oauthext: private_key_id holds spaces or control characters");
    testing.assertEqual(
        refusal(withNumber($f, "project_id", 7)),
        "oauthext: project_id is not a string");
    testing.assertEqual(
        refusal(withString($f, "token_uri", "https://x\n.example/token")),
        "oauthext: token_uri holds spaces or control characters");
}

func testTheTokenEndpointMustBeHttpsOrLocal() {
    def f as string init keyFile("https://oauth2.googleapis.com/token").file;
    for (def ok in [
        "https://oauth2.googleapis.com/token",
        "HTTPS://x/token",
        "http://127.0.0.1:9099/token",
        "http://localhost/token",
        "http://[::1]:8080/t"
    ]) {
        testing.assertEqual(refusal(withString($f, "token_uri", $ok)), "");
    }
    for (def bad in [
        "http://oauth2.googleapis.com/token",
        "http://127.0.0.1.evil.example/token",
        "http://localhost.evil.example/",
        "https://",
        "ftp://x/token",
        "oauth2.googleapis.com/token"
    ]) {
        testing.assertContains(
            refusal(withString($f, "token_uri", $bad)),
            "oauthext: token_uri must be https (or http on this machine), got ");
    }
}

func testTheAssertionFollowsGoogleConventions() {
    def k as TestKey init keyFile("https://oauth2.googleapis.com/token");
    def sa as ServiceAccount init serviceAccount($k.file);
    def a as string init serviceAccountAssertion(
        $sa,
        "https://www.googleapis.com/auth/cloud-platform",
        "");
    def claims as json.Value init jwt.verify("RS256", $a, $k.publicKey);
    testing.assertEqual(json.asString($claims, "/iss"), $sa.clientEmail);
    testing.assertEqual(json.asString($claims, "/aud"), "https://oauth2.googleapis.com/token");
    testing.assertEqual(
        json.asString($claims, "/scope"),
        "https://www.googleapis.com/auth/cloud-platform");
    testing.assertFalse(json.has($claims, "/sub"));
    testing.assertEqual(json.asInt($claims, "/exp") - json.asInt($claims, "/iat"), 3600);
    def h as json.Value init jwt.header($a);
    testing.assertEqual(json.asString($h, "/alg"), "RS256");
    testing.assertEqual(json.asString($h, "/kid"), "0123abcd");
    # acting for a user puts them in `sub`
    def as2 as string init serviceAccountAssertion($sa, "s1 s2", "ada@example.com");
    def c2 as json.Value init jwt.verify("RS256", $as2, $k.publicKey);
    testing.assertEqual(json.asString($c2, "/sub"), "ada@example.com");
    testing.assertEqual(json.asString($c2, "/scope"), "s1 s2");
}

func testTheAssertionRefusesABadScopeOrSubject() {
    def sa as ServiceAccount init serviceAccount(keyFile("https://oauth2.googleapis.com/token").file);
    for (def bad in ["", "   ", "a\nb"]) {
        def msg as string init "";
        try {
            serviceAccountAssertion($sa, $bad, "");
        } catch (e) {
            $msg = $e.message;
        }
        testing.assertContains($msg, "oauthext: the scope must be one or more scope URLs");
    }
    for (def bad in ["ada", "ada @example.com", "ada@example.com\r\n"]) {
        def msg as string init "";
        try {
            serviceAccountAssertion($sa, "s", $bad);
        } catch (e) {
            $msg = $e.message;
        }
        testing.assertContains($msg, "oauthext: the subject must be a user's e-mail address");
    }
}

func testAKeyThatCannotSignIsAnOauthextError() {
    def f as string init withString(
        keyFile("https://oauth2.googleapis.com/token").file,
        "private_key",
        "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n");
    def kind as string init "";
    def msg as string init "";
    try {
        serviceAccountAssertion(serviceAccount($f), "s", "");
    } catch (e) {
        $kind = $e.kind;
        $msg = $e.message;
    }
    testing.assertEqual($kind, "oauthext");
    testing.assertContains($msg, "oauthext: cannot sign with the service-account key: ");
}

func testGoogleServiceAccountTradesTheAssertion() {
    def srv as httpd.Server init httpd.listen("127.0.0.1:0");
    def t as task of Posted init spawn {
        return tokenEndpoint(
            $srv,
            200,
            '{"access_token":"ya29.x","expires_in":3599,"token_type":"Bearer"}');
    };
    def url as string init "http://" + httpd.address($srv) + "/token";
    def k as TestKey init keyFile($url);
    def tok as oauth.Token init googleServiceAccountAs(
        $k.file,
        "https://www.googleapis.com/auth/drive",
        "ada@example.com");
    def seen as Posted init task.waitTimeout($t, 10000);
    httpd.shutdown($srv);
    testing.assertEqual($tok.accessToken, "ya29.x");
    testing.assertEqual($tok.tokenType, "Bearer");
    testing.assertEqual($tok.refreshToken, "");
    testing.assertTrue($tok.expiresAt > time.unix(time.now()) + 3500);
    testing.assertEqual($seen.method, "POST");
    testing.assertEqual($seen.contentType, "application/x-www-form-urlencoded");
    testing.assertEqual($seen.form["grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer");
    # the assertion authenticates the client: no id, secret or scope parameter
    testing.assertEqual(maps.keys($seen.form), ["grant_type", "assertion"]);
    def claims as json.Value init jwt.verify("RS256", $seen.form["assertion"], $k.publicKey);
    testing.assertEqual(json.asString($claims, "/aud"), $url);
    testing.assertEqual(json.asString($claims, "/sub"), "ada@example.com");
}

func testARefusalFromGoogleKeepsTheOauthKind() {
    def srv as httpd.Server init httpd.listen("127.0.0.1:0");
    def t as task of Posted init spawn {
        return tokenEndpoint(
            $srv,
            400,
            '{"error":"invalid_grant","error_description":"Invalid JWT Signature."}');
    };
    def k as TestKey init keyFile("http://" + httpd.address($srv) + "/token");
    def kind as string init "";
    def msg as string init "";
    try {
        googleServiceAccount($k.file, "https://www.googleapis.com/auth/drive");
    } catch (e) {
        $kind = $e.kind;
        $msg = $e.message;
    }
    def seen as Posted init task.waitTimeout($t, 10000);
    httpd.shutdown($srv);
    # the account acts for itself: no `sub`
    testing.assertFalse(json.has(jwt.decode($seen.form["assertion"]), "/sub"));
    testing.assertEqual($kind, "oauth");
    testing.assertEqual($msg, "invalid_grant: Invalid JWT Signature.");
}

func testABadKeyFileFailsBeforeAnyRequest() {
    # nothing listens on port 1: a request would fail with a connection error
    def f as string init withString(keyFile("http://127.0.0.1:1/token").file, "type", "user");
    def msg as string init "";
    try {
        googleServiceAccount($f, "s");
    } catch (e) {
        $msg = $e.message;
    }
    testing.assertContains($msg, "oauthext: the key file is not a service-account key");
}

func testKeyFileValuesAreCheckedStrictly() {
    def k as TestKey init keyFile("https://oauth2.googleapis.com/token");
    def f as string init $k.file;
    for (def bad in ["@", "a@", "a@@b", "a@b@c", "@b.example", "a b@c.example", "a@-b.example"]) {
        testing.assertContains(
            refusal(withString($f, "client_email", $bad)),
            "client_email is not an e-mail address");
    }
    # a second key after the first
    def pem as string init serviceAccount($f).privateKey;
    testing.assertEqual(
        refusal(withString($f, "private_key", $pem + $pem)),
        "oauthext: private_key is not one PKCS#8 PEM private key");
    testing.assertEqual(
        refusal(withString($f, "private_key", $pem + "trailing")),
        "oauthext: private_key is not one PKCS#8 PEM private key");
    def sa as ServiceAccount init serviceAccount($f);
    for (def bad in ["@", "a@", "a@@b", "a@b@c"]) {
        def msg as string init "";
        try {
            serviceAccountAssertion($sa, "s", $bad);
        } catch (e) {
            $msg = $e.message;
        }
        testing.assertContains($msg, "the subject must be a user's e-mail address");
    }
}

func testATokenUriCannotHideItsHost() {
    def f as string init keyFile("https://oauth2.googleapis.com/token").file;
    for (def bad in [
        "http://localhost:1@127.0.0.2:4/token",
        "http://[::1]@evil.example/token",
        "http://127.0.0.1:80@evil.example/token",
        "https://u@oauth2.googleapis.com/token",
        "https://?",
        "https://#",
        "https:///token",
        "https://@",
        "https://a.example/t#f",
        "https://a.example:x/t"
    ]) {
        testing.assertContains(
            refusal(withString($f, "token_uri", $bad)),
            "oauthext: token_uri must be https (or http on this machine), got ");
    }
}

func testTenantLabelsAreChecked() {
    for (def bad in ["a..b", ".a", "a.", "-a.example", "a-.example"]) {
        def msg as string init "";
        try {
            microsoft($bad, "id", "", "s");
        } catch (e) {
            $msg = $e.message;
        }
        testing.assertContains($msg, "the tenant must be");
    }
    # punycode labels hold double hyphens
    testing.assertContains(
        microsoft("xn--bcher-kva.example", "id", "", "s").tokenUrl,
        "/xn--bcher-kva.example/");
}

func testANonJsonAnswerFromGoogleIsAnOauthError() {
    def srv as httpd.Server init httpd.listen("127.0.0.1:0");
    def t as task of Posted init spawn {
        return tokenEndpoint($srv, 502, "<html>Bad Gateway</html>");
    };
    def k as TestKey init keyFile("http://" + httpd.address($srv) + "/token");
    def msg as string init "";
    try {
        googleServiceAccount($k.file, "s");
    } catch (e) {
        $msg = $e.kind + ": " + $e.message;
    }
    task.waitTimeout($t, 10000);
    httpd.shutdown($srv);
    testing.assertEqual($msg, "oauth: non-JSON response from the token endpoint (HTTP 502)");
}
