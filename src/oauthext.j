# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.26.0
# pragma-jennifer-capability: net

/**
 * Vendor-specific OAuth2 on top of the bundled `oauth` module, which keeps
 * only the standard grants. Here live the parts that encode one provider's
 * endpoints, key formats or claim conventions: `Config` presets for Google and
 * Microsoft (Entra ID), and Google service accounts, which sign an RFC 7523
 * assertion with the key from their JSON key file and trade it for a token
 * through `oauth.jwtBearer`.
 *
 * A problem with the deck's own input (a key file, a tenant, a scope) is an
 * `Error` of kind "oauthext"; a failed request or a refusal from the token
 * endpoint keeps the `oauth` module's kind "oauth".
 *
 * @module oauthext
 * @example
 *   def tok as oauth.Token init oauthext.googleServiceAccount(
 *       fs.readString("service-account.json"),
 *       "https://www.googleapis.com/auth/cloud-platform");
 */
use convert;
use json;
use lists;
use regex;
use strings;

import "oauth.j" as oauth;
import "uri.j" as uri;

/** Google's token endpoint. */
export def const GOOGLE_TOKEN_URL as string init "https://oauth2.googleapis.com/token";

/** Google's authorization endpoint, for `oauth.authorize`. */
export def const GOOGLE_AUTHORIZE_URL as string init "https://accounts.google.com/o/oauth2/v2/auth";

/** Google's device-authorization endpoint. */
export def const GOOGLE_DEVICE_URL as string init "https://oauth2.googleapis.com/device/code";

/** The lifetime of a service-account assertion, in seconds: Google's maximum, one hour. */
export def const SERVICE_ACCOUNT_LIFETIME as int init 3600;

# a tenant is a name Microsoft accepts in the URL path: `common`,
# `organizations`, `consumers`, a GUID or a domain: dot-separated labels of
# letters, digits and inner hyphens
def const TENANT as string init
    '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$';

# an e-mail address: one `@`, no space or control character before it, a
# domain after it
def const EMAIL as string init
    '^[^@\x00-\x20\x7f-\x9f]+@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$';

# control characters, which no scope holds
def const CONTROL as string init '[\x00-\x1f\x7f-\x9f]';

# control characters and whitespace, which no URL, e-mail address or key id holds
def const SPACE_OR_CONTROL as string init '[\x00-\x20\x7f-\x9f]';

# the hosts a token endpoint may be plain http on: an emulator on this machine
def const LOOPBACK as list of string init ["127.0.0.1", "localhost", "[::1]"];

/**
 * A Google service-account key, read from its JSON key file.
 *
 * @field clientEmail {string} the account, `name@project.iam.gserviceaccount.com`
 * @field privateKey {string} its PKCS#8 PEM private key
 * @field privateKeyId {string} the key's id, sent as the assertion's `kid`
 * @field tokenUri {string} the token endpoint the assertion is for
 * @field projectId {string} the Google Cloud project, `""` if the file names none
 */
export def struct ServiceAccount {
    clientEmail as string,
    privateKey as string,
    privateKeyId as string,
    tokenUri as string,
    projectId as string
};

/**
 * Throw an oauthext error.
 *
 * @param message {string} what went wrong, without the `oauthext: ` prefix
 * @throws {Error} kind "oauthext", always
 */
func fail(message as string) {
    throw Error{kind: "oauthext", message: "oauthext: " + $message};
}

/**
 * Text quoted for an error message: at most 80 characters, control characters as `?`.
 *
 * @param s {string} the text
 * @return {string} the text, quoted
 */
func shown(s as string) {
    def t as string init $s;
    if (len($t) > 80) {
        $t = strings.substring($t, 0, 80) + "...";
    }
    return "\"" + regex.replace(CONTROL, $t, "?") + "\"";
}

# --- presets --------------------------------------------------------------

/**
 * A `Config` for Google's OAuth2 endpoints, for the device flow, the browser
 * sign-in (`oauth.authorize`), refresh and client credentials.
 *
 * @param clientId {string} the OAuth2 client id
 * @param clientSecret {string} the client secret
 * @param scope {string} the space-separated scopes
 * @return {oauth.Config} the config
 * @example
 *   def cfg as oauth.Config init oauthext.google($id, $secret, "https://mail.google.com/");
 */
export func google(clientId as string, clientSecret as string, scope as string) {
    return oauth.Config{
        tokenUrl: GOOGLE_TOKEN_URL,
        deviceUrl: GOOGLE_DEVICE_URL,
        authorizeUrl: GOOGLE_AUTHORIZE_URL,
        clientId: $clientId,
        clientSecret: $clientSecret,
        scope: $scope
    };
}

/**
 * A `Config` for a Microsoft Entra ID (Microsoft 365) tenant's v2.0
 * endpoints. Unlike `oauth.discover`, it works for the multi-tenant `common`,
 * `organizations` and `consumers`, whose metadata names a placeholder issuer.
 *
 * @param tenant {string} `common`, `organizations`, `consumers`, the tenant's GUID or one of its domains
 * @param clientId {string} the application (client) id
 * @param clientSecret {string} the client secret, `""` for a public client
 * @param scope {string} the space-separated scopes
 * @return {oauth.Config} the config
 * @throws {Error} kind "oauthext" if the tenant is not a GUID, a domain or one of the three names
 * @example
 *   def cfg as oauth.Config init oauthext.microsoft("common", $id, "",
 *       "https://outlook.office.com/IMAP.AccessAsUser.All offline_access");
 */
export func microsoft(
    tenant as string,
    clientId as string,
    clientSecret as string,
    scope as string) {
    if (len($tenant) > 253 or not regex.matches(TENANT, $tenant)) {
        fail("the tenant must be common, organizations, consumers, a GUID or a domain, got " +
            shown($tenant));
    }
    def base as string init "https://login.microsoftonline.com/" + $tenant + "/oauth2/v2.0";
    return oauth.Config{
        tokenUrl: $base + "/token",
        deviceUrl: $base + "/devicecode",
        authorizeUrl: $base + "/authorize",
        clientId: $clientId,
        clientSecret: $clientSecret,
        scope: $scope
    };
}

# --- Google service accounts ----------------------------------------------

/**
 * Read a Google service-account key file. The file must be a service-account
 * key (`"type": "service_account"`) with `client_email`, `private_key` (PKCS#8
 * PEM), `private_key_id` and `token_uri`; the token endpoint must be https, or
 * plain http on this machine (an emulator).
 *
 * @param keyJson {string} the key file's content
 * @return {ServiceAccount} the key
 * @throws {Error} kind "oauthext" if it is not such a key file
 */
export func serviceAccount(keyJson as string) {
    def key as json.Value;
    try {
        $key = json.decode($keyJson);
    } catch (e) {
        fail("the service-account key is not valid JSON: " + shown($e.message));
    }
    if (json.typeOf($key) != "map") {
        fail("the service-account key is not a JSON object");
    }
    def kind as string init field($key, "type");
    if ($kind != "service_account") {
        fail("the key file is not a service-account key (type " + shown($kind) + ")");
    }
    def email as string init field($key, "client_email");
    if (not regex.matches(EMAIL, $email)) {
        fail("client_email is not an e-mail address: " + shown($email));
    }
    def pem as string init field($key, "private_key");
    def body as string init strings.trim($pem);
    if (not strings.startsWith($body, "-----BEGIN PRIVATE KEY-----") or
        not strings.endsWith($body, "-----END PRIVATE KEY-----") or
        strings.count($body, "-----BEGIN") != 1 or strings.count($body, "-----END") != 1) {
        fail("private_key is not one PKCS#8 PEM private key");
    }
    def kid as string init field($key, "private_key_id");
    if (regex.matches(SPACE_OR_CONTROL, $kid)) {
        fail("private_key_id holds spaces or control characters");
    }
    def tokenUri as string init field($key, "token_uri");
    checkTokenUri($tokenUri);
    def project as string init "";
    if (json.has($key, "/project_id")) {
        if (json.typeOf(json.get($key, "/project_id")) != "string") {
            fail("project_id is not a string");
        }
        $project = json.asString($key, "/project_id");
    }
    return ServiceAccount{
        clientEmail: $email,
        privateKey: $pem,
        privateKeyId: $kid,
        tokenUri: $tokenUri,
        projectId: $project
    };
}

/**
 * A non-empty string field of the key file.
 *
 * @param key {json.Value} the key file
 * @param name {string} the field
 * @return {string} its value
 * @throws {Error} kind "oauthext" if it is missing, not a string or empty
 */
func field(key as json.Value, name as string) {
    if (not json.has($key, "/" + $name)) {
        fail("the service-account key has no " + $name);
    }
    if (json.typeOf(json.get($key, "/" + $name)) != "string") {
        fail($name + " is not a string");
    }
    def v as string init json.asString($key, "/" + $name);
    if ($v == "") {
        fail($name + " is empty");
    }
    return $v;
}

/**
 * Refuse a token endpoint that is not https, or plain http on this machine:
 * it needs a host, and may hold no login part (`user@`), fragment, space or
 * control character.
 *
 * @param url {string} the endpoint
 * @throws {Error} kind "oauthext" if it is neither
 */
func checkTokenUri(url as string) {
    if (regex.matches(SPACE_OR_CONTROL, $url)) {
        fail("token_uri holds spaces or control characters");
    }
    if (not endpointOk($url)) {
        fail("token_uri must be https (or http on this machine), got " + shown($url));
    }
}

/**
 * Whether a URL is https, or plain http on this machine, with a host and no
 * login part or fragment.
 *
 * @param url {string} the URL
 * @return {bool} whether it is
 */
func endpointOk(url as string) {
    if (strings.contains($url, "#") or strings.contains(authority($url), "@")) {
        return false;
    }
    def u as uri.Uri;
    try {
        $u = uri.parse($url);
    } catch (e) {
        return false;
    }
    if ($u.host == "" or $u.user != "" or not regex.matches('^[0-9]*$', $u.port)) {
        return false;
    }
    def scheme as string init strings.lower($u.scheme);
    if ($scheme == "https") {
        return true;
    }
    return $scheme == "http" and lists.contains(LOOPBACK, strings.lower($u.host));
}

/**
 * The part of an absolute URL between `://` and its path, query or fragment.
 *
 * @param url {string} the URL
 * @return {string} the authority, `""` without `://`
 */
func authority(url as string) {
    def at as int init strings.indexOf($url, "://");
    if ($at < 0) {
        return "";
    }
    def rest as string init strings.substring($url, $at + 3);
    for (def stop in ["/", "?", "#"]) {
        def k as int init strings.indexOf($rest, $stop);
        if ($k >= 0) {
            $rest = strings.substring($rest, 0, $k);
        }
    }
    return $rest;
}

/**
 * The signed assertion a service account trades for a token: RS256, `kid` the
 * key's id, `iss` the account, `aud` the token endpoint, `scope` as a claim,
 * valid for `SERVICE_ACCOUNT_LIFETIME` seconds. A non-empty `subject` is the
 * user the account acts for (Google Workspace domain-wide delegation).
 *
 * @param sa {ServiceAccount} the key, from `serviceAccount`
 * @param scope {string} the space-separated scopes
 * @param subject {string} the user to act for, `""` for the account itself
 * @return {string} the compact signed assertion
 * @throws {Error} kind "oauthext" if the scope or subject is unusable or the key cannot sign
 */
export func serviceAccountAssertion(sa as ServiceAccount, scope as string, subject as string) {
    if (strings.trim($scope) == "" or regex.matches(CONTROL, $scope)) {
        fail("the scope must be one or more scope URLs separated by spaces, got " + shown($scope));
    }
    if ($subject != "" and not regex.matches(EMAIL, $subject)) {
        fail("the subject must be a user's e-mail address, got " + shown($subject));
    }
    def extra as json.Value init json.set(json.map(), "/scope", $scope);
    def signed as string init "";
    try {
        $signed = oauth.jwtAssertion(
            "RS256",
            $sa.clientEmail,
            $subject,
            $sa.tokenUri,
            SERVICE_ACCOUNT_LIFETIME,
            $extra,
            convert.bytesFromString("utf-8", $sa.privateKey),
            $sa.privateKeyId);
    } catch (e) {
        fail("cannot sign with the service-account key: " + $e.message);
    }
    return $signed;
}

/**
 * Log in as a Google service account: read its key file, sign an assertion
 * for `scope` and trade it at the key's token endpoint. The token lasts about
 * an hour and has no refresh token; call again for a new one.
 *
 * @param keyJson {string} the key file's content
 * @param scope {string} the space-separated scopes, e.g. `https://www.googleapis.com/auth/cloud-platform`
 * @return {oauth.Token} the access token
 * @throws {Error} kind "oauthext" if the key file or scope is unusable; kind "oauth" if the request fails or Google refuses
 * @example
 *   def tok as oauth.Token init oauthext.googleServiceAccount(
 *       fs.readString("service-account.json"),
 *       "https://www.googleapis.com/auth/devstorage.read_only");
 */
export func googleServiceAccount(keyJson as string, scope as string) {
    return googleServiceAccountAs($keyJson, $scope, "");
}

/**
 * `googleServiceAccount`, acting for a user: the token carries the user's
 * access, as Google Workspace domain-wide delegation grants it to the account.
 *
 * @param keyJson {string} the key file's content
 * @param scope {string} the space-separated scopes
 * @param subject {string} the user's e-mail address, `""` for the account itself
 * @return {oauth.Token} the access token
 * @throws {Error} kind "oauthext" if the key file, scope or subject is unusable; kind "oauth" if the request fails or Google refuses
 */
export func googleServiceAccountAs(keyJson as string, scope as string, subject as string) {
    def sa as ServiceAccount init serviceAccount($keyJson);
    def assertion as string init serviceAccountAssertion($sa, $scope, $subject);
    def cfg as oauth.Config init oauth.Config{
        tokenUrl: $sa.tokenUri,
        deviceUrl: "",
        authorizeUrl: "",
        clientId: "",
        clientSecret: "",
        scope: ""
    };
    return oauth.jwtBearer($cfg, $assertion);
}
