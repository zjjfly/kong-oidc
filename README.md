# What is Kong OIDC plugin
**this repo is forked from https://github.com/revomatico/kong-oidc,it supports multiple clients and preflight request bypass.In addtion,behaviour of verifing bearer token has been adjusted,it happened only if bearer token provided**

**kong-oidc** is a plugin for [Kong](https://github.com/kong/kong) implementing the
[OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html) Relying Party (RP) functionality.

It authenticates users against an OpenID Connect Provider using
[OpenID Connect Discovery](http://openid.net/specs/openid-connect-discovery-1_0.html)
and the Basic Client Profile (i.e. the Authorization Code flow).

It maintains sessions for authenticated users by leveraging `lua-resty-openidc` thus offering
a configurable choice between storing the session state in a client-side browser cookie or use
in of the server-side storage mechanisms `shared-memory|memcache|redis`.

> **Note:** at the moment, there is an issue using memcached/redis, probably due to session locking: the sessions freeze. Help to debug this is appreciated. I am currently using shared memory to store sessions.

It supports server-wide caching of resolved Discovery documents and validated Access Tokens.

It can be used as a reverse proxy terminating OAuth/OpenID Connect in front of an origin server so that
the origin server/services can be protected with the relevant standards without implementing those on
the server itself.

The introspection functionality adds capability for already authenticated users and/or applications that
already possess access token to go through kong. The actual token verification is then done by Resource Server.

## How does it work

The diagram below shows the message exchange between the involved parties.

![alt Kong OIDC flow](docs/kong_oidc_flow.png)

The `X-Userinfo` header contains the payload from the Userinfo Endpoint

```json
X-Userinfo: {"preferred_username":"alice","id":"60f65308-3510-40ca-83f0-e9c0151cc680","sub":"60f65308-3510-40ca-83f0-e9c0151cc680"}
```

The plugin also sets the `ngx.ctx.authenticated_credential` variable, which can be using in other Kong plugins:

```lua
ngx.ctx.authenticated_credential = {
    id = "60f65308-3510-40ca-83f0-e9c0151cc680",   -- sub field from Userinfo
    username = "alice"                             -- preferred_username from Userinfo
}
```

For successfully authenticated request, possible (anonymous) consumer identity set by higher priority plugin is cleared as part of setting the credentials.

The plugin will try to retrieve the user's groups from a field in the token (default `groups`) and set `kong.ctx.shared.authenticated_groups` so that Kong authorization plugins can make decisions based on the user's group membership.

## Dependencies

**kong-oidc** depends on the following package:

- [`lua-resty-openidc`](https://github.com/zmartzone/lua-resty-openidc/)

## Installation

If you're using `luarocks` execute the following:

     luarocks install kong-oidc

[Kong >= 0.14] Since `KONG_CUSTOM_PLUGINS` has been removed, you also need to set the `KONG_PLUGINS` environment variable to include besides the bundled ones, oidc

     export KONG_PLUGINS=bundled,oidc

## Usage

### Parameters

| Parameter                                   | Default                                    | Required | description                                                                                                                                                                             |
| ------------------------------------------- | ------------------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`                                      |                                            | true     | plugin name, has to be `oidc`                                                                                                                                                           |
| `config.client_id`                          |                                            | true     | OIDC Client ID(s)                                                                                                                                                                          |
| `config.client_secret`                      |                                            | true     | OIDC Client secret(s)                                                                                                                                                                     |
| `config.client_arg`                          | Client_ID                                 | true     | Header key contains Client ID                                                                                                                                                                          |
| `config.discovery`                          | <https://.well-known/openid-configuration> | false    | OIDC Discovery Endpoint (`/.well-known/openid-configuration`)                                                                                                                           |
| `config.scope`                              | openid                                     | false    | OAuth2 Token scope. To use OIDC it has to contains the `openid` scope                                                                                                                   |
| `config.ssl_verify`                         | false                                      | false    | Enable SSL verification to OIDC Provider                                                                                                                                                |
| `config.session_secret`                     |                                            | false    | Additional parameter, which is used to encrypt the session cookie. Needs to be random                                                                                                   |
| `config.introspection_endpoint`             |                                            | false    | Token introspection endpoint                                                                                                                                                            |
| `config.timeout`                            |                                            | false    | OIDC endpoint calls timeout                                                                                                                                                             |
| `config.introspection_endpoint_auth_method` | client_secret_basic                        | false    | Token introspection authentication method. `resty-openidc` supports `client_secret_(basic\|post)`                                                                                       |
| `config.bearer_only`                        | no                                         | false    | Only introspect tokens without redirecting                                                                                                                                              |
| `config.realm`                              | kong                                       | false    | Realm used in WWW-Authenticate response header                                                                                                                                          |
| `config.logout_path`                        | /logout                                    | false    | Absolute path used to logout from the OIDC RP                                                                                                                                           |
| `config.unauth_action`                      | auth                                       | false    | What action to take when unauthenticated <br> - `auth` to redirect to the login page and attempt (re)authenticatation,<br> - `deny` to stop with 401                                    |
| `config.recovery_page_path`                 |                                            | false    | Path of a recovery page to redirect the user when error occurs (except 401). To not show any error, you can use '/' to redirect immediately home. The error will be logged server side. |
| `config.ignore_auth_filters`                |                                            | false    | A comma-separated list of endpoints to bypass authentication for                                                                                                                        |
| `config.redirect_uri`                       |                                            | false    | A relative or absolute URI the OP will redirect to after successful authentication                                                                                                      |
| `config.userinfo_header_name`               | `X-Userinfo`                               | false    | The name of the HTTP header to use when passing the UserInfo to the upstream server                                                                                                     |
| `config.id_token_header_name`               | `X-ID-Token`                               | false    | The name of the HTTP header to use when passing the ID Token to the upstream server                                                                                                     |
| `config.access_token_header_name`           | `X-Access-Token`                           | false    | The name of the HTTP header to use when passing the Access Token to the upstream server                                                                                                 |
| `config.access_token_as_bearer`             | no                                         | false    | Whether or not the access token should be passed as a Bearer token                                                                                                                      |
| `config.disable_userinfo_header`            | no                                         | false    | Disable passing the Userinfo to the upstream server                                                                                                                                     |
| `config.disable_id_token_header`            | no                                         | false    | Disable passing the ID Token to the upstream server                                                                                                                                     |
| `config.disable_access_token_header`        | no                                         | false    | Disable passing the Access Token to the upstream server                                                                                                                                 |
| `config.groups_claim`                       | groups                                     | false    | Name of the claim in the token to get groups from                                                                                                                                       |
| `config.skip_already_auth_requests`         | no                                         | false    | Ignore requests where credentials have already been set by a higher priority plugin such as basic-auth                                                                                  |
| `config.bearer_jwt_auth_enable`             | no                                         | false    | Authenticate based on JWT (ID) token if it is in Authorization (Bearer) header. Checks iss, sub, aud, exp, iat (as in ID token). `config.discovery` must be defined to discover JWKS    |
| `config.bearer_jwt_auth_allowed_auds`       |                                            | false    | List of JWT token `aud` values allowed when validating JWT token in Authorization header. If not provided, uses value from `config.client_id`                                           |
| `config.bearer_jwt_auth_signing_algs`       | [ 'RS256' ]                                | false    | List of allowed signing algorithms for Authorization header JWT token validation. Must match to OIDC provider and `resty-openidc` supported algorithms                                  |
| `config.header_names`                       |                                            | false    | List of custom upstream HTTP headers to be added based on claims. Must have same number of elements as `config.header_claims`. Example: `[ 'x-oidc-email', 'x-oidc-email-verified' ]`   |
| `config.header_claims`                      |                                            | false    | List of claims to be used as source for custom upstream headers. Claims are sourced from Userinfo, ID Token, Bearer JWT, Introspection, depending on auth method.  Use only claims containing simple string values. Example: `[ 'email', 'email_verified'` |
| `config.`bypass_preflight_request                      |                                            | false    | Flag to determine whether this plugin bypass the preflight requests |

### Enabling kong-oidc

To enable the plugin only for one API:

```http
POST /apis/<api_id>/plugins/ HTTP/1.1
Host: localhost:8001
Content-Type: application/x-www-form-urlencoded
Cache-Control: no-cache

name=oidc&config.client_id=kong-oidc&config.client_secret=29d98bf7-168c-4874-b8e9-9ba5e7382fa0&config.discovery=https%3A%2F%2F<oidc_provider>%2F.well-known%2Fopenid-configuration
```

To enable the plugin globally:

```http
POST /plugins HTTP/1.1
Host: localhost:8001
Content-Type: application/x-www-form-urlencoded
Cache-Control: no-cache

name=oidc&config.client_id=kong-oidc&config.client_secret=29d98bf7-168c-4874-b8e9-9ba5e7382fa0&config.discovery=https%3A%2F%2F<oidc_provider>%2F.well-known%2Fopenid-configuration
```

A successful response:

```http
HTTP/1.1 201 Created
Date: Tue, 24 Oct 2017 19:37:38 GMT
Content-Type: application/json; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Access-Control-Allow-Origin: *
Server: kong/0.11.0

{
    "created_at": 1508871239797,
    "config": {
        "response_type": "code",
        "client_id": ["kong-oidc"],
        "discovery": "https://<oidc_provider>/.well-known/openid-configuration",
        "scope": "openid",
        "ssl_verify": "no",
        "client_secret": ["29d98bf7-168c-4874-b8e9-9ba5e7382fa0"],
        "token_endpoint_auth_method": "client_secret_post"
    },
    "id": "58cc119b-e5d0-4908-8929-7d6ed73cb7de",
    "enabled": true,
    "name": "oidc",
    "api_id": "32625081-c712-4c46-b16a-5d6d9081f85f"
}
```

### Upstream API request

For successfully authenticated request, the plugin will set upstream header `X-Credential-Identifier` to contain `sub` claim from user info, ID token or introspection result. Header `X-Anonymous-Consumer` is cleared.

The plugin adds a additional `X-Userinfo`, `X-Access-Token` and `X-Id-Token` headers to the upstream request, which can be consumer by upstream server. All of them are base64 encoded:

```http
GET / HTTP/1.1
Host: netcat:9000
Connection: keep-alive
X-Forwarded-For: 172.19.0.1
X-Forwarded-Proto: http
X-Forwarded-Host: localhost
X-Forwarded-Port: 8000
X-Real-IP: 172.19.0.1
Cache-Control: max-age=0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: pl-PL,pl;q=0.8,en-US;q=0.6,en;q=0.4
Cookie: session=KOn1am4mhQLKazlCA.....
X-Userinfo: eyJnaXZlbl9uYW1lIjoixITEmMWaw5PFgcW7xbnEhiIsInN1YiI6ImM4NThiYzAxLTBiM2ItNDQzNy1hMGVlLWE1ZTY0ODkwMDE5ZCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFkbWluIiwibmFtZSI6IsSExJjFmsOTxYHFu8W5xIYiLCJ1c2VybmFtZSI6ImFkbWluIiwiaWQiOiJjODU4YmMwMS0wYjNiLTQ0MzctYTBlZS1hNWU2NDg5MDAxOWQifQ==
X-Access-Token: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJGenFSY0N1Ry13dzlrQUJBVng1ZG9sT2ZwTFhBNWZiRGFlVDRiemtnSzZRIn0.eyJqdGkiOiIxYjhmYzlkMC1jMjlmLTQwY2ItYWM4OC1kNzMyY2FkODcxY2IiLCJleHAiOjE1NDg1MTA4MjksIm5iZiI6MCwiaWF0IjoxNTQ4NTEwNzY5LCJpc3MiOiJodHRwOi8vMTkyLjE2OC4wLjk6ODA4MC9hdXRoL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOlsibWFzdGVyLXJlYWxtIiwiYWNjb3VudCJdLCJzdWIiOiJhNmE3OGQ5MS01NDk0LTRjZTMtOTU1NS04NzhhMTg1Y2E0YjkiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJrb25nIiwibm9uY2UiOiJmNGRkNDU2YzBjZTY4ZmFmYWJmNGY4ZDA3YjQ0YWE4NiIsImF1dGhfdGltZSI6…IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiJ9.GWuguFjSEDGxw_vbD04UMKxtai15BE2lwBO0YkSzp-NKZ2SxAzl0nyhZxpP0VTzk712nQ8f_If5-mQBf_rqEVnOraDmX5NOXP0B8AoaS1jsdq4EomrhZGqlWmuaV71Cnqrw66iaouBR_6Q0s8bgc1FpCPyACM4VWs57CBdTrAZ2iv8dau5ODkbEvSgIgoLgBbUvjRKz1H0KyeBcXlVSgHJ_2zB9q2HvidBsQEIwTP8sWc6er-5AltLbV8ceBg5OaZ4xHoramMoz2xW-ttjIujS382QQn3iekNByb62O2cssTP3UYC747ehXReCrNZmDA6ecdnv8vOfIem3xNEnEmQw
X-Id-Token: eyJuYmYiOjAsImF6cCI6ImtvbmciLCJpYXQiOjE1NDg1MTA3NjksImlzcyI6Imh0dHA6XC9cLzE5Mi4xNjguMC45OjgwODBcL2F1dGhcL3JlYWxtc1wvbWFzdGVyIiwiYXVkIjoia29uZyIsIm5vbmNlIjoiZjRkZDQ1NmMwY2U2OGZhZmFiZjRmOGQwN2I0NGFhODYiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiIsImF1dGhfdGltZSI6MTU0ODUxMDY5NywiYWNyIjoiMSIsInNlc3Npb25fc3RhdGUiOiJiNDZmODU2Ny0zODA3LTQ0YmMtYmU1Mi1iMTNiNWQzODI5MTQiLCJleHAiOjE1NDg1MTA4MjksImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwianRpIjoiMjI1ZDRhNDItM2Y3ZC00Y2I2LTkxMmMtOGNkYzM0Y2JiNTk2Iiwic3ViIjoiYTZhNzhkOTEtNTQ5NC00Y2UzLTk1NTUtODc4YTE4NWNhNGI5IiwidHlwIjoiSUQifQ==
```

### Standard OpenID Connect Scopes and Claims

The OpenID Connect Core 1.0 profile specifies the following standard scopes and claims:

| Scope     | Claim(s)                                                                                                                               |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `openid`  | `sub`. In an ID Token, `iss`, `aud`, `exp`, `iat` will also be provided.                                                               |
| `profile` | Typically claims like `name`, `family_name`, `given_name`, `middle_name`, `preferred_username`, `nickname`, `picture` and `updated_at` |
| `email`   | `email` and `email_verified` (_boolean_) indicating if the email address has been verified by the user                                 |

_Note that the `openid` scope is a mandatory designator scope._

#### Description of the standard claims

| Claim                | Type           | Description                                                                                                                                                 |
| -------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `iss`                | URI            | The Uniform Resource Identifier uniquely identifying the OpenID Connect Provider (_OP_)                                                                     |
| `aud`                | string / array | The intended audiences. For ID tokens, the identity token is one or more clients. For Access tokens, the audience is typically one or more Resource Servers |
| `nbf`                | integer        | _Not before_ timestamp in Unix Epoch time\*. May be omitted or set to 0 to indicate that the audience can disregard the claim                               |
| `exp`                | integer        | _Expires_ timestamp in Unix Epoch time\*                                                                                                                    |
| `name`               | string         | Preferred display name. Ex. `John Doe`                                                                                                                      |
| `family_name`        | string         | Last name. Ex. `Doe`                                                                                                                                        |
| `given_name`         | string         | First name. Ex. `John`                                                                                                                                      |
| `middle_name`        | string         | Middle name. Ex. `Donald`                                                                                                                                   |
| `nickname`           | string         | Nick name. Ex. `Johnny`                                                                                                                                     |
| `preferred_username` | string         | Preferred user name. Ex. `johdoe`                                                                                                                           |
| `picture`            | base64         | A Base-64 encoded picture (typically PNG or JPEG) of the subject                                                                                            |
| `updated_at`         | integer        | A timestamp in Unix Epoch time\*                                                                                                                            |

`*` (Seconds since January 1st 1970).

### Passing the Access token as a normal Bearer token

To pass the access token to the upstream server as a normal Bearer token, configure the plugin as follows:

| Key                                    | Value           |
| -------------------------------------- | --------------- |
| `config.access_token_header_name`      | `Authorization` |
| `config.access_token_as_bearer`        | `yes`           |

## Development

### Running Unit Tests

To run unit tests, run the following command:

```shell
./bin/run-unit-tests.sh
```

This may take a while for the first run, as the docker image will need to be built, but subsequent runs will be quick.

### Building the Integration Test Environment

To build the integration environment (Kong with the oidc plugin enabled, and Keycloak as the OIDC Provider), you will first need to find your computer's IP, and assign that to the environment variable `IP`. Finally, you will run the `./bin/build-env.sh` command. Here's an example:

```shell
export IP=192.168.0.1
./bin/build-env.sh
```

To tear the environment down:

```shell
./bin/teardown-env.sh
```
