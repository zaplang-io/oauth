import oauth

struct _TokenReply:
    int64 status
    str body
    dict[str, str] headers = {}
    int64 delay_ms = 0

def _serve_token_reply(bytes listener, _TokenReply reply, channel[bytes] requests):
    try:
        auto connection = net.accept(listener)
        try:
            auto request = http.read_request(connection)
            requests <- request
            if reply.delay_ms > 0:
                time.sleep_for(time.millis(reply.delay_ms))
            else:
                http.respond(connection, reply.status, reply.body, reply.headers)
        finally:
            net.close_conn(connection)
    finally:
        net.close_listener(listener)

def _success() -> _TokenReply:
    return _TokenReply(
        200,
        "{\"access_token\":\"issued\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"read write\"}",
    )

def _serve_fetch(_TokenReply reply) -> oauth.Token:
    auto listener = net.listen("127.0.0.1", 0)
    auto client = oauth.Client(
        "client",
        "secret",
        http.url("127.0.0.1", net.port(listener), "/token"),
        timeout=3000,
    )
    auto requests = channel[bytes](1)
    scope:
        spawn _serve_token_reply(listener, reply, requests)
        return client.fetch_token({"grant_type": "client_credentials"})

@test
def _basic_is_default_and_sends_form():
    auto listener = net.listen("127.0.0.1", 0)
    auto endpoint = http.url("127.0.0.1", net.port(listener), "/token")
    auto client = oauth.Client("client:id +", "secret&☃=", endpoint, timeout=3000)
    auto requests = channel[bytes](1)
    auto form = {"grant_type": "authorization_code", "code+key": "a b+c&é", "empty": ""}
    scope:
        spawn _serve_token_reply(listener, _success(), requests)
        auto token = client.fetch_token(form=form)
        assert token.access_token == "issued"
        assert token.scope.unwrap() == "read write"
        auto request = <-requests
        assert http.method(request) == "POST"
        assert http.path(request) == "/token"
        assert http.req_header(request, "content-type") == "application/x-www-form-urlencoded"
        assert http.req_header(request, "accept") == "application/json"
        assert http.req_header(request, "authorization") == "Basic Y2xpZW50JTNBaWQrJTJCOnNlY3JldCUyNiVFMiU5OCU4MyUzRA=="
        auto body = http.req_body(request)
        auto sent = url.parse_query_first(body)
        assert len(sent) == 3
        assert sent["grant_type"] == "authorization_code"
        assert sent["code+key"] == "a b+c&é"
        assert sent["empty"] == ""
        assert "code%2Bkey=a+b%2Bc%26%C3%A9" in body

@test
def _post_credentials_and_caller_form():
    auto listener = net.listen("127.0.0.1", 0)
    auto endpoint = http.url("127.0.0.1", net.port(listener), "/token")
    auto client = oauth.Client(
        "client+id",
        "secret&=☃",
        endpoint,
        token_endpoint_auth_method="client_secret_post",
        timeout=3000,
    )
    auto requests = channel[bytes](1)
    auto form = {"grant_type": "client_credentials", "scope": "read write"}
    scope:
        spawn _serve_token_reply(listener, _success(), requests)
        assert client.fetch_token(form).access_token == "issued"
        auto request = <-requests
        assert http.req_header(request, "authorization") == ""
        auto sent = url.parse_query_first(http.req_body(request))
        assert len(sent) == 4
        assert sent["client_id"] == "client+id"
        assert sent["client_secret"] == "secret&=☃"
        assert sent["grant_type"] == "client_credentials"
        assert sent["scope"] == "read write"
    assert len(form) == 2

@test
def _refresh_uses_endpoint_and_preserves_credential():
    auto listener = net.listen("127.0.0.1", 0)
    auto endpoint = http.url("127.0.0.1", net.port(listener), "/token")
    auto client = oauth.Client("client", "", endpoint, timeout=3000)
    auto requests = channel[bytes](1)
    auto old = oauth.Token(
        "old",
        "Bearer",
        expires_at=Optional.Some(0),
        refresh_token=Optional.Some("old+secret"),
    )
    scope:
        spawn _serve_token_reply(listener, _success(), requests)
        auto current = client.ensure_active_token(old, leeway=0)
        assert current.access_token == "issued"
        assert current.refresh_token.unwrap() == "old+secret"
        assert old.access_token == "old"
        auto request = <-requests
        assert http.req_header(request, "authorization") == "Basic Y2xpZW50Og=="
        auto sent = url.parse_query_first(http.req_body(request))
        assert len(sent) == 2
        assert sent["grant_type"] == "refresh_token"
        assert sent["refresh_token"] == "old+secret"
    auto active = oauth.Token("active", "Bearer")
    assert client.ensure_active_token(active).access_token == "active"

@test
def _invalid_client_carries_structured_provider_fields():
    auto reply = _TokenReply(
        401,
        "{\"error\":\"invalid_client\",\"error_description\":\"credentials rejected\",\"error_uri\":\"https://issuer.example/errors\"}",
        {"WWW-Authenticate": "Basic"},
    )
    auto caught = False
    try:
        _serve_fetch(reply)
    except oauth.InvalidClientError as failure:
        assert failure.error == "invalid_client"
        assert failure.status == 401
        assert failure.error_description.unwrap() == "credentials rejected"
        assert failure.error_uri.unwrap() == "https://issuer.example/errors"
        caught = True
    assert caught

@test
def _base_catch_exposes_fields_for_a_named_error():
    auto caught = False
    try:
        _serve_fetch(
            _TokenReply(
                400,
                "{\"error\":\"invalid_grant\",\"error_description\":\"expired grant\"}",
            ),
        )
    except oauth.TokenEndpointError as failure:
        assert failure.error == "invalid_grant"
        assert failure.status == 400
        assert failure.error_description.unwrap() == "expired grant"
        assert failure.error_uri.is_none()
        caught = True
    assert caught

@test
def _standard_errors_dispatch_and_extension_errors_use_base():
    for code in ["invalid_request", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope", "provider_extension"]:
        auto caught = ""
        try:
            _serve_fetch(_TokenReply(400, "{\"error\":\"" + code + "\"}"))
        except oauth.InvalidRequestError:
            caught = "invalid_request"
        except oauth.InvalidGrantError:
            caught = "invalid_grant"
        except oauth.UnauthorizedClientError:
            caught = "unauthorized_client"
        except oauth.UnsupportedGrantTypeError:
            caught = "unsupported_grant_type"
        except oauth.InvalidScopeError:
            caught = "invalid_scope"
        except oauth.TokenEndpointError as failure:
            assert failure.status == 400
            assert failure.error_description.is_none()
            assert failure.error_uri.is_none()
            caught = failure.error
        assert caught == code

@test
def _http_failures_without_valid_provider_error():
    for reply in [_TokenReply(500, "<html>bad gateway</html>"), _TokenReply(502, "{\"access_token\":\"ignored\",\"token_type\":\"Bearer\"}"), _TokenReply(400, "{\"error\":false}"), _TokenReply(400, "{\"error\":\"invalid_request\",\"error_description\":false}"), _TokenReply(307, "", {"Location": "/other"})]:
        auto caught = False
        try:
            _serve_fetch(reply)
        except oauth.TokenEndpointHTTPError as failure:
            assert failure.status == reply.status
            assert failure.error == ""
            assert failure.error_uri.is_none()
            caught = True
        assert caught

@test
def _success_status_can_report_oauth_error_or_bad_token():
    auto caught = False
    try:
        _serve_fetch(_TokenReply(200, "{\"error\":\"invalid_grant\"}"))
    except oauth.InvalidGrantError as failure:
        caught = failure.status == 200
    assert caught
    for body in ["not JSON", "[]", "{\"access_token\":\"missing-type\"}", "{\"error\":\"\"}", "{\"error\":\"invalid_request\",\"error_uri\":42}"]:
        auto rejected = False
        try:
            _serve_fetch(_TokenReply(200, body))
        except oauth.InvalidTokenError:
            rejected = True
        assert rejected

@test
def _timeout_stays_typed():
    auto listener = net.listen("127.0.0.1", 0)
    auto endpoint = http.url("127.0.0.1", net.port(listener), "/token")
    auto client = oauth.Client("client", "secret", endpoint, timeout=100)
    auto requests = channel[bytes](1)
    auto reply = _TokenReply(200, "", delay_ms=500)
    auto timed_out = False
    scope:
        spawn _serve_token_reply(listener, reply, requests)
        try:
            client.fetch_token({"grant_type": "client_credentials"})
        except TimeoutError:
            timed_out = True
    assert timed_out

def _reject_fetch(oauth.Client client, dict[str, str] form, str expected):
    auto rejected = False
    try:
        client.fetch_token(form)
    except ValueError as message:
        rejected = message == expected
    assert rejected

@test
def _rejects_invalid_request_configuration():
    auto url = "https://issuer.example/token"
    auto client = oauth.Client("client", "secret", url)
    auto form = {"grant_type": "client_credentials"}
    _reject_fetch(client, {}, "grant_type must be non-empty")
    _reject_fetch(client, {"grant_type": ""}, "grant_type must be non-empty")
    _reject_fetch(oauth.Client("", "secret", url), form, "client_id must be non-empty")
    _reject_fetch(
        oauth.Client("client", "secret", url, timeout=-1),
        form,
        "token endpoint timeout must be non-negative",
    )
    _reject_fetch(
        oauth.Client("client", "secret", url, token_endpoint_auth_method="unknown"),
        form,
        "unsupported token endpoint authentication method",
    )
    for field in ["client_id", "client_secret"]:
        auto invalid = form.copy()
        invalid[field] = "injected"
        _reject_fetch(
            client,
            invalid,
            "client credentials must come from the endpoint configuration",
        )
    for endpoint in ["http://issuer.example/token", "ftp://issuer.example/token"]:
        _reject_fetch(
            oauth.Client("client", "secret", endpoint),
            form,
            "token endpoint requires HTTPS outside numeric loopback",
        )
    for endpoint in ["/token", "https:///token", "https://user@issuer.example/token", "https://issuer.example/token#"]:
        _reject_fetch(
            oauth.Client("client", "secret", endpoint),
            form,
            "token endpoint must be an absolute URI without user information or a fragment",
        )
    _reject_fetch(
        oauth.Client("client", "secret", "https://issuer.example/token path"),
        form,
        "token endpoint must be an ASCII URI without whitespace",
    )
