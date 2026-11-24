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

@test
def _form_escapes_names_and_values():
    auto body = _encode_token_form(
        {"grant_type": "authorization_code", "code+key": "a b+c&é", "empty": ""},
    )
    auto fields = url.parse_query_first(body)
    assert len(fields) == 3
    assert fields["grant_type"] == "authorization_code"
    assert fields["code+key"] == "a b+c&é"
    assert fields["empty"] == ""
    assert "code%2Bkey=a+b%2Bc%26%C3%A9" in body
    assert "empty=" in body

@test
def _basic_credentials_are_form_encoded_before_base64():
    assert _basic_authorization("client:id +", "secret&☃=") == "Basic Y2xpZW50JTNBaWQrJTJCOnNlY3JldCUyNiVFMiU5OCU4MyUzRA=="
    assert _basic_authorization("client", "") == "Basic Y2xpZW50Og=="

@test
def _transport_posts_form_and_returns_response():
    auto listener = net.listen("127.0.0.1", 0)
    auto endpoint = http.url("127.0.0.1", net.port(listener), "/token")
    auto requests = channel[bytes](1)
    auto form = {"grant_type": "refresh_token", "refresh_token": "old+credential"}
    scope:
        spawn _serve_token_reply(listener, _success(), requests)
        auto response = _post_token_form(
            endpoint,
            form,
            "client",
            "secret",
            "client_secret_basic",
            3000,
        )
        assert http.status(response) == 200
        assert Token.from_json(http.body(response)).access_token == "issued"
        auto request = <-requests
        assert http.method(request) == "POST"
        assert http.path(request) == "/token"
        assert http.req_header(request, "content-type") == "application/x-www-form-urlencoded"
        assert http.req_header(request, "accept") == "application/json"
        assert http.req_header(request, "authorization") == "Basic Y2xpZW50OnNlY3JldA=="
        auto sent = url.parse_query_first(http.req_body(request))
        assert len(sent) == 2
        assert sent["grant_type"] == "refresh_token"
        assert sent["refresh_token"] == "old+credential"

@test
def _transport_posts_body_credentials_without_mutating_form():
    auto listener = net.listen("127.0.0.1", 0)
    auto endpoint = http.url("127.0.0.1", net.port(listener), "/token")
    auto requests = channel[bytes](1)
    auto form = {"grant_type": "client_credentials", "scope": "read write"}
    scope:
        spawn _serve_token_reply(listener, _success(), requests)
        auto response = _post_token_form(
            endpoint,
            form,
            "client+id",
            "secret&=☃",
            "client_secret_post",
            3000,
        )
        assert http.status(response) == 200
        auto request = <-requests
        assert http.req_header(request, "authorization") == ""
        auto sent = url.parse_query_first(http.req_body(request))
        assert sent["client_id"] == "client+id"
        assert sent["client_secret"] == "secret&=☃"
        assert sent["grant_type"] == "client_credentials"
        assert sent["scope"] == "read write"
    assert len(form) == 2

@test
def _transport_rejects_caller_credentials_and_unknown_auth():
    for field in ["client_id", "client_secret"]:
        auto rejected = False
        try:
            _post_token_form(
                "",
                {field: "injected"},
                "client",
                "secret",
                "client_secret_basic",
                100,
            )
        except ValueError as message:
            rejected = message == "client credentials must come from the endpoint configuration"
        assert rejected
    auto rejected = False
    try:
        _post_token_form(
            "",
            {"grant_type": "refresh_token"},
            "client",
            "secret",
            "unknown",
            100,
        )
    except ValueError as message:
        rejected = message == "unsupported token endpoint authentication method"
    assert rejected

@test
def _transport_does_not_follow_redirects():
    auto listener = net.listen("127.0.0.1", 0)
    auto endpoint = http.url("127.0.0.1", net.port(listener), "/token")
    auto requests = channel[bytes](1)
    auto redirect = _TokenReply(307, "", {"Location": "/other"})
    scope:
        spawn _serve_token_reply(listener, redirect, requests)
        auto response = _post_token_form(
            endpoint,
            {"grant_type": "refresh_token"},
            "client",
            "secret",
            "client_secret_basic",
            3000,
        )
        assert http.status(response) == 307
        assert http.header(response, "location") == "/other"
        assert len(http.redirects(response)) == 0

@test
def _transport_has_a_total_timeout():
    auto listener = net.listen("127.0.0.1", 0)
    auto endpoint = http.url("127.0.0.1", net.port(listener), "/token")
    auto requests = channel[bytes](1)
    auto reply = _TokenReply(200, "", delay_ms=500)
    auto timed_out = False
    scope:
        spawn _serve_token_reply(listener, reply, requests)
        try:
            _post_token_form(
                endpoint,
                {"grant_type": "refresh_token"},
                "client",
                "secret",
                "client_secret_basic",
                100,
            )
        except TimeoutError:
            timed_out = True
    assert timed_out
