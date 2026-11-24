import oauth

def _client(
    str redirect_uri = "https://app.example/callback",
    str authorization_endpoint = "https://issuer.example/authorize",
    str token_endpoint = "https://issuer.example/token",
) -> oauth.Client:
    return oauth.Client(
        "web-client",
        "secret",
        token_endpoint,
        timeout=3000,
        authorization_endpoint=authorization_endpoint,
        redirect_uri=redirect_uri,
    )

def _reject_callback(oauth.Client client, str callback, (str, str, str) request):
    auto rejected = False
    try:
        client.exchange_code(callback, request)
    except oauth.InvalidAuthorizationResponseError:
        rejected = True
    assert rejected

@test
def _authorization_url_contains_s256_and_cryptographic_state():
    auto client = _client(
        authorization_endpoint="https://issuer.example/authorize?tenant=blue%2Bgreen",
    )
    auto target, state, verifier = client.authorization_url(
        scope=["openid", "read:profile"],
    )
    auto parts = url.split(target)
    auto fields = url.parse_query_first(parts.query)
    assert parts.scheme == "https"
    assert parts.host == "issuer.example"
    assert parts.path == "/authorize"
    assert fields["tenant"] == "blue+green"
    assert fields["response_type"] == "code"
    assert fields["client_id"] == "web-client"
    assert fields["redirect_uri"] == "https://app.example/callback"
    assert fields["scope"] == "openid read:profile"
    assert fields["state"] == state
    assert fields["code_challenge_method"] == "S256"
    assert len(fields["code_challenge"]) == 43
    assert len(base64.urlsafe_decode(fields["code_challenge"])) == 32
    assert "code_verifier" not in fields
    assert len(base64.urlsafe_decode(state)) == 32
    assert len(base64.urlsafe_decode(verifier)) == 32
    assert state != verifier
    auto second_target, second_state, second_verifier = client.authorization_url()
    auto second_fields = url.parse_query_first(url.split(second_target).query)
    assert "scope" not in second_fields
    assert state != second_state
    assert verifier != second_verifier

@test
def _caller_state_round_trips_as_form_data():
    auto state = "browser session+/&%"
    auto target, expected, verifier = _client().authorization_url(
        state=Optional.Some(state),
    )
    assert expected == state
    auto fields = url.parse_query_first(url.split(target).query)
    assert fields["state"] == state
    assert len(verifier) == 43

@test
def _rfc7636_s256_vector_and_callback_error_fields():
    auto client = _client()
    auto verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    auto request = (
        "https://issuer.example/authorize?response_type=code&client_id=web-client&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&state=expected&code_challenge_method=S256&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "expected",
        verifier,
    )
    auto caught = False
    try:
        client.exchange_code(
            "https://app.example/callback?state=expected&error=access_denied&error_description=user+declined&error_uri=https%3A%2F%2Fissuer.example%2Fhelp",
            request,
        )
    except oauth.AuthorizationResponseError as failure:
        assert failure.error == "access_denied"
        assert failure.error_description.unwrap() == "user declined"
        assert failure.error_uri.unwrap() == "https://issuer.example/help"
        caught = True
    assert caught

@test
def _state_is_checked_before_provider_error_or_token_request():
    auto client = _client()
    auto request = client.authorization_url(state=Optional.Some("expected"))
    for callback in ["https://app.example/callback?state=other&code=code", "https://app.example/callback?code=code", "https://app.example/callback?state=&error=access_denied", "https://app.example/callback?state=other&error=access_denied"]:
        auto caught = False
        try:
            client.exchange_code(callback, request)
        except oauth.MismatchingStateError:
            caught = True
        assert caught

@test
def _malformed_callbacks_are_rejected_without_network():
    auto client = _client(redirect_uri="https://app.example/callback?tenant=blue")
    auto request = client.authorization_url(state=Optional.Some("expected"))
    for callback in ["https://other.example/callback?tenant=blue&state=expected&code=c", "https://app.example:444/callback?tenant=blue&state=expected&code=c", "https://app.example/other?tenant=blue&state=expected&code=c", "https://app.example/callback?state=expected&code=c", "https://app.example/callback?tenant=red&state=expected&code=c", "https://app.example/callback?tenant=blue&tenant=blue&state=expected&code=c", "https://app.example/callback?tenant=blue&state=expected&code=c#fragment", "https://app.example/callback?tenant=blue&state=expected", "https://app.example/callback?tenant=blue&state=expected&code=", "https://app.example/callback?tenant=blue&state=expected&code=c&code=c", "https://app.example/callback?tenant=blue&state=expected&st%61te=expected&code=c", "https://app.example/callback?tenant=blue&state=expected&error=", "https://app.example/callback?tenant=blue&state=expected&error=access_denied&code=c", "https://app.example/callback?tenant=blue&state=expected&error=access_denied&error_description=a&error_description=b", "https://app.example/callback?tenant=blue&state=expected&code=%zz", "https://app.example/callback?tenant=blue&state=expected&code=%A", "https://app.example/callback?tenant=blue&state=expected&code=%FF"]:
        _reject_callback(client, callback, request)

@test
def _request_is_bound_to_endpoint_and_verifier():
    auto client = _client(
        authorization_endpoint="https://issuer.example/authorize?tenant=blue",
    )
    auto request_url, state, verifier = client.authorization_url(
        state=Optional.Some("expected"),
    )
    auto callback = "https://app.example/callback?state=expected&code=issued"
    auto other = _client(
        authorization_endpoint="https://other.example/authorize?tenant=blue",
    )
    _reject_callback(other, callback, (request_url, state, verifier))
    auto different_tenant = _client(
        authorization_endpoint="https://issuer.example/authorize?tenant=red",
    )
    _reject_callback(different_tenant, callback, (request_url, state, verifier))
    auto second_url, second_state, second_verifier = client.authorization_url()
    _reject_callback(client, callback, (request_url, state, second_verifier))

def _serve_code_exchanges(bytes listener, str verifier, str redirect):
    try:
        for attempt in range(2):
            auto connection = net.accept(listener)
            try:
                auto request = http.read_request(connection)
                assert http.method(request) == "POST"
                assert http.path(request) == "/token"
                assert http.req_header(request, "authorization") == ""
                auto fields = url.parse_query_first(http.req_body(request))
                assert len(fields) == 5
                assert fields["grant_type"] == "authorization_code"
                assert fields["client_id"] == "native-client"
                assert fields["code"] == "code+123"
                assert fields["code_verifier"] == verifier
                assert fields["redirect_uri"] == redirect
                assert "client_secret" not in fields
                if attempt == 0:
                    http.respond(
                        connection,
                        200,
                        "{\"access_token\":\"issued\",\"token_type\":\"Bearer\"}",
                    )
                else:
                    http.respond(connection, 400, "{\"error\":\"invalid_grant\"}")
            finally:
                net.close_conn(connection)
    finally:
        net.close_listener(listener)

@test
def _public_exchange_and_provider_replay_rejection():
    auto listener = net.listen("127.0.0.1", 0)
    auto redirect = "com.example.app:/callback?tenant=blue"
    auto client = oauth.Client(
        "native-client",
        "",
        http.url("127.0.0.1", net.port(listener), "/token"),
        token_endpoint_auth_method="none",
        timeout=3000,
        authorization_endpoint="https://issuer.example/authorize",
        redirect_uri=redirect,
    )
    auto target, state, verifier = client.authorization_url()
    auto request = (target, state, verifier)
    auto callback = redirect + "&state=" + state + "&code=code%2B123"
    scope:
        spawn _serve_code_exchanges(listener, verifier, redirect)
        assert client.exchange_code(callback, request).access_token == "issued"
        auto replay_rejected = False
        try:
            client.exchange_code(callback, request)
        except oauth.InvalidGrantError as failure:
            replay_rejected = failure.status == 400 and failure.error == "invalid_grant"
        assert replay_rejected

@test
def _invalid_authorization_configuration():
    auto client = _client()
    for scope in [[""], ["read write"], ["read\"write"], ["read\\write"], ["é"]]:
        auto invalid = False
        try:
            client.authorization_url(scope=scope)
        except ValueError:
            invalid = True
        assert invalid
    for state in ["", "has\nnewline", "é"]:
        auto invalid = False
        try:
            client.authorization_url(state=Optional.Some(state))
        except ValueError:
            invalid = True
        assert invalid
    for invalid_client in [_client(authorization_endpoint="http://issuer.example/authorize"), _client(authorization_endpoint="https://issuer.example/authorize?st%61te=preexisting"), _client(redirect_uri="https://app.example/callback?code=preexisting"), _client(redirect_uri="https://app.example/callback#fragment"), _client(redirect_uri="/relative")]:
        auto invalid = False
        try:
            invalid_client.authorization_url()
        except ValueError:
            invalid = True
        assert invalid

@test
def _public_auth_rejects_configured_secret():
    auto client = oauth.Client(
        "public",
        "secret",
        "https://issuer.example/token",
        token_endpoint_auth_method="none",
    )
    auto caught = False
    try:
        client.fetch_token({"grant_type": "authorization_code"})
    except ValueError as message:
        caught = message == "public client authentication requires an empty client_secret"
    assert caught
