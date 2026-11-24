import oauth

struct _CredentialsReply:
    int64 status
    str body
    int64 delay_ms = 0

def _serve_credentials(
    bytes listener,
    list[_CredentialsReply] replies,
    Optional[str] expected_scope,
    bool post_auth,
):
    try:
        for reply in replies:
            auto connection = net.accept(listener)
            try:
                auto request = http.read_request(connection)
                assert http.method(request) == "POST"
                assert http.path(request) == "/token"
                assert http.req_header(request, "content-type") == "application/x-www-form-urlencoded"
                auto fields = url.parse_query_first(http.req_body(request))
                assert fields["grant_type"] == "client_credentials"
                assert "refresh_token" not in fields
                if post_auth:
                    assert http.req_header(request, "authorization") == ""
                    assert fields["client_id"] == "service"
                    assert fields["client_secret"] == "secret"
                else:
                    assert http.req_header(request, "authorization") == "Basic c2VydmljZTpzZWNyZXQ="
                    assert "client_id" not in fields
                    assert "client_secret" not in fields
                if expected_scope.is_some():
                    assert fields["scope"] == expected_scope.unwrap()
                else:
                    assert "scope" not in fields
                if reply.delay_ms > 0:
                    time.sleep_for(time.millis(reply.delay_ms))
                http.respond(connection, reply.status, reply.body)
            finally:
                net.close_conn(connection)
    finally:
        net.close_listener(listener)

def _credentials_client(
    bytes listener,
    str auth_method = "client_secret_basic",
) -> oauth.Client:
    return oauth.Client(
        "service",
        "secret",
        http.url("127.0.0.1", net.port(listener), "/token"),
        token_endpoint_auth_method=auth_method,
        timeout=3000,
    )

@test
def _client_credentials_gets_scoped_bearer_and_discards_refresh_token():
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _credentials_client(listener)
    auto reply = _CredentialsReply(
        200,
        "{\"access_token\":\"machine\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"read write\",\"refresh_token\":\"ignored\"}",
    )
    scope:
        spawn _serve_credentials(listener, [reply], Optional.Some("read write"), False)
        auto token = client.fetch_client_credentials(scope=["read", "write"])
        assert token.access_token == "machine"
        assert token.scope.unwrap() == "read write"
        assert token.expires_in.unwrap() == 3600
        assert token.refresh_token.is_none()

@test
def _client_credentials_empty_scope_is_omitted_with_post_auth():
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _credentials_client(listener, "client_secret_post")
    auto reply = _CredentialsReply(
        200,
        "{\"access_token\":\"machine\",\"token_type\":\"Bearer\"}",
    )
    scope:
        spawn _serve_credentials(listener, [reply], None, True)
        auto token = client.fetch_client_credentials(scope=[])
        assert token.access_token == "machine"
        assert token.scope.is_none()

@test
def _raw_client_credentials_ignores_even_malformed_refresh_token():
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _credentials_client(listener)
    auto reply = _CredentialsReply(
        200,
        "{\"access_token\":\"machine\",\"token_type\":\"Bearer\",\"refresh_token\":{\"ignored\":true}}",
    )
    scope:
        spawn _serve_credentials(listener, [reply], None, False)
        auto token = client.fetch_token({"grant_type": "client_credentials"})
        assert token.access_token == "machine"
        assert token.refresh_token.is_none()

@test
def _token_source_reacquires_after_expiry():
    auto listener = net.listen("127.0.0.1", 0)
    auto source = _credentials_client(listener).client_credentials_token_source(
        scope=["read"],
        leeway=0,
    )
    auto replies = [
        _CredentialsReply(
            200,
            "{\"access_token\":\"short\",\"token_type\":\"Bearer\",\"expires_in\":2,\"refresh_token\":\"unused\"}",
        ),
        _CredentialsReply(
            200,
            "{\"access_token\":\"renewed\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
        ),
    ]
    scope:
        spawn _serve_credentials(listener, replies, Optional.Some("read"), False)
        auto first = source.token()
        assert first.access_token == "short"
        assert first.refresh_token.is_none()
        assert source.token().access_token == "short"
        time.sleep_for(time.millis(2100))
        assert first.is_expired(leeway=0)
        assert source.token().access_token == "renewed"
        assert source.token().access_token == "renewed"

@test
def _token_source_uses_default_expiry_leeway():
    auto listener = net.listen("127.0.0.1", 0)
    auto source = _credentials_client(listener).client_credentials_token_source()
    auto replies = [
        _CredentialsReply(
            200,
            "{\"access_token\":\"near-expiry\",\"token_type\":\"Bearer\",\"expires_in\":30}",
        ),
        _CredentialsReply(
            200,
            "{\"access_token\":\"renewed\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
        ),
    ]
    scope:
        spawn _serve_credentials(listener, replies, None, False)
        auto first = source.token()
        assert not first.is_expired(leeway=0)
        assert source.token().access_token == "renewed"

@test
def _token_source_retries_typed_failure_and_rejects_expired_arrival():
    auto listener = net.listen("127.0.0.1", 0)
    auto source = _credentials_client(listener).client_credentials_token_source()
    auto replies = [
        _CredentialsReply(
            401,
            "{\"error\":\"invalid_client\",\"error_description\":\"bad credential\"}",
        ),
        _CredentialsReply(
            200,
            "{\"access_token\":\"expired\",\"token_type\":\"Bearer\",\"expires_at\":1}",
        ),
        _CredentialsReply(
            200,
            "{\"access_token\":\"recovered\",\"token_type\":\"Bearer\"}",
        ),
    ]
    scope:
        spawn _serve_credentials(listener, replies, None, False)
        auto invalid = False
        try:
            source.token()
        except oauth.InvalidClientError as failure:
            invalid = failure.status == 401 and failure.error_description.unwrap() == "bad credential"
        assert invalid
        auto expired = False
        try:
            source.token()
        except oauth.InvalidTokenError:
            expired = True
        assert expired
        assert source.token().access_token == "recovered"

def _read_token(oauth.ClientCredentialsTokenSource source, channel[str] results):
    results <- source.token().access_token

@test
def _token_source_shares_acquisition_and_protects_cached_token():
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _credentials_client(listener)
    auto requested = ["read"]
    auto source = client.client_credentials_token_source(scope=requested)
    client.client_secret = "changed"
    requested[0] = "changed"
    auto results = channel[str](4)
    auto reply = _CredentialsReply(
        200,
        "{\"access_token\":\"shared\",\"token_type\":\"Bearer\"}",
        delay_ms=50,
    )
    scope:
        spawn _serve_credentials(listener, [reply], Optional.Some("read"), False)
        for index in range(4):
            spawn _read_token(source, results)
        for index in range(4):
            auto access_token = <-results
            assert access_token == "shared"
        auto caller_token = source.token()
        caller_token.access_token = "caller-modified"
        assert source.token().access_token == "shared"

@test
def _provider_invalid_scope_remains_typed():
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _credentials_client(listener)
    auto reply = _CredentialsReply(
        400,
        "{\"error\":\"invalid_scope\",\"error_description\":\"scope denied\"}",
    )
    scope:
        spawn _serve_credentials(
            listener,
            [reply],
            Optional.Some("not-permitted"),
            False,
        )
        auto caught = False
        try:
            client.fetch_client_credentials(scope=["not-permitted"])
        except oauth.InvalidScopeError as failure:
            caught = failure.status == 400 and failure.error == "invalid_scope"
        assert caught

@test
def _invalid_client_credentials_arguments_fail_before_network():
    auto endpoint = "https://issuer.example/token"
    auto client = oauth.Client("service", "secret", endpoint)
    for item in ["", "two scopes", "é"]:
        auto invalid = False
        try:
            client.fetch_client_credentials(scope=[item])
        except ValueError:
            invalid = True
        assert invalid
    auto leeway_rejected = False
    try:
        client.client_credentials_token_source(leeway=-1)
    except ValueError:
        leeway_rejected = True
    assert leeway_rejected
    auto public_client = oauth.Client(
        "public",
        "",
        endpoint,
        token_endpoint_auth_method="none",
    )
    auto public_rejected = False
    try:
        public_client.fetch_client_credentials()
    except ValueError as message:
        public_rejected = message == "client credentials grant requires client authentication"
    assert public_rejected
