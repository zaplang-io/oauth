import oauth

def _metadata_fixture() -> str:
    return "{\"issuer\":\"https://issuer.example/tenant\",\"authorization_endpoint\":\"https://issuer.example/tenant/authorize\",\"token_endpoint\":\"https://tokens.example/token\",\"device_authorization_endpoint\":\"https://issuer.example/tenant/device\",\"jwks_uri\":\"https://keys.example/jwks\",\"scopes_supported\":[\"openid\",\"profile\"],\"grant_types_supported\":[\"authorization_code\",\"client_credentials\"],\"response_types_supported\":[\"code\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],\"code_challenge_methods_supported\":[\"S256\"],\"extension\":{\"ignored\":true}}"

@test
def _parses_and_configures_client_from_provider_metadata():
    auto metadata = oauth.ProviderMetadata.from_json(
        "https://issuer.example/tenant",
        _metadata_fixture(),
    )
    assert metadata.issuer == "https://issuer.example/tenant"
    assert metadata.authorization_endpoint.unwrap() == "https://issuer.example/tenant/authorize"
    assert metadata.token_endpoint == "https://tokens.example/token"
    assert metadata.device_authorization_endpoint.unwrap() == "https://issuer.example/tenant/device"
    assert metadata.jwks_uri.unwrap() == "https://keys.example/jwks"
    assert metadata.scopes_supported.unwrap() == ["openid", "profile"]
    assert metadata.grant_types_supported.unwrap() == ["authorization_code", "client_credentials"]
    assert metadata.response_types_supported.unwrap() == ["code"]
    assert metadata.token_endpoint_auth_methods_supported.unwrap() == ["client_secret_basic", "client_secret_post"]
    assert metadata.code_challenge_methods_supported.unwrap() == ["S256"]
    auto client = oauth.Client.from_metadata(
        metadata,
        "client",
        "secret",
        redirect_uri="https://app.example/callback",
        token_endpoint_auth_method="client_secret_post",
        timeout=1500,
    )
    assert client.client_id == "client"
    assert client.client_secret == "secret"
    assert client.token_endpoint == metadata.token_endpoint
    assert client.authorization_endpoint == metadata.authorization_endpoint.unwrap()
    assert client.device_authorization_endpoint == metadata.device_authorization_endpoint.unwrap()
    assert client.redirect_uri == "https://app.example/callback"
    assert client.token_endpoint_auth_method == "client_secret_post"
    assert client.timeout == 1500
    auto target, state, verifier = client.authorization_url(scope=["openid"])
    assert url.split(target).path == "/tenant/authorize"
    auto query = url.parse_query_first(url.split(target).query)
    assert query["redirect_uri"] == "https://app.example/callback"
    assert query["scope"] == "openid"

@test
def _client_credentials_only_metadata_can_omit_authorization_endpoint():
    auto metadata = oauth.ProviderMetadata.from_json(
        "https://issuer.example",
        "{\"issuer\":\"https://issuer.example\",\"token_endpoint\":\"https://issuer.example/token\",\"grant_types_supported\":[\"client_credentials\"]}",
    )
    assert metadata.authorization_endpoint.is_none()
    assert metadata.device_authorization_endpoint.is_none()
    assert metadata.scopes_supported.is_none()
    auto client = oauth.Client.from_metadata(metadata, "service", "secret")
    assert client.authorization_endpoint == ""
    assert client.device_authorization_endpoint == ""
    assert client.token_endpoint_auth_method == "client_secret_basic"
    assert client.timeout == 0

@test
def _issuer_comparison_is_exact():
    auto document = _metadata_fixture()
    for issuer in ["https://issuer.example", "https://issuer.example/tenant/", "https://ISSUER.example/tenant", "https://issuer.example:443/tenant", "https://issuer.example/%74enant"]:
        auto mismatched = False
        try:
            oauth.ProviderMetadata.from_json(issuer, document)
        except oauth.IssuerMismatchError:
            mismatched = True
        assert mismatched
    auto with_slash = document.replace(
        "\"issuer\":\"https://issuer.example/tenant\"",
        "\"issuer\":\"https://issuer.example/tenant/\"",
    )
    assert oauth.ProviderMetadata.from_json("https://issuer.example/tenant/", with_slash).issuer == "https://issuer.example/tenant/"

@test
def _rejects_invalid_issuer_configuration():
    for issuer in ["/relative", "https:///no-host", "http://issuer.example", "https://issuer.example/tenant?", "https://issuer.example/tenant#", "https://name@issuer.example", "https://issuer.example/tenant space"]:
        auto rejected = False
        try:
            oauth.ProviderMetadata.from_json(issuer, _metadata_fixture())
        except ValueError:
            rejected = True
        assert rejected

def _reject_metadata(str document):
    auto rejected = False
    try:
        oauth.ProviderMetadata.from_json("https://issuer.example", document)
    except oauth.InvalidProviderMetadataError:
        rejected = True
    assert rejected

@test
def _rejects_bad_metadata_and_missing_required_endpoints():
    for document in ["", "<html>not JSON</html>", "null", "[]", "42", "{\"issuer\":null}", "{\"issuer\":\"\",\"token_endpoint\":\"https://issuer.example/token\"}", "{\"issuer\":\"https://issuer.example\",\"authorization_endpoint\":\"https://issuer.example/authorize\"}", "{\"issuer\":\"https://issuer.example\",\"token_endpoint\":\"https://issuer.example/token\"}", "{\"issuer\":\"https://issuer.example\",\"token_endpoint\":\"https://issuer.example/token\",\"grant_types_supported\":[\"authorization_code\"]}", "{\"issuer\":\"https://issuer.example\",\"token_endpoint\":\"https://issuer.example/token\",\"grant_types_supported\":[\"implicit\"]}"]:
        _reject_metadata(document)
    auto prefix = "{\"issuer\":\"https://issuer.example\",\"token_endpoint\":\"https://issuer.example/token\",\"authorization_endpoint\":\"https://issuer.example/authorize\","
    for field in ["\"device_authorization_endpoint\":\"/relative\"", "\"jwks_uri\":\"http://keys.example/jwks\"", "\"scopes_supported\":\"openid\"", "\"scopes_supported\":[\"openid\",false]", "\"scopes_supported\":[\"\"]", "\"grant_types_supported\":null", "\"token_endpoint_auth_methods_supported\":[42]", "\"code_challenge_methods_supported\":{}"]:
        _reject_metadata(prefix + field + "}")

@test
def _document_limit_counts_utf8_bytes():
    auto document = _metadata_fixture()
    auto padding = " "
    for index in range(16):
        padding = padding + padding
    auto exact = document + padding[:65536 - len(bytes(document))]
    auto metadata = oauth.ProviderMetadata.from_json(
        "https://issuer.example/tenant",
        exact,
    )
    assert metadata.issuer == "https://issuer.example/tenant"
    auto wide = "é"
    for index in range(15):
        wide = wide + wide
    for oversized in [exact + " ", "{\"unused\":\"" + wide + "\"}"]:
        auto rejected = False
        try:
            oauth.ProviderMetadata.from_json("https://issuer.example/tenant", oversized)
        except oauth.ProviderMetadataTooLargeError:
            rejected = True
        assert rejected
