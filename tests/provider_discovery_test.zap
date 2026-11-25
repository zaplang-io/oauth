import oauth

struct _DiscoveryReply:
    str path
    int64 status
    str body = ""
    str content_type = "application/json"
    int64 advertised_size = 0

def _serve_discovery(bytes listener, list[_DiscoveryReply] replies):
    try:
        for reply in replies:
            auto connection = net.accept(listener)
            try:
                auto request = http.read_request(connection)
                assert http.method(request) == "GET"
                assert http.path(request) == reply.path
                assert http.req_header(request, "accept") == "application/json"
                assert http.req_header(request, "authorization") == ""
                if reply.advertised_size > 0:
                    net.send(
                        connection,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(reply.advertised_size) + "\r\nConnection: close\r\n\r\n",
                    )
                elif reply.status == 302:
                    http.respond(
                        connection,
                        reply.status,
                        reply.body,
                        {"Location": "/other"},
                    )
                else:
                    http.respond(
                        connection,
                        reply.status,
                        reply.body,
                        {"Content-Type": reply.content_type},
                    )
            finally:
                net.close_conn(connection)
    finally:
        net.close_listener(listener)

def _discovery_document(str issuer, str fields) -> str:
    return "{\"issuer\":\"" + issuer + "\",\"token_endpoint\":\"https://tokens.example/token\"" + fields + "}"

def _oidc_document(str issuer) -> str:
    return _discovery_document(
        issuer,
        ",\"authorization_endpoint\":\"https://issuer.example/authorize\",\"jwks_uri\":\"https://issuer.example/jwks\"",
    )

@test
def _oidc_discovers_root_and_tenant_issuers():
    for path in ["", "/", "/tenant/sub", "/tenant/sub/", "/%74enant/"]:
        auto listener = net.listen("127.0.0.1", 0)
        auto issuer = http.url("127.0.0.1", net.port(listener), path)
        auto normalized = path
        if path.endswith("/"):
            normalized = path[:-1]
        auto reply = _DiscoveryReply(
            normalized + "/.well-known/openid-configuration",
            200,
            _oidc_document(issuer),
            "Application/JSON; charset=UTF-8",
        )
        scope:
            spawn _serve_discovery(listener, [reply])
            auto metadata = oauth.discover(issuer, timeout=3000)
            assert metadata.issuer == issuer
            assert metadata.token_endpoint == "https://tokens.example/token"
            assert metadata.authorization_endpoint.unwrap() == "https://issuer.example/authorize"
            assert metadata.jwks_uri.unwrap() == "https://issuer.example/jwks"
            auto client = oauth.Client.from_metadata(metadata, "service", "secret")
            assert client.token_endpoint == metadata.token_endpoint

@test
def _oidc_404_falls_back_to_rfc8414():
    for path in ["", "/tenant/sub/"]:
        auto listener = net.listen("127.0.0.1", 0)
        auto issuer = http.url("127.0.0.1", net.port(listener), path)
        auto normalized = path
        if path.endswith("/"):
            normalized = path[:-1]
        auto replies = [
            _DiscoveryReply(
                normalized + "/.well-known/openid-configuration",
                404,
                "missing",
                "text/plain",
            ),
            _DiscoveryReply(
                "/.well-known/oauth-authorization-server" + normalized,
                200,
                _discovery_document(
                    issuer,
                    ",\"grant_types_supported\":[\"client_credentials\"]",
                ),
            ),
        ]
        scope:
            spawn _serve_discovery(listener, replies)
            auto metadata = oauth.discover(issuer)
            assert metadata.issuer == issuer
            assert metadata.authorization_endpoint.is_none()
            assert metadata.grant_types_supported.unwrap() == ["client_credentials"]

@test
def _discovery_surfaces_http_errors_without_redirect_or_other_fallback():
    for status in [204, 302, 403, 500]:
        auto listener = net.listen("127.0.0.1", 0)
        auto issuer = http.url("127.0.0.1", net.port(listener), "/tenant")
        auto reply = _DiscoveryReply("/tenant/.well-known/openid-configuration", status)
        scope:
            spawn _serve_discovery(listener, [reply])
            auto caught = False
            try:
                oauth.discover(issuer, timeout=3000)
            except oauth.ProviderDiscoveryHTTPError as failure:
                caught = failure.status == status
            assert caught

@test
def _discovery_reports_fallback_404():
    auto listener = net.listen("127.0.0.1", 0)
    auto issuer = http.url("127.0.0.1", net.port(listener), "/tenant")
    auto replies = [
        _DiscoveryReply("/tenant/.well-known/openid-configuration", 404),
        _DiscoveryReply("/.well-known/oauth-authorization-server/tenant", 404),
    ]
    scope:
        spawn _serve_discovery(listener, replies)
        auto caught = False
        try:
            oauth.discover(issuer, timeout=3000)
        except oauth.ProviderDiscoveryHTTPError as failure:
            caught = failure.status == 404
        assert caught

@test
def _invalid_metadata_and_issuer_mismatch_do_not_trigger_fallback():
    for kind in ["bad-json", "media-type", "missing-authorization", "mismatch"]:
        auto listener = net.listen("127.0.0.1", 0)
        auto issuer = http.url("127.0.0.1", net.port(listener), "/tenant")
        auto body = _oidc_document(issuer)
        auto content_type = "application/json"
        match kind:
            case "bad-json":
                body = "<html>invalid</html>"
            case "media-type":
                content_type = "text/html"
            case "missing-authorization":
                body = _discovery_document(
                    issuer,
                    ",\"grant_types_supported\":[\"client_credentials\"]",
                )
            case "mismatch":
                body = _oidc_document(issuer + "/")
        auto reply = _DiscoveryReply(
            "/tenant/.well-known/openid-configuration",
            200,
            body,
            content_type,
        )
        scope:
            spawn _serve_discovery(listener, [reply])
            auto caught = ""
            try:
                oauth.discover(issuer, timeout=3000)
            except oauth.IssuerMismatchError:
                caught = "mismatch"
            except oauth.InvalidProviderMetadataError:
                caught = "invalid"
            if kind == "mismatch":
                assert caught == "mismatch"
            else:
                assert caught == "invalid"

@test
def _http_limit_rejects_oversized_headers_before_requiring_the_body():
    for use_fallback in [False, True]:
        auto listener = net.listen("127.0.0.1", 0)
        auto issuer = http.url("127.0.0.1", net.port(listener), "/tenant")
        auto path = "/tenant/.well-known/openid-configuration"
        list[_DiscoveryReply] replies = []
        if use_fallback:
            replies.append(_DiscoveryReply(path, 404))
            path = "/.well-known/oauth-authorization-server/tenant"
        replies.append(_DiscoveryReply(path, 200, advertised_size=65537))
        scope:
            spawn _serve_discovery(listener, replies)
            auto caught = False
            try:
                oauth.discover(issuer, timeout=3000)
            except oauth.ProviderMetadataTooLargeError:
                caught = True
            assert caught

@test
def _http_accepts_metadata_at_exact_byte_limit():
    auto listener = net.listen("127.0.0.1", 0)
    auto issuer = http.url("127.0.0.1", net.port(listener), "/tenant")
    auto document = _oidc_document(issuer)
    auto padding = " "
    for index in range(16):
        padding = padding + padding
    auto exact = document + padding[:65536 - len(bytes(document))]
    auto reply = _DiscoveryReply("/tenant/.well-known/openid-configuration", 200, exact)
    scope:
        spawn _serve_discovery(listener, [reply])
        assert oauth.discover(issuer, timeout=3000).issuer == issuer

@test
def _discovery_rejects_invalid_timeout():
    auto caught = False
    try:
        oauth.discover("https://issuer.example", timeout=-1)
    except ValueError:
        caught = True
    assert caught
