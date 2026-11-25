import oauth

const str _GRANT = "urn:ietf:params:oauth:grant-type:device_code"

struct _DeviceReply:
    str path
    int64 status
    str body
    int64 stall_ms = 0

struct _DeviceRequest:
    dict[str, str] form
    str auth
    int64 received_ns

def _serve_device(
    bytes listener,
    list[_DeviceReply] replies,
    channel[_DeviceRequest] requests,
):
    try:
        for reply in replies:
            auto connection = net.accept(listener)
            try:
                auto request = http.read_request(connection)
                assert http.method(request) == "POST"
                assert http.path(request) == reply.path
                assert http.req_header(request, "content-type") == "application/x-www-form-urlencoded"
                assert http.req_header(request, "accept") == "application/json"
                requests <- _DeviceRequest(url.parse_query_first(http.req_body(request)), http.req_header(request, "authorization"), time.monotonic_ns())
                if reply.stall_ms > 0:
                    time.sleep_for(time.millis(reply.stall_ms))
                else:
                    http.respond(
                        connection,
                        reply.status,
                        reply.body,
                        {"Content-Type": "application/json"},
                    )
            finally:
                net.close_conn(connection)
    finally:
        net.close_listener(listener)

def _device_client(
    bytes listener,
    str auth = "none",
    str secret = "",
    int64 timeout = 3000,
) -> oauth.Client:
    auto port = net.port(listener)
    return oauth.Client(
        "device-client",
        secret,
        http.url("127.0.0.1", port, "/token"),
        token_endpoint_auth_method=auth,
        timeout=timeout,
        device_authorization_endpoint=http.url("127.0.0.1", port, "/device"),
    )

def _device_document(str extra) -> str:
    return "{\"device_code\":\"device+secret\",\"user_code\":\"ABCD-EFGH\",\"verification_uri\":\"https://issuer.example/verify\",\"expires_in\":30" + extra + "}"

def _device_reply(str extra = ",\"interval\":1") -> _DeviceReply:
    return _DeviceReply("/device", 200, _device_document(extra))

def _issued() -> _DeviceReply:
    return _DeviceReply(
        "/token",
        200,
        "{\"access_token\":\"device-token\",\"token_type\":\"Bearer\"}",
    )

def _assert_public_poll(_DeviceRequest request):
    assert request.auth == ""
    assert len(request.form) == 3
    assert request.form["client_id"] == "device-client"
    assert request.form["grant_type"] == _GRANT
    assert request.form["device_code"] == "device+secret"

def _assert_early(oauth.Client client, oauth.DeviceAuthorizationResponse authorization):
    auto caught = False
    try:
        client.poll_device_access_token(authorization)
    except oauth.DevicePollingTooSoonError as failure:
        caught = failure.retry_after_ms > 0
    assert caught

def _wait_for_poll(oauth.DeviceAuthorizationResponse authorization):
    time.sleep_for(time.millis(authorization.poll_after_ms()))

@test
def _device_authorization_surfaces_fields_and_default_interval():
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _device_client(listener, "client_secret_post", "credential")
    auto requests = channel[_DeviceRequest](1)
    auto reply = _device_reply(
        ",\"verification_uri_complete\":\"https://issuer.example/verify?user_code=ABCD-EFGH\"",
    )
    scope:
        spawn _serve_device(listener, [reply], requests)
        auto authorization = client.device_authorization(scope=["read", "write"])
        auto sent = <-requests
        assert sent.auth == ""
        assert sent.form["client_id"] == "device-client"
        assert sent.form["client_secret"] == "credential"
        assert sent.form["scope"] == "read write"
        assert "grant_type" not in sent.form
        assert authorization.device_code == "device+secret"
        assert authorization.user_code == "ABCD-EFGH"
        assert authorization.verification_uri == "https://issuer.example/verify"
        assert authorization.verification_uri_complete.unwrap() == "https://issuer.example/verify?user_code=ABCD-EFGH"
        assert authorization.expires_in == 30
        assert authorization.interval == 5
        assert authorization.poll_after_ms() > 0
        assert authorization.poll_after_ms() <= 5000

@test
def _blocking_device_poll_repeats_pending_until_success():
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _device_client(listener)
    auto requests = channel[_DeviceRequest](3)
    auto replies = [
        _device_reply(),
        _DeviceReply("/token", 400, "{\"error\":\"authorization_pending\"}"),
        _issued(),
    ]
    scope:
        spawn _serve_device(listener, replies, requests)
        auto authorization = client.device_authorization()
        assert authorization.interval == 1
        assert authorization.verification_uri_complete.is_none()
        assert client.device_access_token(authorization).access_token == "device-token"
        auto enrollment = <-requests
        auto first = <-requests
        auto second = <-requests
        assert enrollment.form["client_id"] == "device-client"
        assert "scope" not in enrollment.form
        _assert_public_poll(first)
        _assert_public_poll(second)
        assert first.received_ns - enrollment.received_ns >= 1000000000
        assert second.received_ns - first.received_ns >= 1000000000
        auto completed = False
        try:
            client.poll_device_access_token(authorization)
        except ValueError:
            completed = True
        assert completed

@test
def _caller_driven_poll_enforces_interval_and_slow_down():
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _device_client(listener)
    auto requests = channel[_DeviceRequest](3)
    auto replies = [
        _device_reply(),
        _DeviceReply("/token", 400, "{\"error\":\"slow_down\"}"),
        _issued(),
    ]
    scope:
        spawn _serve_device(listener, replies, requests)
        auto authorization = client.device_authorization()
        _assert_early(client, authorization)
        _wait_for_poll(authorization)
        assert client.poll_device_access_token(authorization).is_none()
        assert authorization.poll_after_ms() > 5000
        assert authorization.poll_after_ms() <= 6000
        _assert_early(client, authorization)
        _wait_for_poll(authorization)
        assert client.poll_device_access_token(authorization).unwrap().access_token == "device-token"
        auto enrollment = <-requests
        auto first = <-requests
        auto second = <-requests
        _assert_public_poll(first)
        _assert_public_poll(second)
        assert second.received_ns - first.received_ns >= 6000000000

@test
def _device_poll_doubles_interval_after_timeout():
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _device_client(listener, timeout=300)
    auto requests = channel[_DeviceRequest](3)
    auto replies = [
        _device_reply(),
        _DeviceReply("/token", 200, "", stall_ms=500),
        _issued(),
    ]
    scope:
        spawn _serve_device(listener, replies, requests)
        auto authorization = client.device_authorization()
        _wait_for_poll(authorization)
        assert client.poll_device_access_token(authorization).is_none()
        assert authorization.poll_after_ms() > 1000
        assert authorization.poll_after_ms() <= 2000
        assert client.device_access_token(authorization).access_token == "device-token"
        auto enrollment = <-requests
        auto first = <-requests
        auto second = <-requests
        assert second.received_ns - first.received_ns >= 2000000000

@test
def _terminal_device_errors_stop_polling_and_keep_provider_fields():
    for code in ["expired_token", "access_denied", "invalid_grant"]:
        auto listener = net.listen("127.0.0.1", 0)
        auto client = _device_client(listener)
        auto requests = channel[_DeviceRequest](2)
        auto body = "{\"error\":\"" + code + "\",\"error_description\":\"provider stopped\"}"
        auto replies = [_device_reply(), _DeviceReply("/token", 400, body)]
        scope:
            spawn _serve_device(listener, replies, requests)
            auto authorization = client.device_authorization()
            auto caught = ""
            try:
                client.device_access_token(authorization)
            except oauth.DeviceCodeExpiredError as failure:
                assert failure.status == 400
                assert failure.error_description.unwrap() == "provider stopped"
                caught = "expired_token"
            except oauth.DeviceAccessDeniedError as failure:
                assert failure.status == 400
                assert failure.error_description.unwrap() == "provider stopped"
                caught = "access_denied"
            except oauth.InvalidGrantError as failure:
                caught = failure.error
            assert caught == code
            auto completed = False
            try:
                client.poll_device_access_token(authorization)
            except ValueError:
                completed = True
            assert completed

@test
def _local_expiry_prevents_poll_and_clients_cannot_swap_device_codes():
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _device_client(listener)
    auto requests = channel[_DeviceRequest](1)
    auto short = _DeviceReply(
        "/device",
        200,
        _device_document(",\"interval\":9223372036854775807").replace(
            "\"expires_in\":30",
            "\"expires_in\":1",
        ),
    )
    scope:
        spawn _serve_device(listener, [short], requests)
        auto authorization = client.device_authorization()
        auto different = oauth.Client(
            "another",
            "",
            client.token_endpoint,
            token_endpoint_auth_method="none",
        )
        auto foreign = False
        try:
            different.poll_device_access_token(authorization)
        except ValueError:
            foreign = True
        assert foreign
        auto expired = False
        try:
            client.device_access_token(authorization)
        except oauth.DeviceCodeExpiredError as failure:
            expired = failure.status == 0 and failure.error == "expired_token"
        assert expired

def _reject_device_response(str document):
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _device_client(listener)
    auto requests = channel[_DeviceRequest](1)
    auto reply = _DeviceReply("/device", 200, document)
    scope:
        spawn _serve_device(listener, [reply], requests)
        auto caught = False
        try:
            client.device_authorization()
        except oauth.InvalidDeviceAuthorizationError:
            caught = True
        assert caught

@test
def _malformed_device_response_and_subminimum_interval_are_rejected():
    for body in ["", "[]", "{}", "non-JSON", _device_document(",\"interval\":0"), _device_document(",\"interval\":-1"), _device_document(",\"interval\":null"), _device_document(",\"interval\":0.5"), _device_document(",\"verification_uri_complete\":\"\""), _device_document(",\"verification_uri_complete\":\"https://issuer.example/verify#first second\""), _device_document("").replace("\"expires_in\":30", "\"expires_in\":0"), _device_document("").replace("\"expires_in\":30", "\"expires_in\":9223372036854775807"), _device_document("").replace("\"user_code\":\"ABCD-EFGH\"", "\"user_code\":null"), _device_document("").replace("https://issuer.example/verify", "http://issuer.example/verify"), _device_document("").replace("\"device_code\":\"device+secret\",", "")]:
        _reject_device_response(body)

@test
def _device_authorization_surfaces_http_and_oauth_failures():
    for status in [401, 503]:
        auto listener = net.listen("127.0.0.1", 0)
        auto client = _device_client(listener)
        auto requests = channel[_DeviceRequest](1)
        auto body = "unavailable"
        if status == 401:
            body = "{\"error\":\"invalid_client\"}"
        auto reply = _DeviceReply("/device", status, body)
        scope:
            spawn _serve_device(listener, [reply], requests)
            auto caught = 0
            try:
                client.device_authorization()
            except oauth.InvalidClientError as failure:
                assert failure.error == "invalid_client"
                caught = failure.status
            except oauth.DeviceAuthorizationHTTPError as failure:
                caught = failure.status
            assert caught == status

@test
def _poll_request_is_bounded_by_device_expiry():
    auto listener = net.listen("127.0.0.1", 0)
    auto client = _device_client(listener, timeout=0)
    auto requests = channel[_DeviceRequest](2)
    auto brief = _device_document(",\"interval\":1").replace(
        "\"expires_in\":30",
        "\"expires_in\":2",
    )
    auto replies = [
        _DeviceReply("/device", 200, brief),
        _DeviceReply("/token", 200, "", stall_ms=1500),
    ]
    scope:
        spawn _serve_device(listener, replies, requests)
        auto authorization = client.device_authorization()
        auto expired = False
        try:
            client.device_access_token(authorization)
        except oauth.DeviceCodeExpiredError as failure:
            expired = failure.status == 0
        assert expired
        auto enrollment = <-requests
        auto poll = <-requests
        _assert_public_poll(poll)
