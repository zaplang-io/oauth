import datetime
import oauth

def _now() -> int64:
    return datetime.to_timestamp(datetime.now())

def _reject(str document):
    auto rejected = False
    try:
        oauth.Token.from_json(document)
    except oauth.InvalidTokenError:
        rejected = True
    assert rejected

def _unexpected_refresh(str credential) -> oauth.Token:
    raise AssertionError("refresh was called unexpectedly")

def _refreshed(str credential) -> oauth.Token:
    assert credential == "old-refresh"
    return oauth.Token.from_json(
        "{\"access_token\":\"fresh\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"read write\"}",
    )

def _rotated(str credential) -> oauth.Token:
    assert credential == "old-refresh"
    return oauth.Token.from_json(
        "{\"access_token\":\"fresh\",\"token_type\":\"bearer\",\"refresh_token\":\"new-refresh\"}",
    )

def _failed_refresh(str credential) -> oauth.Token:
    assert credential == "old-refresh"
    raise ValueError("token endpoint failed")

@test
def _reads_response_with_optional_fields():
    auto before = _now()
    auto token = oauth.Token.from_json(
        "{\"access_token\":\"access\",\"token_type\":\"bEaReR\",\"expires_in\":3600,\"refresh_token\":\"refresh\",\"scope\":\"read write\",\"provider_extra\":true}",
    )
    auto after = _now()
    assert token.access_token == "access"
    assert token.token_type == "bEaReR"
    assert token.expires_in.unwrap() == 3600
    assert token.expires_at.unwrap() >= before + 3600
    assert token.expires_at.unwrap() <= after + 3600
    assert token.refresh_token.unwrap() == "refresh"
    assert token.scope.unwrap() == "read write"
    assert not token.is_expired()

@test
def _persisted_deadline_takes_precedence_and_is_preserved():
    auto token = oauth.Token.from_json(
        "{\"access_token\":\"a\\\"b\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"expires_at\":1,\"refresh_token\":\"refresh\",\"scope\":\"read\"}",
    )
    assert token.is_expired(leeway=0)
    auto restored = oauth.Token.from_json(token.to_json())
    assert restored.access_token == token.access_token
    assert restored.token_type == token.token_type
    assert restored.expires_at.unwrap() == 1
    assert restored.expires_in.unwrap() == 3600
    assert restored.refresh_token.unwrap() == "refresh"
    assert restored.scope.unwrap() == "read"
    assert restored.is_expired(leeway=0)

@test
def _omits_absent_optional_values_and_keeps_scope_keyword():
    auto minimal = oauth.Token.from_json(
        "{\"access_token\":\"access\",\"token_type\":\"Bearer\"}",
    )
    assert minimal.expires_at.is_none()
    assert minimal.expires_in.is_none()
    assert minimal.refresh_token.is_none()
    assert minimal.scope.is_none()
    assert not minimal.is_expired(leeway=9223372036854775807)
    match json.loads(minimal.to_json()):
        case JsonValue.Object(fields):
            assert len(fields) == 2
        case _:
            assert False
    auto scoped = oauth.Token("access", "Bearer", scope=Optional.Some("read"))
    assert oauth.Token.from_json(scoped.to_json()).scope.unwrap() == "read"

@test
def _expiry_leeway_and_zero_lifetime():
    auto near = oauth.Token("near", "Bearer", expires_at=Optional.Some(_now() + 45))
    assert near.is_expired()
    assert near.is_expired(leeway=90)
    assert not near.is_expired(leeway=0)
    auto far = oauth.Token("far", "Bearer", expires_at=Optional.Some(_now() + 3600))
    assert not far.is_expired()
    assert far.is_expired(leeway=9223372036854775807)
    auto expired = oauth.Token.from_json(
        "{\"access_token\":\"access\",\"token_type\":\"Bearer\",\"expires_in\":0}",
    )
    assert expired.expires_in.unwrap() == 0
    assert expired.is_expired(leeway=0)
    auto rejected = False
    try:
        far.is_expired(leeway=-1)
    except ValueError:
        rejected = True
    assert rejected

@test
def _rejects_invalid_objects_and_token_types():
    for document in ["", "{", "null", "[]", "42", "{}", "{}{}", "{\"token_type\":\"Bearer\"}", "{\"access_token\":\"\",\"token_type\":\"Bearer\"}", "{\"access_token\":123,\"token_type\":\"Bearer\"}", "{\"access_token\":null,\"token_type\":\"Bearer\"}", "{\"access_token\":\"access\"}", "{\"access_token\":\"access\",\"token_type\":\"\"}", "{\"access_token\":\"access\",\"token_type\":false}", "{\"access_token\":\"access\",\"token_type\":\"MAC\"}"]:
        _reject(document)

@test
def _rejects_invalid_optional_fields():
    auto prefix = "{\"access_token\":\"access\",\"token_type\":\"Bearer\","
    for field in ["\"expires_in\":true", "\"expires_in\":null", "\"expires_in\":\"3600\"", "\"expires_in\":1.5", "\"expires_in\":-1", "\"expires_in\":9223372036854775807", "\"expires_in\":9223372036854775808", "\"expires_at\":-1", "\"expires_at\":null", "\"expires_at\":1.5", "\"expires_at\":9223372036854775808", "\"refresh_token\":[]", "\"refresh_token\":\"\"", "\"refresh_token\":null", "\"scope\":[]", "\"scope\":null"]:
        _reject(prefix + field + "}")

@test
def _active_tokens_skip_refresh():
    auto fresh = oauth.Token.from_json(
        "{\"access_token\":\"fresh\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
    )
    assert fresh.ensure_active_token(_unexpected_refresh).access_token == "fresh"
    auto unknown = oauth.Token("unknown", "Bearer")
    assert unknown.ensure_active_token(_unexpected_refresh).access_token == "unknown"
    auto near = oauth.Token("near", "Bearer", expires_at=Optional.Some(_now() + 45))
    assert near.ensure_active_token(_unexpected_refresh, leeway=0).access_token == "near"

@test
def _refresh_preserves_or_rotates_the_credential():
    auto old = oauth.Token.from_json(
        "{\"access_token\":\"old\",\"token_type\":\"Bearer\",\"expires_at\":1,\"refresh_token\":\"old-refresh\"}",
    )
    auto fresh = old.ensure_active_token(_refreshed)
    assert fresh.access_token == "fresh"
    assert fresh.refresh_token.unwrap() == "old-refresh"
    assert fresh.scope.unwrap() == "read write"
    assert fresh.expires_in.unwrap() == 3600
    assert not fresh.is_expired()
    assert old.access_token == "old"
    assert old.expires_at.unwrap() == 1
    auto rotated = old.ensure_active_token(_rotated)
    assert rotated.access_token == "fresh"
    assert rotated.refresh_token.unwrap() == "new-refresh"
    assert old.refresh_token.unwrap() == "old-refresh"

@test
def _rejects_missing_refresh_credential_and_propagates_endpoint_failure():
    auto expired = oauth.Token("old", "Bearer", expires_at=Optional.Some(0))
    auto missing = False
    try:
        expired.ensure_active_token(_unexpected_refresh)
    except oauth.MissingRefreshTokenError:
        missing = True
    assert missing
    auto old = oauth.Token(
        "old",
        "Bearer",
        expires_at=Optional.Some(0),
        refresh_token=Optional.Some("old-refresh"),
    )
    auto failed = False
    try:
        old.ensure_active_token(_failed_refresh)
    except ValueError as message:
        failed = message == "token endpoint failed"
    assert failed
    assert old.access_token == "old"
    assert old.refresh_token.unwrap() == "old-refresh"
