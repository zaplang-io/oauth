@test
def _well_known_urls_for_root_tenant_and_trailing_slash():
    for issuer in ["https://issuer.example", "https://issuer.example/"]:
        auto oidc, oauth = _provider_metadata_urls(issuer)
        assert oidc == "https://issuer.example/.well-known/openid-configuration"
        assert oauth == "https://issuer.example/.well-known/oauth-authorization-server"
    for issuer in ["https://issuer.example:8443/tenant/sub", "https://issuer.example:8443/tenant/sub/"]:
        auto oidc, oauth = _provider_metadata_urls(issuer)
        assert oidc == "https://issuer.example:8443/tenant/sub/.well-known/openid-configuration"
        assert oauth == "https://issuer.example:8443/.well-known/oauth-authorization-server/tenant/sub"
    auto oidc, oauth = _provider_metadata_urls("http://[::1]:8080/%74enant/")
    assert oidc == "http://[::1]:8080/%74enant/.well-known/openid-configuration"
    assert oauth == "http://[::1]:8080/.well-known/oauth-authorization-server/%74enant"
