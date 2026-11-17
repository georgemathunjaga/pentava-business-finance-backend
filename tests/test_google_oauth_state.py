import importlib
from pentava_finances import google_auth


def test_state_survives_module_reload_and_cannot_be_replayed(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIRECTORY", str(tmp_path))
    class Flow:
        def authorization_url(self, **kwargs):
            return "https://accounts.google.com/fixture", "fixture-state"
    monkeypatch.setattr(google_auth, "create_google_flow", lambda: Flow())
    _, state = google_auth.get_authorization_url("owner")
    importlib.reload(google_auth)
    assert google_auth.consume_oauth_state(state) == "owner"
    assert google_auth.consume_oauth_state(state) is None


def test_expired_state_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIRECTORY", str(tmp_path))
    with google_auth.database() as db:
        db.execute("CREATE TABLE oauth_states(digest TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires REAL NOT NULL)")
        db.execute("INSERT INTO oauth_states VALUES(?,?,?)", (google_auth.digest("expired"), "owner", 0))
    assert google_auth.consume_oauth_state("expired") is None


def test_exchange_uses_original_pkce_verifier_once(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIRECTORY", str(tmp_path))
    import pytest
    class Flow:
        code_verifier = "original-pkce-verifier"
        credentials = "credentials"
        def authorization_url(self, **kwargs):
            return "https://accounts.google.com/fixture", "pkce-state"
        def fetch_token(self, **kwargs):
            assert kwargs == {"code": "google-code"}
    def make_flow(state=None, code_verifier=None):
        if state:
            assert state == "pkce-state"
            assert code_verifier == Flow.code_verifier
        return Flow()
    monkeypatch.setattr(google_auth, "create_google_flow", make_flow)
    _, state = google_auth.get_authorization_url("owner")
    assert google_auth.consume_oauth_state(state) == "owner"
    assert google_auth.exchange_code("google-code", state) == "credentials"
    with pytest.raises(google_auth.GoogleOAuthError):
        google_auth.exchange_code("google-code", state)


import pytest

@pytest.mark.parametrize("complete", [True, False])
def test_incremental_consent_scope_response(monkeypatch, tmp_path, complete):
    from requests_oauthlib import OAuth2Session
    from oauthlib.oauth2.rfc6749.parameters import parse_token_response
    import json
    monkeypatch.setenv("DATA_DIRECTORY", str(tmp_path))
    monkeypatch.delenv("OAUTHLIB_RELAX_TOKEN_SCOPE", raising=False)
    granted = list(google_auth.GOOGLE_SCOPES) if complete else [google_auth.GOOGLE_SCOPES[0]]
    granted.append("openid")
    class Flow:
        code_verifier = "fixture-verifier"
        oauth2session = OAuth2Session(scope=google_auth.GOOGLE_SCOPES)
        def authorization_url(self, **kwargs):
            return "https://accounts.google.com/fixture", "scope-state"
        def fetch_token(self, **kwargs):
            parse_token_response(json.dumps({"access_token":"fixture-token", "token_type":"Bearer", "scope":" ".join(granted)}), scope=google_auth.GOOGLE_SCOPES)
        @property
        def credentials(self):
            return self.oauth2session.token
    monkeypatch.setattr(google_auth, "create_google_flow", lambda **kwargs: Flow())
    _, state = google_auth.get_authorization_url("owner")
    google_auth.consume_oauth_state(state)
    if complete:
        assert google_auth.exchange_code("code", state)["access_token"] == "fixture-token"
    else:
        with pytest.raises(google_auth.GoogleOAuthError, match="required Sheets permissions"):
            google_auth.exchange_code("code", state)
