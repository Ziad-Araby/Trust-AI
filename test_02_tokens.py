# Task 2 (Security / Auth): Token, Role and Session tests -> Screens 1 and 10
from config import ADMIN, GUEST, PROTECTED, ROLE_CLAIM
from helpers import call, body, get_tokens, tamper_payload, alg_none_token


def test_no_token_gets_401():
    for method, path in PROTECTED:
        assert call(method, path).status_code == 401


def test_guest_gets_403_and_the_required_role():
    token = get_tokens(GUEST)["accessToken"]
    for method, path in PROTECTED:
        r = call(method, path, token)
        assert r.status_code == 403
        assert "requiredRole" in body(r)      # the Access Restricted screen needs it


def test_guest_cannot_edit_the_role_inside_the_token():
    token = get_tokens(GUEST)["accessToken"]
    fake = tamper_payload(token, ROLE_CLAIM, "Security Admin")
    for method, path in PROTECTED:
        assert call(method, path, fake).status_code == 401


def test_token_with_alg_none_is_rejected():
    for method, path in PROTECTED:
        assert call(method, path, alg_none_token()).status_code == 401


def test_garbage_token_is_rejected():
    for method, path in PROTECTED:
        assert call(method, path, "garbage").status_code == 401


def test_refresh_token_works_only_once():
    old = get_tokens(ADMIN)["refreshToken"]
    first = call("POST", "/auth/refresh", json_body={"refreshToken": old})
    assert first.status_code == 200
    second = call("POST", "/auth/refresh", json_body={"refreshToken": old})
    assert second.status_code == 401


def test_logout_cancels_the_refresh_token():
    tokens = get_tokens(ADMIN)
    call("POST", "/auth/logout", tokens["accessToken"], json_body={"refreshToken": tokens["refreshToken"]})
    r = call("POST", "/auth/refresh", json_body={"refreshToken": tokens["refreshToken"]})
    assert r.status_code == 401
