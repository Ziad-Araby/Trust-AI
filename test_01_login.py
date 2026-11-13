# Task 1 (Security / Auth): Sign In tests  -> Screen 5
from config import ADMIN, LOCKOUT, PENDING
from helpers import login, body


def test_wrong_password_gives_401():
    r = login(ADMIN[0], "wrong-password")
    assert r.status_code == 401
    assert body(r).get("code") == "INVALID_CREDENTIALS"


def test_unknown_email_looks_like_wrong_password():
    # user enumeration: the attacker must not learn which emails exist
    a = login(ADMIN[0], "wrong-password")
    b = login("nobody@trust.local", "wrong-password")
    assert a.status_code == b.status_code
    assert body(a) == body(b)


def test_pending_account_is_told_clearly():
    r = login(PENDING[0], PENDING[1])
    assert body(r).get("code") == "ACCOUNT_PENDING"


def test_lockout_after_many_failed_logins():
    last = None
    for i in range(10):
        last = login(LOCKOUT[0], "wrong-" + str(i))
    assert last.status_code == 423
    assert body(last).get("code") == "ACCOUNT_LOCKED"


def test_locked_account_rejects_the_right_password_too():
    r = login(LOCKOUT[0], LOCKOUT[1])
    assert r.status_code == 423


def test_sql_injection_in_email():
    r = login("' OR '1'='1' --", "x")
    assert r.status_code in (400, 401, 422)


def test_very_long_password_does_not_crash():
    r = login(ADMIN[0], "a" * 5000)
    assert r.status_code < 500


#python -u test_01_login.py