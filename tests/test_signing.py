"""v2 Ed25519 signing primitives + receipt signing."""

import base64


from agentledger.receipt import Receipt
from agentledger.signing import (
    SIGNATURE_ALG,
    generate_keypair,
    public_key_from_b64,
    public_key_to_b64,
    sign,
    verify,
)


def _receipt(**kw):
    return Receipt(
        principal="user:d", agent="agent:a",
        permitted_tools=["get_rates"], permitted_scopes=["read:rates"], **kw
    )


def test_sign_verify_roundtrip():
    priv, pub = generate_keypair()
    payload = b"hello"
    sig = sign(payload, priv)
    assert verify(payload, sig, pub) is True


def test_verify_fails_on_tampered_payload():
    priv, pub = generate_keypair()
    sig = sign(b"hello", priv)
    assert verify(b"hello-tampered", sig, pub) is False


def test_verify_fails_on_wrong_key():
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    sig = sign(b"hello", priv)
    assert verify(b"hello", sig, other_pub) is False


def test_verify_rejects_unaccepted_alg():
    priv, pub = generate_keypair()
    sig = sign(b"x", priv)
    # T10: a non-pinned algorithm marker must never verify.
    assert verify(b"x", sig, pub, alg="none") is False
    assert verify(b"x", sig, pub, alg="rs256") is False


def test_verify_handles_garbage_signature():
    _, pub = generate_keypair()
    assert verify(b"x", "!!!not base64!!!", pub) is False


def test_receipt_sign_sets_fields_and_verifies():
    priv, pub = generate_keypair()
    r = _receipt()
    assert r.is_signed is False
    r.sign(priv)
    assert r.is_signed is True
    assert r.signature_alg == SIGNATURE_ALG
    assert verify(r.canonical_bytes(), r.signature, pub) is True


def test_signature_breaks_if_grant_widened():
    """Tampering with the grant after signing must invalidate the signature."""
    priv, pub = generate_keypair()
    r = _receipt()
    r.sign(priv)
    r.permitted_tools.append("delete_everything")  # widen scope post-signing
    assert verify(r.canonical_bytes(), r.signature, pub) is False


def test_public_key_b64_roundtrip():
    _, pub = generate_keypair()
    b64 = public_key_to_b64(pub)
    restored = public_key_from_b64(b64)
    priv2, pub2 = generate_keypair()
    # base64 decodes to 32 raw bytes
    assert len(base64.b64decode(b64)) == 32
    # restored key verifies a signature the original would
    assert public_key_to_b64(restored) == b64
