# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Security regression tests for Certificate Authority.

Validates that:
- Sponsor signatures are cryptographically verified (CRIT-1 fix)
- Refresh tokens are validated against issued tokens (CRIT-2 fix)
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from agentmesh.core.identity.ca import (
    CertificateAuthority,
    RegistrationRequest,
    RegistrationResponse,
    SponsorRegistry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sponsor_keypair():
    """Generate a sponsor Ed25519 keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def _sign_registration(
    private_key: ed25519.Ed25519PrivateKey,
    agent_name: str,
    sponsor_email: str,
    capabilities: list[str] | None = None,
) -> bytes:
    """Create a valid sponsor signature for a registration request."""
    capabilities = capabilities or []
    capabilities_str = ",".join(sorted(capabilities))
    payload = f"{agent_name}:{sponsor_email}:{capabilities_str}"
    return private_key.sign(payload.encode("utf-8"))


def _make_agent_public_key() -> bytes:
    """Generate a fresh Ed25519 agent public key."""
    private = ed25519.Ed25519PrivateKey.generate()
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _make_ca_with_sponsor(email: str = "sponsor@corp.com"):
    """Create a CA with a registered sponsor."""
    sponsor_private, sponsor_public = _make_sponsor_keypair()
    registry = SponsorRegistry()
    registry.register_sponsor(email, sponsor_public)
    ca = CertificateAuthority(sponsor_registry=registry)
    return ca, sponsor_private, email


# ---------------------------------------------------------------------------
# SponsorRegistry tests
# ---------------------------------------------------------------------------


class TestSponsorRegistry:
    """Tests for the SponsorRegistry."""

    def test_register_and_lookup(self):
        reg = SponsorRegistry()
        _, pub = _make_sponsor_keypair()
        reg.register_sponsor("test@example.com", pub)
        assert reg.is_registered("test@example.com")
        assert reg.get_public_key("test@example.com") is pub

    def test_unregistered_returns_none(self):
        reg = SponsorRegistry()
        assert reg.get_public_key("nobody@example.com") is None
        assert not reg.is_registered("nobody@example.com")

    def test_remove_sponsor(self):
        reg = SponsorRegistry()
        _, pub = _make_sponsor_keypair()
        reg.register_sponsor("rm@example.com", pub)
        reg.remove_sponsor("rm@example.com")
        assert not reg.is_registered("rm@example.com")


# ---------------------------------------------------------------------------
# CRIT-1: Sponsor signature verification
# ---------------------------------------------------------------------------


class TestSponsorSignatureVerification:
    """CRIT-1: Validates that _validate_sponsor_signature actually verifies."""

    def test_valid_sponsor_signature_accepted(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        sig = _sign_registration(sponsor_key, "my-agent", email, ["read:data"])
        request = RegistrationRequest(
            agent_name="my-agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=sig,
            capabilities=["read:data"],
        )
        # Should not raise
        response = ca.register_agent(request)
        assert response.status == "success"
        assert response.initial_trust_score == 500

    def test_fabricated_signature_rejected(self):
        ca, _, email = _make_ca_with_sponsor()
        request = RegistrationRequest(
            agent_name="rogue-agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=b"totally-fake-signature",
            capabilities=[],
        )
        with pytest.raises(ValueError, match="Invalid sponsor signature"):
            ca.register_agent(request)

    def test_unregistered_sponsor_rejected(self):
        ca, sponsor_key, _ = _make_ca_with_sponsor("known@corp.com")
        sig = _sign_registration(sponsor_key, "agent", "unknown@evil.com")
        request = RegistrationRequest(
            agent_name="agent",
            public_key=_make_agent_public_key(),
            sponsor_email="unknown@evil.com",
            sponsor_signature=sig,
            capabilities=[],
        )
        with pytest.raises(ValueError, match="Invalid sponsor signature"):
            ca.register_agent(request)

    def test_wrong_key_signature_rejected(self):
        """Signature from a different key than the registered sponsor."""
        ca, _, email = _make_ca_with_sponsor()
        rogue_key = ed25519.Ed25519PrivateKey.generate()
        sig = _sign_registration(rogue_key, "agent", email)
        request = RegistrationRequest(
            agent_name="agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=sig,
            capabilities=[],
        )
        with pytest.raises(ValueError, match="Invalid sponsor signature"):
            ca.register_agent(request)

    def test_tampered_capabilities_rejected(self):
        """Signature valid for different capabilities than claimed."""
        ca, sponsor_key, email = _make_ca_with_sponsor()
        # Sign for ["read:data"] but request claims ["read:data", "admin:all"]
        sig = _sign_registration(sponsor_key, "agent", email, ["read:data"])
        request = RegistrationRequest(
            agent_name="agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=sig,
            capabilities=["read:data", "admin:all"],
        )
        with pytest.raises(ValueError, match="Invalid sponsor signature"):
            ca.register_agent(request)

    def test_empty_sponsor_registry_rejects_all(self):
        """CA with no registered sponsors rejects everything."""
        ca = CertificateAuthority()
        key = ed25519.Ed25519PrivateKey.generate()
        sig = _sign_registration(key, "agent", "anyone@example.com")
        request = RegistrationRequest(
            agent_name="agent",
            public_key=_make_agent_public_key(),
            sponsor_email="anyone@example.com",
            sponsor_signature=sig,
            capabilities=[],
        )
        with pytest.raises(ValueError, match="Invalid sponsor signature"):
            ca.register_agent(request)


# ---------------------------------------------------------------------------
# CRIT-2: Refresh token validation
# ---------------------------------------------------------------------------


class TestRefreshTokenValidation:
    """CRIT-2: Validates that rotate_credentials checks issued tokens."""

    def _register_agent(self, ca, sponsor_key, email):
        """Register an agent and return the response."""
        sig = _sign_registration(sponsor_key, "test-agent", email)
        request = RegistrationRequest(
            agent_name="test-agent",
            public_key=_make_agent_public_key(),
            sponsor_email=email,
            sponsor_signature=sig,
        )
        return ca.register_agent(request)

    def test_valid_refresh_token_accepted(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg = self._register_agent(ca, sponsor_key, email)
        new_key = _make_agent_public_key()
        # Use the real refresh token from registration
        rotated = ca.rotate_credentials(
            reg.agent_did, reg.refresh_token, new_key
        )
        assert rotated.agent_did == reg.agent_did
        assert rotated.status == "success"

    def test_fabricated_token_rejected(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg = self._register_agent(ca, sponsor_key, email)
        new_key = _make_agent_public_key()
        with pytest.raises(ValueError, match="Invalid or expired refresh token"):
            ca.rotate_credentials(reg.agent_did, "fake-token-12345", new_key)

    def test_token_bound_to_did(self):
        """Token from agent A cannot be used to rotate agent B's creds."""
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg_a = self._register_agent(ca, sponsor_key, email)
        new_key = _make_agent_public_key()
        with pytest.raises(ValueError, match="Invalid or expired refresh token"):
            ca.rotate_credentials("did:mesh:differentagent", reg_a.refresh_token, new_key)

    def test_token_single_use(self):
        """Refresh token can only be used once."""
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg = self._register_agent(ca, sponsor_key, email)
        new_key = _make_agent_public_key()
        # First use succeeds
        ca.rotate_credentials(reg.agent_did, reg.refresh_token, new_key)
        # Second use fails (token consumed)
        with pytest.raises(ValueError, match="Invalid or expired refresh token"):
            ca.rotate_credentials(reg.agent_did, reg.refresh_token, _make_agent_public_key())

    def test_rotated_credentials_have_new_refresh_token(self):
        """After rotation, a new valid refresh token is issued."""
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg = self._register_agent(ca, sponsor_key, email)
        new_key = _make_agent_public_key()
        rotated = ca.rotate_credentials(reg.agent_did, reg.refresh_token, new_key)
        # The new refresh token should also work
        another_key = _make_agent_public_key()
        rotated2 = ca.rotate_credentials(
            rotated.agent_did, rotated.refresh_token, another_key
        )
        assert rotated2.agent_did == reg.agent_did

    def test_missing_public_key_raises(self):
        ca, sponsor_key, email = _make_ca_with_sponsor()
        reg = self._register_agent(ca, sponsor_key, email)
        with pytest.raises(ValueError, match="New public key required"):
            ca.rotate_credentials(reg.agent_did, reg.refresh_token)
