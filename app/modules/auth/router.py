"""
OIDC/SSO login flow. Each institution can register its own OIDC issuer
(Institution.oidc_domain) so staff log in via their existing IdP (Okta,
Azure AD, etc). On successful callback, we mint our own short-lived JWT
carrying tenant_id + role, which every other module trusts via
app.core.security.get_current_auth.
"""
from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/login/{institution_slug}")
async def login(institution_slug: str):
    """
    TODO: look up Institution by slug, redirect to its OIDC provider's
    authorization endpoint with correct client_id/redirect_uri.
    """
    raise NotImplementedError


@router.get("/callback")
async def callback(code: str, state: str):
    """
    TODO: exchange code for tokens with the IdP, resolve/create User row,
    issue our own JWT (sub=user_id, tenant_id, role), return to client.
    """
    raise NotImplementedError
