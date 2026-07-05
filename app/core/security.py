"""
JWT decoding + the `current_user` / `current_tenant` FastAPI dependencies.
Institutions authenticate via OIDC/SSO (see app/modules/auth); once exchanged
for our own short-lived JWT, every downstream request carries tenant_id + role.
"""
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings

bearer_scheme = HTTPBearer()


@dataclass
class AuthContext:
    user_id: str
    tenant_id: str
    role: str


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from e


async def get_current_auth(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> AuthContext:
    payload = decode_token(creds.credentials)
    return AuthContext(
        user_id=payload["sub"],
        tenant_id=payload["tenant_id"],
        role=payload.get("role", "viewer"),
    )


def require_role(*allowed_roles: str):
    """Dependency factory: `Depends(require_role("admin", "analyst"))`."""
    def _check(auth: AuthContext = Depends(get_current_auth)) -> AuthContext:
        if auth.role not in allowed_roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return auth
    return _check
