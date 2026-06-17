import logging
from typing import Set
from fastapi import Security, HTTPException, status, Depends
from fastapi.security.api_key import APIKeyHeader
from core.config import settings

logger = logging.getLogger(__name__)

# Define the custom header for key retrieval
API_KEY_HEADER_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)

def verify_api_key(
    api_key_header_value: str = Security(api_key_header)
) -> str:
    """
    Validates API key from request headers.
    Returns: The assigned role name string ('Admin' or 'Analyst')
    Raises: HTTP 401 Unauthorized for invalid keys.
    """
    if not api_key_header_value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Missing API Key in header '{API_KEY_HEADER_NAME}'"
        )
        
    # Check key mappings configured in env settings
    if api_key_header_value in settings.ADMIN_API_KEYS:
        return "Admin"
    elif api_key_header_value in settings.ANALYST_API_KEYS:
        return "Analyst"
        
    logger.warning("Failed authentication attempt with invalid API key.")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired API Key"
    )


class RoleChecker:
    """Dependency helper to enforce Role-Based Access Control (RBAC)."""
    def __init__(self, allowed_roles: Set[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, role: str = Depends(verify_api_key)) -> str:
        if role not in self.allowed_roles:
            logger.warning("Unauthorized access attempt. Client has role '%s', required: %s", role, self.allowed_roles)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to perform this action."
            )
        return role

# Define shortcut dependencies for routes
require_analyst = RoleChecker({"Analyst", "Admin"})  # Analysts and Admins can view threat intel
require_admin = RoleChecker({"Admin"})                # Only Admins can run ingestions or delete data
