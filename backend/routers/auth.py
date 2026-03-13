"""
PRISM API — Authentication Endpoint
POST /api/auth/login — user login
POST /api/auth/logout — user logout
GET /api/auth/me — get current user
"""

from fastapi import APIRouter, HTTPException, Response, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

# Hardcoded credentials (for demo purposes)
VALID_CREDENTIALS = {
    "jk2302@gmail.com": "Jk@9176101672"
}

# Simple session storage (in production, use Redis or database)
active_sessions = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    authenticated: bool
    username: Optional[str] = None


@router.post("/auth/login")
async def login(req: LoginRequest, response: Response):
    """
    Authenticate user with hardcoded credentials.
    Sets a session cookie on success.
    """
    username = req.username.strip()
    password = req.password
    
    # Validate credentials
    if username not in VALID_CREDENTIALS:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if VALID_CREDENTIALS[username] != password:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Create session (simple token-based)
    import secrets
    session_token = secrets.token_urlsafe(32)
    active_sessions[session_token] = username
    
    # Set cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=86400,  # 24 hours
        samesite="lax"
    )
    
    return {
        "authenticated": True,
        "username": username,
        "message": "Login successful"
    }


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    """
    Logout user and clear session.
    """
    session_token = request.cookies.get("session_token")
    
    if session_token and session_token in active_sessions:
        del active_sessions[session_token]
    
    response.delete_cookie("session_token")
    
    return {
        "authenticated": False,
        "message": "Logout successful"
    }


@router.get("/auth/me", response_model=UserResponse)
async def get_current_user(request: Request):
    """
    Get current authenticated user.
    """
    session_token = request.cookies.get("session_token")
    
    if not session_token or session_token not in active_sessions:
        return UserResponse(authenticated=False)
    
    username = active_sessions[session_token]
    return UserResponse(authenticated=True, username=username)


# Helper function to check authentication (can be used as dependency)
def require_auth(request: Request):
    """
    Dependency to require authentication for protected routes.
    """
    session_token = request.cookies.get("session_token")
    
    if not session_token or session_token not in active_sessions:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    return active_sessions[session_token]
