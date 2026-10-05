from datetime import datetime, timedelta
from jose import jwt, JWTError

import os
from dotenv import load_dotenv

# Load env variables
load_dotenv()

SECRET_KEY = os.getenv("SUPABASE_JWT_SECRET", "JPL_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOUR = 6

def create_access_token(data: dict):
    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOUR)
    to_encode.update({"exp":expire})

    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return token

def verify_token(token: str):
    if not token:
        return None
        
    # 1. Attempt fast local verification if token algorithm is HS256/HS384/HS512
    try:
        header = jwt.get_unverified_header(token)
        token_alg = header.get("alg", "HS256")
        
        # Only attempt local decode if algorithm is symmetric HMAC or if we have JWKS for asymmetric
        import time
        payload = None

        if token_alg.startswith("HS"):
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256", "HS384", "HS512"], options={"verify_aud": False, "verify_exp": False})
        elif token_alg.startswith("RS"):
            from jwt import PyJWKClient
            jwks_url = os.getenv("SUPABASE_JWKS_URL")
            if jwks_url:
                jwks_client = PyJWKClient(jwks_url)
                signing_key = jwks_client.get_signing_key_from_jwt(token)
                payload = jwt.decode(token, signing_key.key, algorithms=["RS256", "RS384", "RS512"], options={"verify_aud": False, "verify_exp": False})

        if payload:
            # Allow a 12-hour grace period for the auction duration since frontend doesn't auto-refresh
            if payload.get("exp") and payload["exp"] < time.time() - (12 * 3600):
                print("[Auth Info] Session token has expired beyond 12-hour grace period.")
                return None

            role = (
                payload.get("app_metadata", {}).get("role") or 
                payload.get("user_metadata", {}).get("role") or 
                payload.get("role") or 
                "team"
            )
            return {
                "id": payload.get("sub"),
                "email": payload.get("email"),
                "role": role,
                "team_id": payload.get("user_metadata", {}).get("team_id"),
                "name": payload.get("user_metadata", {}).get("name", "")
            }
    except jwt.ExpiredSignatureError:
        print("[Auth Info] Session token has expired. User needs to log in again.")
        return None
    except Exception as e:
        print(f"[Auth Info] Local token verification failed ({e}). Falling back to Supabase API.")
        pass  # Fall through to Supabase Auth API verification

    # 2. Fallback to Supabase Auth API verification if local check fails
    try:
        from core.supabase_client import get_supabase_client
        supabase = get_supabase_client()
        res = supabase.auth.get_user(token)
        user = res.user
        
        if not user:
            return None
            
        app_meta_role = user.app_metadata.get("role") if user.app_metadata else None
        user_meta_role = user.user_metadata.get("role") if user.user_metadata else None
        role = app_meta_role or user_meta_role or "team"
        
        return {
            "id": user.id,
            "email": user.email,
            "role": role,
            "team_id": user.user_metadata.get("team_id") if user.user_metadata else None,
            "name": user.user_metadata.get("name", "") if user.user_metadata else ""
        }
    
    except Exception as api_err:
        err_str = str(api_err)
        if "expired" in err_str.lower():
            print("[Auth Info] Session token has expired via Supabase API check.")
        else:
            print("[Auth Error] Token verification failed via Supabase API:", api_err)
        return None
    
def get_token_from_request(request):
    # 1️⃣ Check Authorization header (Android)
    auth_header = request.headers.get("Authorization")

    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1]

    # 2️⃣ Fallback to Cookie (Web)
    return request.cookies.get("access_token")