import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException

ALGORITHM = "HS512"   # strong algo
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # token lifetime

# --- Create JWT with user’s secret key ---
def create_jwt(data: dict, user_secret: str, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, user_secret, algorithm=ALGORITHM)
    return encoded_jwt

# --- Decode JWT with user’s secret key ---
def decode_jwt(token: str, user_secret: str):
    try:
        payload = jwt.decode(token, user_secret, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired, please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
