import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException

# --- Secret key (generate a strong random one in production!) ---
SECRET_KEY = "SUPER_SECRET_SIC_KEY_CHANGE_ME"
ALGORITHM = "HS512"   # Stronger than HS256
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Tokens last 1 hour

# --- Create JWT ---
def create_jwt(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Decode & verify JWT ---
def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired, please log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
