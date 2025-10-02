import jwt
from datetime import datetime, timedelta

# Secret key for JWT — keep this safe
JWT_SECRET = "replace_this_with_a_strong_secret"
JWT_ALGO = "HS256"
JWT_EXPIRES_MINUTES = 60 * 24  # 1 day

# Create a JWT token
def create_jwt(payload: dict) -> str:
    to_encode = payload.copy()
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)

# Decode and validate a JWT token
def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise Exception("Token expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")
