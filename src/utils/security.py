import bcrypt
from datetime import datetime, timedelta
import jwt

# Secret for JWTs — keep this safe in .env or GitHub Secrets
JWT_SECRET = "replace_this_with_a_strong_secret"
JWT_ALGO = "HS256"
JWT_EXPIRES_MINUTES = 60 * 24  # 1 day

# Password hashing
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

# JWT creation and decoding
def create_jwt(payload: dict) -> str:
    to_encode = payload.copy()
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)

def decode_jwt(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
