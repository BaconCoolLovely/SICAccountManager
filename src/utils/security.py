import bcrypt
import secrets
import string

# --- Password hashing ---
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

# --- Secret key generator for users ---
def generate_user_secret_key(length: int = 158) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>?/|"
    return ''.join(secrets.choice(alphabet) for _ in range(length))
