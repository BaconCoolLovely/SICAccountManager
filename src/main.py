from fastapi import FastAPI, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from jose import jwt
import secrets

from models.user import User
from models.device import Device
from utils.database import get_db, init_db
from utils.security import hash_password, verify_password
from utils.jwt_helper import create_jwt, decode_jwt, log_action

# --- App setup ---
app = FastAPI()
templates = Jinja2Templates(directory="src/templates")

# --- Initialize database ---
@app.on_event("startup")
def startup_event():
    init_db()

# Shared code for all blocked accounts
BLOCKED_CODE = "SIC_BLOCKED_2025"

# --- Index route ---
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# --- User registration ---
@app.post("/register")
def register(
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(...),
    birthday: str = Form(...),
    db: Session = Depends(get_db)
):
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(400, "Username already exists")

    # Generate unique 158-character key per user
    secret_key = secrets.token_urlsafe(118)[:158]

    new_user = User(
        username=username,
        password_hash=hash_password(password),
        secret_key=secret_key,
        email=email,
        birthday=birthday,
        is_admin=False,
        blocked=False,
        blocked_code=None
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_action("User registered", username)
    return {"status": "registered", "username": username}


# --- User login ---
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(401, "Invalid username or password")
    if user.blocked:
        raise HTTPException(403, f"Account blocked. Code: {user.blocked_code}")

    token = create_jwt({"sub": user.username, "is_admin": user.is_admin}, user.secret_key)
    log_action("User logged in", username)
    return {"access_token": token, "token_type": "bearer"}


# --- Dashboard ---
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, token: str, db: Session = Depends(get_db)):
    try:
        unsigned = jwt.get_unverified_claims(token)
        username = unsigned.get("sub")
    except Exception:
        raise HTTPException(401, "Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(401, "User not found")

    payload = decode_jwt(token, user.secret_key)
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "username": payload.get("sub"), "is_admin": payload.get("is_admin")},
    )


# --- WatcherDog Admin Endpoints ---
def get_admin_payload(token: str, db: Session):
    try:
        unsigned = jwt.get_unverified_claims(token)
        username = unsigned.get("sub")
    except Exception:
        raise HTTPException(401, "Invalid token structure")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(401, "Invalid user")
    payload = decode_jwt(token, user.secret_key)
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin required")
    return payload

# Shutdown website/OS
@app.post("/admin/watcherdog/shutdown")
def watcherdog_shutdown(confirmation: str = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    payload = get_admin_payload(token, db)
    if confirmation != "CONFIRM_SHUTDOWN":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Shutdown requested", payload.get("sub"))
    return {"status": "shutdown_requested", "requested_by": payload.get("sub")}


# Lock website
@app.post("/admin/watcherdog/lock-website")
def lock_website(confirmation: str = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    payload = get_admin_payload(token, db)
    if confirmation != "CONFIRM_LOCK":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Website locked", payload.get("sub"))
    return {"status": "website_locked", "requested_by": payload.get("sub")}


# Unlock website
@app.post("/admin/watcherdog/unlock-website")
def unlock_website(confirmation: str = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    payload = get_admin_payload(token, db)
    if confirmation != "CONFIRM_UNLOCK":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Website unlocked", payload.get("sub"))
    return {"status": "website_unlocked", "requested_by": payload.get("sub")}


# Block user
@app.post("/admin/watcherdog/block-user")
def block_user(user_id: int = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    payload = get_admin_payload(token, db)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    user.blocked = True
    user.blocked_code = BLOCKED_CODE
    db.commit()
    log_action(f"User {user.username} blocked", payload.get("sub"))
    return {
        "status": "user_blocked",
        "username": user.username,
        "email": user.email,
        "birthday": user.birthday,
        "id": user.id,
        "blocked_code": user.blocked_code
    }

# Unblock user
@app.post("/admin/watcherdog/unblock-user")
def unblock_user(user_id: int = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    payload = get_admin_payload(token, db)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    user.blocked = False
    user.blocked_code = None
    db.commit()
    log_action(f"User {user.username} unblocked", payload.get("sub"))
    return {
        "status": "user_unblocked",
        "username": user.username,
        "email": user.email,
        "birthday": user.birthday,
        "id": user.id
    }
