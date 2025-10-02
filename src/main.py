from fastapi import FastAPI, Form, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from models.user import User
from models.device import Device
from utils.jwt_helper import create_jwt, decode_jwt
from utils.security import hash_password, verify_password, generate_user_secret_key
from utils.logs import log_action
from database import get_db

app = FastAPI()
templates = Jinja2Templates(directory="src/templates")

# -------------------------------------------------
#  User Authentication & Dashboard
# -------------------------------------------------
@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    hashed = hash_password(password)
    secret_key = generate_user_secret_key()
    user = User(username=username, password_hash=hashed, secret_key=secret_key)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action("User registered", username)
    return {"message": "User registered successfully"}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(401, "Invalid username or password")

    token = create_jwt({"sub": user.username, "is_admin": user.is_admin}, user.secret_key)
    log_action("User logged in", username)
    return {"access_token": token}

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, token: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == decode_jwt(token, user.secret_key)["sub"]).first()
    if not user:
        raise HTTPException(401, "User not found")

    payload = decode_jwt(token, user.secret_key)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "username": payload.get("sub")
    })

@app.post("/register-device")
def register_device(name: str = Form(...), user_id: int = Form(...), db: Session = Depends(get_db)):
    device = Device(name=name, owner_id=user_id)
    db.add(device)
    db.commit()
    db.refresh(device)
    log_action(f"Device {device.name} registered", f"User {user_id}")
    return {"message": "Device registered successfully", "device_id": device.id}

# -------------------------------------------------
#  WatcherDog Admin Endpoints (shutdown/lock/block etc.)
# -------------------------------------------------
# (same as before, but in each endpoint we fetch user.secret_key first before decode_jwt)
