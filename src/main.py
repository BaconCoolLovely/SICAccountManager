from fastapi import FastAPI, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from utils.jwt_helper import create_jwt, decode_jwt
from utils.security import hash_password, verify_password
from utils.logs import log_action
from models.user import User
from models.device import Device
from database import get_db

app = FastAPI()
templates = Jinja2Templates(directory="src/templates")

# -------------------------------
# User Authentication + Dashboard
# -------------------------------

@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(400, "User already exists")
    user = User(username=username, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    return {"msg": "User registered successfully"}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(401, "Invalid username or password")
    token = create_jwt({"sub": user.username, "is_admin": user.is_admin})
    log_action("User logged in", user.username)
    return {"access_token": token}

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(user: dict = Depends(decode_jwt), db: Session = Depends(get_db)):
    devices = db.query(Device).filter(Device.owner_id == user["sub"]).all()
    return templates.TemplateResponse("dashboard.html", {"request": {}, "user": user, "devices": devices})

@app.post("/register-device")
def register_device(name: str = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    try:
        payload = decode_jwt(token)
    except Exception:
        raise HTTPException(401, "Invalid token")
    device = Device(name=name, authorized=True, owner_id=payload["sub"])
    db.add(device)
    db.commit()
    log_action(f"Device {name} registered", payload["sub"])
    return {"msg": "Device registered successfully", "device": name}

# -------------------------------
# WatcherDog Admin Endpoints
# -------------------------------

@app.post("/admin/watcherdog/shutdown")
def watcherdog_shutdown(confirmation: str = Form(...), token: str = Form(...)):
    try:
        payload = decode_jwt(token)
    except Exception as e:
        raise HTTPException(401, f"Invalid token: {str(e)}")
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin required")
    if confirmation != "CONFIRM_SHUTDOWN":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Shutdown requested", payload.get("sub"))
    # TODO: enqueue safe shutdown process
    return {"status": "shutdown_requested", "requested_by": payload.get("sub")}

@app.post("/admin/watcherdog/lock-website")
def lock_website(confirmation: str = Form(...), token: str = Form(...)):
    try:
        payload = decode_jwt(token)
    except Exception as e:
        raise HTTPException(401, f"Invalid token: {str(e)}")
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin required")
    if confirmation != "CONFIRM_LOCK":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Website locked", payload.get("sub"))
    # TODO: disable routes safely
    return {"status": "website_locked", "requested_by": payload.get("sub")}

@app.post("/admin/watcherdog/unlock-website")
def unlock_website(confirmation: str = Form(...), token: str = Form(...)):
    try:
        payload = decode_jwt(token)
    except Exception as e:
        raise HTTPException(401, f"Invalid token: {str(e)}")
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin required")
    if confirmation != "CONFIRM_UNLOCK":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Website unlocked", payload.get("sub"))
    # TODO: enable routes safely
    return {"status": "website_unlocked", "requested_by": payload.get("sub")}

@app.post("/admin/watcherdog/block-device")
def block_device(device_id: int = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    try:
        payload = decode_jwt(token)
    except Exception as e:
        raise HTTPException(401, f"Invalid token: {str(e)}")
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin required")
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    device.authorized = False
    db.commit()
    log_action(f"Device {device.name} blocked", payload.get("sub"))
    return {"status": "device_blocked", "device": device.name}

@app.post("/admin/watcherdog/unblock-device")
def unblock_device(device_id: int = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    try:
        payload = decode_jwt(token)
    except Exception as e:
        raise HTTPException(401, f"Invalid token: {str(e)}")
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin required")
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    device.authorized = True
    db.commit()
    log_action(f"Device {device.name} unblocked", payload.get("sub"))
    return {"status": "device_unblocked", "device": device.name}

# -------------------------------
# Admin Dashboard Page
# -------------------------------

@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard(user: dict = Depends(decode_jwt), db: Session = Depends(get_db)):
    if not user.get("is_admin"):
        raise HTTPException(403, "Admin required")
    devices = db.query(Device).all()
    return templates.TemplateResponse("admin_dashboard.html", {"request": {}, "user": user, "devices": devices})
