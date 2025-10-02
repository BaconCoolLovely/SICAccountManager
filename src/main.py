from fastapi import FastAPI, Request, Form, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.user import Base, User
from models.device import Device
from utils.security import hash_password, verify_password, create_jwt, decode_jwt
from utils.logs import log_action  # WatcherDog logging

# --- Database Setup ---
DATABASE_URL = "sqlite:///./sic_account_manager.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# --- App Setup ---
app = FastAPI()
templates = Jinja2Templates(directory="src/templates")

# --- Dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- JWT Auth Dependency ---
def get_current_user(token: str = Header(...), db=Depends(get_db)):
    try:
        payload = decode_jwt(token)
        user_id = payload.get("user_id")
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(401, "User not found")
        return user
    except:
        raise HTTPException(401, "Invalid token")

# --- ROUTES ---

# Landing page
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Register new user
@app.post("/register")
def register(username: str = Form(...), password: str = Form(...), db=Depends(get_db)):
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(400, "Username already exists")
    user = User(username=username, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User registered", "username": user.username}

# Login
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), db=Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    token = create_jwt({"sub": user.username, "user_id": user.id, "is_admin": user.is_admin})
    return {"access_token": token, "token_type": "bearer"}

# Dashboard page
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, current_user: User = Depends(get_current_user), db=Depends(get_db)):
    devices = db.query(Device).filter(Device.owner_id == current_user.id).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "devices": devices})

# Register a device
@app.post("/register-device")
def register_device(device_name: str = Form(...), current_user: User = Depends(get_current_user), db=Depends(get_db)):
    device = Device(name=device_name, owner_id=current_user.id, authorized=True)
    db.add(device)
    db.commit()
    db.refresh(device)
    return {"message": "Device registered", "device": device.name}

# --- WatcherDog Admin Endpoints ---

# Shutdown website/OS
@app.post("/admin/watcherdog/shutdown")
def watcherdog_shutdown(confirmation: str = Form(...), token: str = Form(...)):
    try:
        payload = decode_jwt(token)
    except:
        raise HTTPException(401, "Invalid token")
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin required")
    if confirmation != "CONFIRM_SHUTDOWN":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Shutdown requested", payload.get("sub"))
    # TODO: enqueue safe shutdown process
    return {"status": "shutdown_requested", "requested_by": payload.get("sub")}

# Lock website
@app.post("/admin/watcherdog/lock-website")
def lock_website(confirmation: str = Form(...), token: str = Form(...)):
    try:
        payload = decode_jwt(token)
    except:
        raise HTTPException(401, "Invalid token")
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin required")
    if confirmation != "CONFIRM_LOCK":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Website locked", payload.get("sub"))
    # TODO: disable routes safely
    return {"status": "website_locked", "requested_by": payload.get("sub")}

# Unlock website
@app.post("/admin/watcherdog/unlock-website")
def unlock_website(confirmation: str = Form(...), token: str = Form(...)):
    try:
        payload = decode_jwt(token)
    except:
        raise HTTPException(401, "Invalid token")
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin required")
    if confirmation != "CONFIRM_UNLOCK":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Website unlocked", payload.get("sub"))
    # TODO: enable routes safely
    return {"status": "website_unlocked", "requested_by": payload.get("sub")}

# Block device
@app.post("/admin/watcherdog/block-device")
def block_device(device_id: int = Form(...), token: str = Form(...), db=Depends(get_db)):
    try:
        payload = decode_jwt(token)
    except:
        raise HTTPException(401, "Invalid token")
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin required")
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    device.authorized = False
    db.commit()
    log_action(f"Device {device.name} blocked", payload.get("sub"))
    return {"status": "device_blocked", "device": device.name}
