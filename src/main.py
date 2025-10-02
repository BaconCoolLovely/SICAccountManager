from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.user import Base, User
from models.device import Device
from utils.security import hash_password, verify_password, create_jwt, decode_jwt

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
def dashboard(request: Request, db=Depends(get_db)):
    # For now, show all devices (later filter by logged-in user)
    devices = db.query(Device).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "devices": devices})

# Register a device
@app.post("/register-device")
def register_device(device_name: str = Form(...), db=Depends(get_db)):
    # For now, assign to user_id=1 as placeholder
    device = Device(name=device_name, owner_id=1, authorized=True)
    db.add(device)
    db.commit()
    db.refresh(device)
    return {"message": "Device registered", "device": device.name}

# --- WatcherDog Admin Endpoint ---
@app.post("/admin/watcherdog/shutdown")
def watcherdog_shutdown(confirmation: str = Form(...), token: str = Form(...)):
    # Validate admin token
    try:
        payload = decode_jwt(token)
    except:
        raise HTTPException(401, "Invalid token")
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin required")
    
    # Safety: require exact confirmation phrase
    if confirmation != "CONFIRM_SHUTDOWN":
        raise HTTPException(400, "Invalid confirmation phrase")
    
    # TODO: trigger safe shutdown process
    return {"status": "shutdown_requested", "requested_by": payload.get("sub")}
