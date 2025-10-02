from fastapi import FastAPI, Form, HTTPException, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from models.database import get_db
from models.user import User
from models.device import Device
from models.appeal import Appeal
from utils.jwt_helper import decode_jwt, get_admin_payload
from utils.logger import log_action

app = FastAPI()

# ---------------------------------------
# User Routes
# ---------------------------------------

@app.post("/appeal")
def submit_appeal(reason: str = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    """
    Submit an appeal if the user's account is blocked and not permanently banned.
    """
    try:
        payload = decode_jwt(token)
    except Exception:
        raise HTTPException(401, "Invalid token")
    
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    
    if not user:
        raise HTTPException(404, "User not found")
    if not user.blocked:
        raise HTTPException(400, "Your account is not blocked")
    if user.permanently_banned:
        raise HTTPException(403, "You are permanently banned and cannot submit appeals")
    
    appeal = Appeal(user_id=user.id, reason=reason)
    db.add(appeal)
    db.commit()
    db.refresh(appeal)
    log_action(f"Appeal submitted by {username}", username)
    
    return {"status": "appeal_submitted", "appeal_id": appeal.id}


# ---------------------------------------
# WatcherDog Admin Routes
# ---------------------------------------

# Helper: get admin payload
def require_admin(token: str, db: Session):
    payload = get_admin_payload(token, db)
    if not payload.get("is_admin"):
        raise HTTPException(403, "Admin privileges required")
    return payload

# List pending appeals
@app.get("/admin/watcherdog/appeals")
def list_appeals(token: str = Form(...), db: Session = Depends(get_db)):
    payload = require_admin(token, db)
    appeals = db.query(Appeal).filter(Appeal.resolved == False).all()
    result = []
    for a in appeals:
        result.append({
            "appeal_id": a.id,
            "username": a.user.username,
            "email": a.user.email,
            "birthday": a.user.birthday,
            "reason": a.reason,
            "blocked_code": a.user.blocked_code
        })
    return {"pending_appeals": result}

# Resolve appeal
@app.post("/admin/watcherdog/resolve_appeal")
def resolve_appeal(appeal_id: int = Form(...), approve: bool = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    payload = require_admin(token, db)
    appeal = db.query(Appeal).filter(Appeal.id == appeal_id).first()
    if not appeal:
        raise HTTPException(404, "Appeal not found")
    
    appeal.resolved = True
    appeal.approved = approve
    appeal.resolved_at = datetime.utcnow()
    appeal.resolved_by = payload.get("sub")
    
    if approve:
        user = appeal.user
        user.blocked = False
        user.blocked_code = None
        db.commit()
        log_action(f"Appeal approved, user {user.username} unblocked", payload.get("sub"))
        return {"status": "appeal_approved", "user": user.username}
    else:
        db.commit()
        log_action(f"Appeal denied for user {appeal.user.username}", payload.get("sub"))
        return {"status": "appeal_denied", "user": appeal.user.username}


# Tiered block (1=normal, 2=serious, 3=extreme)
@app.post("/admin/watcherdog/block-tiered")
def block_tiered(user_id: int = Form(...), tier: int = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    payload = require_admin(token, db)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    
    if tier == 1:
        user.blocked = True
        user.blocked_code = "BLOCKED"
        log_action(f"Tier-1 block applied to {user.username}", payload.get("sub"))
    elif tier == 2:
        user.blocked = True
        user.blocked_code = "BLOCKED"
        for device in user.devices:
            device.authorized = False
        log_action(f"Tier-2 block applied (devices blocked) to {user.username}", payload.get("sub"))
    elif tier == 3:
        user.blocked = True
        user.blocked_code = "BLOCKED"
        for device in user.devices:
            device.authorized = False
        # TODO: implement OS full lock
        log_action(f"Tier-3 extreme block applied to {user.username}", payload.get("sub"))
    else:
        raise HTTPException(400, "Invalid tier")
    
    db.commit()
    return {"status": "blocked", "tier": tier, "user": user.username}


# Permanently ban user
@app.post("/admin/watcherdog/permanent_ban")
def permanent_ban_user(user_id: int = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    payload = require_admin(token, db)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    
    user.permanently_banned = True
    user.blocked = True
    user.blocked_code = "PERMA_BAN"
    db.commit()
    
    log_action(f"User {user.username} permanently banned", payload.get("sub"))
    return {"status": "user_permanently_banned", "user": user.username}


# --- Optional: WatcherDog shutdown, lock/unlock website, block/unblock device routes ---
# Add your previous WatcherDog endpoints here
