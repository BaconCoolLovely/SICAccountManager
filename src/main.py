from fastapi import FastAPI, Form, HTTPException, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from models.database import get_db
from models.user import User
from models.appeal import Appeal
from models.device import Device
from utils.jwt_helper import decode_jwt, get_admin_payload
from utils.logger import log_action

app = FastAPI()

# ----------------------------
# User Appeal Route (Step 1a)
# ----------------------------
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


# ----------------------------
# Admin - List Pending Appeals (Step 1b)
# ----------------------------
@app.get("/admin/watcherdog/appeals")
def list_appeals(token: str = Form(...), db: Session = Depends(get_db)):
    """
    Returns all unresolved appeals for admin review.
    """
    payload = get_admin_payload(token, db)
    
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


# ----------------------------
# Admin - Resolve Appeal
# ----------------------------
@app.post("/admin/watcherdog/resolve_appeal")
def resolve_appeal(
    appeal_id: int = Form(...),
    approve: bool = Form(...),
    token: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Approve or deny a user's appeal.
    """
    payload = get_admin_payload(token, db)
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


# ----------------------------
# WatcherDog Admin Endpoints
# ----------------------------

# Shutdown website/OS
@app.post("/admin/watcherdog/shutdown")
def watcherdog_shutdown(confirmation: str = Form(...), token: str = Form(...)):
    payload = get_admin_payload(token)
    if confirmation != "CONFIRM_SHUTDOWN":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Shutdown requested", payload.get("sub"))
    # TODO: enqueue safe shutdown process
    return {"status": "shutdown_requested", "requested_by": payload.get("sub")}

# Lock website
@app.post("/admin/watcherdog/lock-website")
def lock_website(confirmation: str = Form(...), token: str = Form(...)):
    payload = get_admin_payload(token)
    if confirmation != "CONFIRM_LOCK":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Website locked", payload.get("sub"))
    # TODO: disable routes safely
    return {"status": "website_locked", "requested_by": payload.get("sub")}

# Unlock website
@app.post("/admin/watcherdog/unlock-website")
def unlock_website(confirmation: str = Form(...), token: str = Form(...)):
    payload = get_admin_payload(token)
    if confirmation != "CONFIRM_UNLOCK":
        raise HTTPException(400, "Invalid confirmation phrase")
    log_action("Website unlocked", payload.get("sub"))
    # TODO: enable routes safely
    return {"status": "website_unlocked", "requested_by": payload.get("sub")}

# Block device
@app.post("/admin/watcherdog/block-device")
def block_device(device_id: int = Form(...), token: str = Form(...), db=Depends(get_db)):
    payload = get_admin_payload(token, db)
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    device.authorized = False
    db.commit()
    log_action(f"Device {device.name} blocked", payload.get("sub"))
    return {"status": "device_blocked", "device": device.name}

# Unblock device
@app.post("/admin/watcherdog/unblock-device")
def unblock_device(device_id: int = Form(...), token: str = Form(...), db=Depends(get_db)):
    payload = get_admin_payload(token, db)
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    device.authorized = True
    db.commit()
    log_action(f"Device {device.name} unblocked", payload.get("sub"))
    return {"status": "device_unblocked", "device": device.name}

# ----------------------------
# Admin - Permanently Ban User
# ----------------------------
@app.post("/admin/watcherdog/permanent_ban")
def permanent_ban_user(user_id: int = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    payload = get_admin_payload(token, db)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    
    user.permanently_banned = True
    user.blocked = True
    user.blocked_code = "PERMA_BAN"
    db.commit()
    
    log_action(f"User {user.username} permanently banned", payload.get("sub"))
    return {"status": "user_permanently_banned", "user": user.username}
