from fastapi import FastAPI, Form, HTTPException, Depends
from sqlalchemy.orm import Session
from models.database import get_db
from models.user import User
from models.appeal import Appeal
from utils.jwt_helper import decode_jwt
from utils.logger import log_action

app = FastAPI()

@app.post("/appeal")
def submit_appeal(reason: str = Form(...), token: str = Form(...), db: Session = Depends(get_db)):
    """
    Submit an appeal if the user's account is blocked.
    """
    try:
        payload = decode_jwt(token)
    except Exception:
        raise HTTPException(401, "Invalid token")
    
    username = payload.get("sub")
    if not username:
        raise HTTPException(401, "Invalid token payload: missing username")
    
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(404, "User not found")
    if not user.blocked:
        raise HTTPException(400, "Your account is not blocked")
    
    # Create a new appeal
    appeal = Appeal(user_id=user.id, reason=reason)
    db.add(appeal)
    db.commit()
    db.refresh(appeal)
    
    # Log action for WatcherDog
    log_action(f"Appeal submitted by {username}", username)
    
    return {
        "status": "appeal_submitted",
        "appeal_id": appeal.id,
        "user": username
    }
