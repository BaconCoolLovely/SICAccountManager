# Other imports...
from fastapi import HTTPException, Form

# Your existing routes: /register, /login, /dashboard, /register-device

# --- WatcherDog Admin Endpoint ---
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
    
    # TODO: enqueue shutdown action safely
    return {"status": "shutdown_requested", "requested_by": payload.get("sub")}
