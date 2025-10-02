# --- WatcherDog Admin Endpoints ---

# Shutdown website/OS
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

# Lock website
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

# Unlock website
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

# Block device
@app.post("/admin/watcherdog/block-device")
def block_device(device_id: int = Form(...), token: str = Form(...), db=Depends(get_db)):
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

# Unblock device
@app.post("/admin/watcherdog/unblock-device")
def unblock_device(device_id: int = Form(...), token: str = Form(...), db=Depends(get_db)):
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
