from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import socketio
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import hashlib
import bcrypt
import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import secrets
import json
import aiofiles
from collections import defaultdict
import time

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'obsidianx-super-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30

# Encryption key for messages (32 bytes for AES-256)
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', secrets.token_hex(32))
aesgcm = AESGCM(bytes.fromhex(ENCRYPTION_KEY[:64]))

# Rate limiting storage
rate_limit_store: Dict[str, Dict] = defaultdict(lambda: {'count': 0, 'reset_time': 0})
gate_attempts: Dict[str, Dict] = defaultdict(lambda: {'count': 0, 'locked_until': 0})
password_attempts: Dict[str, Dict] = defaultdict(lambda: {'count': 0, 'locked_until': 0})

# Upload directory
UPLOAD_DIR = ROOT_DIR / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)

# Socket.IO setup
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')

# Create the main app
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

security = HTTPBearer(auto_error=False)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ==================== PYDANTIC MODELS ====================

class GateValidateRequest(BaseModel):
    code: str

class StudentPickRequest(BaseModel):
    student_id: str

class VerifyPasswordRequest(BaseModel):
    student_id: str
    password: str

class CreateAccountRequest(BaseModel):
    student_id: str
    username: str
    password: str

class LoginRequest(BaseModel):
    gate_code: str
    username: str
    password: str

class AdminLoginRequest(BaseModel):
    username: str
    password: str

class StudentCreateRequest(BaseModel):
    full_name: str
    first_time_password: str

class StudentUpdateRequest(BaseModel):
    full_name: Optional[str] = None

class CodeUpdateRequest(BaseModel):
    first_time_code: Optional[str] = None
    login_code: Optional[str] = None

class MessageCreateRequest(BaseModel):
    chat_id: str
    content: str
    message_uuid: str
    reply_to: Optional[str] = None

class GroupCreateRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    member_ids: List[str]

class GroupUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    add_members: Optional[List[str]] = None
    remove_members: Optional[List[str]] = None

# ==================== UTILITY FUNCTIONS ====================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def encrypt_message(content: str) -> dict:
    iv = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(iv, content.encode(), None)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode()
    }

def decrypt_message(encrypted: dict) -> str:
    try:
        ciphertext = base64.b64decode(encrypted["ciphertext"])
        iv = base64.b64decode(encrypted["iv"])
        return aesgcm.decrypt(iv, ciphertext, None).decode()
    except Exception:
        return "[Decryption failed]"

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    user = await db.users.find_one({"id": payload.get("user_id")}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user.get("banned"):
        raise HTTPException(status_code=403, detail="User is banned")
    return user

async def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access" or not payload.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    admin = await db.admins.find_one({"id": payload.get("admin_id")}, {"_id": 0})
    if not admin:
        raise HTTPException(status_code=401, detail="Admin not found")
    return admin

async def log_audit(admin_id: str, action: str, target_type: str, target_id: str, details: dict = None):
    audit_entry = {
        "id": str(uuid.uuid4()),
        "admin_id": admin_id,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "details": details or {},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await db.audit_logs.insert_one(audit_entry)

def check_rate_limit(user_id: str, limit: int = 30, window: int = 60) -> bool:
    """Token bucket rate limiting - returns True if allowed"""
    now = time.time()
    bucket = rate_limit_store[user_id]
    if now > bucket['reset_time']:
        bucket['count'] = 0
        bucket['reset_time'] = now + window
    if bucket['count'] >= limit:
        return False
    bucket['count'] += 1
    return True

def get_cooldown_remaining(user_id: str) -> int:
    bucket = rate_limit_store[user_id]
    remaining = int(bucket['reset_time'] - time.time())
    return max(0, remaining)

# ==================== SYSTEM CONFIG ====================

async def get_system_config():
    config = await db.system_config.find_one({"id": "main"}, {"_id": 0})
    if not config:
        config = {
            "id": "main",
            "first_time_code": "UJUJUJIJ",
            "login_code": "RJPJKJNJ",
            "slow_mode_seconds": 0,
            "chat_frozen": False
        }
        await db.system_config.insert_one(config)
    return config

# ==================== GATE & AUTH ROUTES ====================

@api_router.post("/gate/validate")
async def validate_gate(request: GateValidateRequest, req: Request):
    client_ip = req.client.host
    now = time.time()
    
    # Check if IP is locked
    if gate_attempts[client_ip]['locked_until'] > now:
        remaining = int(gate_attempts[client_ip]['locked_until'] - now)
        raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {remaining} seconds")
    
    config = await get_system_config()
    code = request.code.strip().upper()
    
    if code == config['first_time_code']:
        gate_attempts[client_ip] = {'count': 0, 'locked_until': 0}
        return {"type": "first_time", "redirect": "/register/pick"}
    elif code == config['login_code']:
        gate_attempts[client_ip] = {'count': 0, 'locked_until': 0}
        return {"type": "login", "redirect": "/login"}
    else:
        gate_attempts[client_ip]['count'] += 1
        if gate_attempts[client_ip]['count'] >= 5:
            gate_attempts[client_ip]['locked_until'] = now + 300  # 5 min lockout
            raise HTTPException(status_code=429, detail="Too many attempts. Locked for 5 minutes")
        raise HTTPException(status_code=400, detail="Invalid code")

@api_router.get("/register/students")
async def get_unregistered_students():
    """Get list of unregistered students for picking"""
    students = await db.students.find({"registered": False}, {"_id": 0, "password_hash": 0}).to_list(1000)
    return students

@api_router.post("/register/pick")
async def pick_student(request: StudentPickRequest):
    student = await db.students.find_one({"id": request.student_id}, {"_id": 0})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    if student.get("registered"):
        raise HTTPException(status_code=400, detail="Student already registered")
    if student.get("locked"):
        raise HTTPException(status_code=403, detail="Student account is locked. Contact admin")
    return {"student_id": student["id"], "full_name": student["full_name"]}

@api_router.post("/register/verify")
async def verify_first_time_password(request: VerifyPasswordRequest, req: Request):
    student = await db.students.find_one({"id": request.student_id}, {"_id": 0})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    if student.get("registered"):
        raise HTTPException(status_code=400, detail="Student already registered")
    if student.get("locked"):
        raise HTTPException(status_code=403, detail="Account locked. Contact admin")
    
    # Check password attempts
    attempt_key = f"pwd_{request.student_id}"
    now = time.time()
    if password_attempts[attempt_key]['locked_until'] > now:
        remaining = int(password_attempts[attempt_key]['locked_until'] - now)
        raise HTTPException(status_code=429, detail=f"Account temporarily locked. Try again in {remaining} seconds")
    
    if not verify_password(request.password, student.get("password_hash", "")):
        password_attempts[attempt_key]['count'] += 1
        if password_attempts[attempt_key]['count'] >= 3:
            # Lock the student
            await db.students.update_one({"id": request.student_id}, {"$set": {"locked": True}})
            password_attempts[attempt_key]['locked_until'] = now + 3600  # 1 hour
            raise HTTPException(status_code=403, detail="Too many wrong attempts. Account locked. Contact admin")
        raise HTTPException(status_code=400, detail=f"Wrong password. {3 - password_attempts[attempt_key]['count']} attempts remaining")
    
    # Password correct
    password_attempts[attempt_key] = {'count': 0, 'locked_until': 0}
    return {"verified": True, "student_id": request.student_id}

@api_router.post("/register/create")
async def create_account(request: CreateAccountRequest):
    student = await db.students.find_one({"id": request.student_id}, {"_id": 0})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    if student.get("registered"):
        raise HTTPException(status_code=400, detail="Student already registered")
    
    # Check username uniqueness
    existing = await db.users.find_one({"username": request.username.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    # Validate username and password
    if len(request.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(request.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    # Create user
    user_id = str(uuid.uuid4())
    user = {
        "id": user_id,
        "student_id": request.student_id,
        "username": request.username.lower(),
        "display_name": student["full_name"],
        "password_hash": hash_password(request.password),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "online": False,
        "banned": False
    }
    await db.users.insert_one(user)
    
    # Mark student as registered
    await db.students.update_one({"id": request.student_id}, {"$set": {"registered": True, "user_id": user_id}})
    
    # Add user to main class group
    main_group = await db.chats.find_one({"type": "main_group"}, {"_id": 0})
    if main_group:
        await db.chats.update_one({"id": main_group["id"]}, {"$addToSet": {"members": user_id}})
    
    config = await get_system_config()
    return {"success": True, "login_code": config["login_code"]}

@api_router.post("/auth/login")
async def login(request: LoginRequest):
    config = await get_system_config()
    
    if request.gate_code.strip().upper() != config["login_code"]:
        raise HTTPException(status_code=400, detail="Invalid gate code")
    
    user = await db.users.find_one({"username": request.username.lower()}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid username or password")
    if user.get("banned"):
        raise HTTPException(status_code=403, detail="Account banned. Contact admin")
    if not verify_password(request.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    # Update last seen
    await db.users.update_one({"id": user["id"]}, {"$set": {"last_seen": datetime.now(timezone.utc).isoformat()}})
    
    access_token = create_access_token({"user_id": user["id"], "username": user["username"]})
    refresh_token = create_refresh_token({"user_id": user["id"], "username": user["username"]})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"]
        }
    }

@api_router.post("/auth/refresh")
async def refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="No token provided")
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Invalid token type")
    
    user = await db.users.find_one({"id": payload.get("user_id")}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user.get("banned"):
        raise HTTPException(status_code=403, detail="Account banned")
    
    access_token = create_access_token({"user_id": user["id"], "username": user["username"]})
    return {"access_token": access_token}

@api_router.get("/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"]
    }

# ==================== CHAT ROUTES ====================

@api_router.get("/chats")
async def get_chats(user: dict = Depends(get_current_user)):
    """Get all chats for the current user"""
    chats = await db.chats.find(
        {"members": user["id"]},
        {"_id": 0}
    ).to_list(100)
    
    result = []
    for chat in chats:
        # Get last message
        last_msg = await db.messages.find_one(
            {"chat_id": chat["id"]},
            {"_id": 0},
            sort=[("created_at", -1)]
        )
        
        # Get unread count
        unread = await db.messages.count_documents({
            "chat_id": chat["id"],
            "sender_id": {"$ne": user["id"]},
            f"read_by.{user['id']}": {"$exists": False}
        })
        
        chat_data = {
            "id": chat["id"],
            "type": chat["type"],
            "name": chat.get("name", ""),
            "description": chat.get("description", ""),
            "members": chat["members"],
            "created_at": chat.get("created_at"),
            "last_message": None,
            "unread_count": unread
        }
        
        if last_msg:
            chat_data["last_message"] = {
                "content": decrypt_message(last_msg["encrypted"]) if last_msg.get("encrypted") else last_msg.get("content", ""),
                "sender_id": last_msg["sender_id"],
                "created_at": last_msg["created_at"]
            }
        
        # For DMs, get the other user's info
        if chat["type"] == "dm":
            other_id = [m for m in chat["members"] if m != user["id"]][0] if len(chat["members"]) > 1 else None
            if other_id:
                other_user = await db.users.find_one({"id": other_id}, {"_id": 0, "password_hash": 0})
                if other_user:
                    chat_data["other_user"] = {
                        "id": other_user["id"],
                        "username": other_user["username"],
                        "display_name": other_user["display_name"],
                        "online": other_user.get("online", False)
                    }
        
        result.append(chat_data)
    
    return result

@api_router.get("/chats/{chat_id}")
async def get_chat(chat_id: str, user: dict = Depends(get_current_user)):
    chat = await db.chats.find_one({"id": chat_id, "members": user["id"]}, {"_id": 0})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    return chat

@api_router.get("/chats/{chat_id}/messages")
async def get_messages(chat_id: str, limit: int = 50, before: str = None, user: dict = Depends(get_current_user)):
    chat = await db.chats.find_one({"id": chat_id, "members": user["id"]}, {"_id": 0})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    query = {"chat_id": chat_id, "deleted": {"$ne": True}}
    if before:
        query["created_at"] = {"$lt": before}
    
    messages = await db.messages.find(query, {"_id": 0}).sort("created_at", -1).limit(limit).to_list(limit)
    
    # Decrypt messages and mark as read
    result = []
    for msg in reversed(messages):
        content = decrypt_message(msg["encrypted"]) if msg.get("encrypted") else msg.get("content", "")
        sender = await db.users.find_one({"id": msg["sender_id"]}, {"_id": 0, "password_hash": 0})
        
        result.append({
            "id": msg["id"],
            "message_uuid": msg.get("message_uuid"),
            "chat_id": msg["chat_id"],
            "sender_id": msg["sender_id"],
            "sender_name": sender["display_name"] if sender else "Unknown",
            "sender_username": sender["username"] if sender else "unknown",
            "content": content,
            "attachment": msg.get("attachment"),
            "reply_to": msg.get("reply_to"),
            "created_at": msg["created_at"],
            "delivered": msg.get("delivered", False),
            "read_by": list(msg.get("read_by", {}).keys())
        })
        
        # Mark as read
        if msg["sender_id"] != user["id"]:
            await db.messages.update_one(
                {"id": msg["id"]},
                {"$set": {f"read_by.{user['id']}": datetime.now(timezone.utc).isoformat()}}
            )
    
    return result

@api_router.post("/chats/{chat_id}/messages")
async def send_message(chat_id: str, request: MessageCreateRequest, user: dict = Depends(get_current_user)):
    config = await get_system_config()
    
    if config.get("chat_frozen"):
        raise HTTPException(status_code=403, detail="Chat is currently frozen by admin")
    
    # Check rate limit
    if not check_rate_limit(user["id"]):
        cooldown = get_cooldown_remaining(user["id"])
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded. Try again in {cooldown} seconds")
    
    # Check slow mode
    if config.get("slow_mode_seconds", 0) > 0:
        last_msg = await db.messages.find_one(
            {"chat_id": chat_id, "sender_id": user["id"]},
            sort=[("created_at", -1)]
        )
        if last_msg:
            last_time = datetime.fromisoformat(last_msg["created_at"].replace("Z", "+00:00"))
            diff = (datetime.now(timezone.utc) - last_time).total_seconds()
            if diff < config["slow_mode_seconds"]:
                remaining = int(config["slow_mode_seconds"] - diff)
                raise HTTPException(status_code=429, detail=f"Slow mode active. Wait {remaining} seconds")
    
    chat = await db.chats.find_one({"id": chat_id, "members": user["id"]}, {"_id": 0})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    # Check for duplicate message UUID
    existing = await db.messages.find_one({"message_uuid": request.message_uuid})
    if existing:
        return {"id": existing["id"], "status": "duplicate"}
    
    # Check if user is shadow muted
    if user["id"] in chat.get("shadow_muted", []):
        # Pretend message was sent but don't actually save it
        return {"id": str(uuid.uuid4()), "status": "sent"}
    
    # Encrypt and save message
    encrypted = encrypt_message(request.content)
    message = {
        "id": str(uuid.uuid4()),
        "message_uuid": request.message_uuid,
        "chat_id": chat_id,
        "sender_id": user["id"],
        "encrypted": encrypted,
        "reply_to": request.reply_to,
        "attachment": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "delivered": True,
        "read_by": {},
        "deleted": False
    }
    await db.messages.insert_one(message)
    
    # Broadcast via Socket.IO
    sender = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0})
    broadcast_msg = {
        "id": message["id"],
        "message_uuid": message["message_uuid"],
        "chat_id": chat_id,
        "sender_id": user["id"],
        "sender_name": sender["display_name"],
        "sender_username": sender["username"],
        "content": request.content,
        "reply_to": request.reply_to,
        "created_at": message["created_at"]
    }
    await sio.emit("new_message", broadcast_msg, room=chat_id)
    
    return {"id": message["id"], "status": "sent"}

@api_router.delete("/messages/{message_id}")
async def delete_message(message_id: str, for_everyone: bool = False, user: dict = Depends(get_current_user)):
    message = await db.messages.find_one({"id": message_id}, {"_id": 0})
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    if message["sender_id"] != user["id"] and not for_everyone:
        raise HTTPException(status_code=403, detail="Cannot delete others' messages")
    
    if for_everyone and message["sender_id"] == user["id"]:
        await db.messages.update_one({"id": message_id}, {"$set": {"deleted": True, "encrypted": encrypt_message("[Message deleted]")}})
        await sio.emit("message_deleted", {"message_id": message_id, "chat_id": message["chat_id"]}, room=message["chat_id"])
    
    return {"success": True}

@api_router.post("/chats/{chat_id}/upload")
async def upload_attachment(
    chat_id: str,
    file: UploadFile = File(...),
    message_uuid: str = Form(...),
    user: dict = Depends(get_current_user)
):
    chat = await db.chats.find_one({"id": chat_id, "members": user["id"]}, {"_id": 0})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    # Validate file type
    allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
    if file.content_type not in allowed_types:
        raise HTTPException(status_code=400, detail="File type not allowed")
    
    # Save file
    file_id = str(uuid.uuid4())
    ext = file.filename.split('.')[-1] if '.' in file.filename else 'bin'
    filename = f"{file_id}.{ext}"
    filepath = UPLOAD_DIR / filename
    
    async with aiofiles.open(filepath, 'wb') as f:
        content = await file.read()
        await f.write(content)
    
    # Create message with attachment
    encrypted = encrypt_message(f"[Attachment: {file.filename}]")
    message = {
        "id": str(uuid.uuid4()),
        "message_uuid": message_uuid,
        "chat_id": chat_id,
        "sender_id": user["id"],
        "encrypted": encrypted,
        "attachment": {
            "id": file_id,
            "filename": file.filename,
            "content_type": file.content_type,
            "url": f"/api/uploads/{filename}"
        },
        "reply_to": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "delivered": True,
        "read_by": {},
        "deleted": False
    }
    await db.messages.insert_one(message)
    
    sender = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0})
    broadcast_msg = {
        "id": message["id"],
        "message_uuid": message["message_uuid"],
        "chat_id": chat_id,
        "sender_id": user["id"],
        "sender_name": sender["display_name"],
        "sender_username": sender["username"],
        "content": f"[Attachment: {file.filename}]",
        "attachment": message["attachment"],
        "created_at": message["created_at"]
    }
    await sio.emit("new_message", broadcast_msg, room=chat_id)
    
    return {"id": message["id"], "attachment": message["attachment"]}

# ==================== DM & GROUP ROUTES ====================

@api_router.get("/users")
async def get_users(user: dict = Depends(get_current_user)):
    """Get all registered users for starting DMs"""
    users = await db.users.find(
        {"id": {"$ne": user["id"]}, "banned": {"$ne": True}},
        {"_id": 0, "password_hash": 0}
    ).to_list(1000)
    return users

@api_router.post("/dm/{other_user_id}")
async def start_dm(other_user_id: str, user: dict = Depends(get_current_user)):
    """Start or get existing DM with another user"""
    other = await db.users.find_one({"id": other_user_id}, {"_id": 0})
    if not other:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if DM already exists
    members_sorted = sorted([user["id"], other_user_id])
    existing = await db.chats.find_one({
        "type": "dm",
        "members": {"$all": members_sorted}
    }, {"_id": 0})
    
    if existing:
        return {"chat_id": existing["id"], "existing": True}
    
    # Create new DM
    chat = {
        "id": str(uuid.uuid4()),
        "type": "dm",
        "members": members_sorted,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "shadow_muted": []
    }
    await db.chats.insert_one(chat)
    
    return {"chat_id": chat["id"], "existing": False}

@api_router.post("/groups")
async def create_group(request: GroupCreateRequest, user: dict = Depends(get_current_user)):
    """Create a new group chat"""
    if len(request.member_ids) < 1:
        raise HTTPException(status_code=400, detail="Group must have at least 1 other member")
    
    members = list(set([user["id"]] + request.member_ids))
    
    chat = {
        "id": str(uuid.uuid4()),
        "type": "group",
        "name": request.name,
        "description": request.description,
        "members": members,
        "admins": [user["id"]],
        "created_by": user["id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "shadow_muted": []
    }
    await db.chats.insert_one(chat)
    
    return {"chat_id": chat["id"]}

@api_router.patch("/groups/{chat_id}")
async def update_group(chat_id: str, request: GroupUpdateRequest, user: dict = Depends(get_current_user)):
    chat = await db.chats.find_one({"id": chat_id, "type": "group", "members": user["id"]}, {"_id": 0})
    if not chat:
        raise HTTPException(status_code=404, detail="Group not found")
    
    updates = {}
    if request.name:
        updates["name"] = request.name
    if request.description is not None:
        updates["description"] = request.description
    if request.add_members:
        updates["$addToSet"] = {"members": {"$each": request.add_members}}
    if request.remove_members:
        updates["$pull"] = {"members": {"$in": request.remove_members}}
    
    if updates:
        if "$addToSet" in updates or "$pull" in updates:
            if "$addToSet" in updates:
                await db.chats.update_one({"id": chat_id}, {"$addToSet": updates.pop("$addToSet")})
            if "$pull" in updates:
                await db.chats.update_one({"id": chat_id}, {"$pull": updates.pop("$pull")})
        if updates:
            await db.chats.update_one({"id": chat_id}, {"$set": updates})
    
    return {"success": True}

@api_router.get("/chats/{chat_id}/members")
async def get_chat_members(chat_id: str, user: dict = Depends(get_current_user)):
    chat = await db.chats.find_one({"id": chat_id, "members": user["id"]}, {"_id": 0})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat not found")
    
    members = await db.users.find(
        {"id": {"$in": chat["members"]}},
        {"_id": 0, "password_hash": 0}
    ).to_list(100)
    
    return members

# ==================== SEARCH ====================

@api_router.get("/search/messages")
async def search_messages(q: str, chat_id: str = None, user: dict = Depends(get_current_user)):
    """Search messages in user's chats"""
    # Get user's chat IDs
    if chat_id:
        chat = await db.chats.find_one({"id": chat_id, "members": user["id"]}, {"_id": 0})
        if not chat:
            raise HTTPException(status_code=404, detail="Chat not found")
        chat_ids = [chat_id]
    else:
        chats = await db.chats.find({"members": user["id"]}, {"_id": 0, "id": 1}).to_list(100)
        chat_ids = [c["id"] for c in chats]
    
    # Search in messages (decrypt and filter)
    messages = await db.messages.find(
        {"chat_id": {"$in": chat_ids}, "deleted": {"$ne": True}},
        {"_id": 0}
    ).sort("created_at", -1).limit(200).to_list(200)
    
    results = []
    for msg in messages:
        content = decrypt_message(msg["encrypted"]) if msg.get("encrypted") else msg.get("content", "")
        if q.lower() in content.lower():
            sender = await db.users.find_one({"id": msg["sender_id"]}, {"_id": 0, "password_hash": 0})
            results.append({
                "id": msg["id"],
                "chat_id": msg["chat_id"],
                "sender_name": sender["display_name"] if sender else "Unknown",
                "content": content,
                "created_at": msg["created_at"]
            })
            if len(results) >= 20:
                break
    
    return results

# ==================== ADMIN ROUTES ====================

@api_router.post("/admin/login")
async def admin_login(request: AdminLoginRequest):
    admin = await db.admins.find_one({"username": request.username}, {"_id": 0})
    if not admin or not verify_password(request.password, admin.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    access_token = create_access_token({"admin_id": admin["id"], "is_admin": True})
    refresh_token = create_refresh_token({"admin_id": admin["id"], "is_admin": True})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "admin": {"id": admin["id"], "username": admin["username"]}
    }

@api_router.get("/admin/students")
async def admin_get_students(admin: dict = Depends(get_admin_user)):
    students = await db.students.find({}, {"_id": 0, "password_hash": 0}).to_list(1000)
    return students

@api_router.post("/admin/students")
async def admin_create_student(request: StudentCreateRequest, admin: dict = Depends(get_admin_user)):
    student = {
        "id": str(uuid.uuid4()),
        "full_name": request.full_name,
        "password_hash": hash_password(request.first_time_password),
        "registered": False,
        "locked": False,
        "user_id": None,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.students.insert_one(student)
    await log_audit(admin["id"], "create_student", "student", student["id"], {"full_name": request.full_name})
    return {"id": student["id"]}

@api_router.patch("/admin/students/{student_id}")
async def admin_update_student(student_id: str, request: StudentUpdateRequest, admin: dict = Depends(get_admin_user)):
    updates = {}
    if request.full_name:
        updates["full_name"] = request.full_name
    if updates:
        await db.students.update_one({"id": student_id}, {"$set": updates})
        await log_audit(admin["id"], "update_student", "student", student_id, updates)
    return {"success": True}

@api_router.delete("/admin/students/{student_id}")
async def admin_delete_student(student_id: str, admin: dict = Depends(get_admin_user)):
    student = await db.students.find_one({"id": student_id}, {"_id": 0})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    
    # Also delete user if exists
    if student.get("user_id"):
        await db.users.delete_one({"id": student["user_id"]})
    
    await db.students.delete_one({"id": student_id})
    await log_audit(admin["id"], "delete_student", "student", student_id, {"full_name": student.get("full_name")})
    return {"success": True}

@api_router.post("/admin/students/{student_id}/reset")
async def admin_reset_student(student_id: str, new_password: str = None, admin: dict = Depends(get_admin_user)):
    """Reset student registration - allows them to re-register"""
    student = await db.students.find_one({"id": student_id}, {"_id": 0})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    
    # Delete user if exists
    if student.get("user_id"):
        # Remove from all chats
        await db.chats.update_many({}, {"$pull": {"members": student["user_id"]}})
        await db.users.delete_one({"id": student["user_id"]})
    
    updates = {"registered": False, "locked": False, "user_id": None}
    if new_password:
        updates["password_hash"] = hash_password(new_password)
    
    await db.students.update_one({"id": student_id}, {"$set": updates})
    await log_audit(admin["id"], "reset_student", "student", student_id)
    return {"success": True}

@api_router.post("/admin/students/{student_id}/unlock")
async def admin_unlock_student(student_id: str, admin: dict = Depends(get_admin_user)):
    await db.students.update_one({"id": student_id}, {"$set": {"locked": False}})
    # Also clear password attempts
    attempt_key = f"pwd_{student_id}"
    password_attempts[attempt_key] = {'count': 0, 'locked_until': 0}
    await log_audit(admin["id"], "unlock_student", "student", student_id)
    return {"success": True}

@api_router.post("/admin/students/{student_id}/ban")
async def admin_ban_student(student_id: str, admin: dict = Depends(get_admin_user)):
    student = await db.students.find_one({"id": student_id}, {"_id": 0})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    if student.get("user_id"):
        await db.users.update_one({"id": student["user_id"]}, {"$set": {"banned": True}})
    await log_audit(admin["id"], "ban_student", "student", student_id)
    return {"success": True}

@api_router.post("/admin/students/{student_id}/unban")
async def admin_unban_student(student_id: str, admin: dict = Depends(get_admin_user)):
    student = await db.students.find_one({"id": student_id}, {"_id": 0})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    if student.get("user_id"):
        await db.users.update_one({"id": student["user_id"]}, {"$set": {"banned": False}})
    await log_audit(admin["id"], "unban_student", "student", student_id)
    return {"success": True}

@api_router.get("/admin/config")
async def admin_get_config(admin: dict = Depends(get_admin_user)):
    return await get_system_config()

@api_router.patch("/admin/config")
async def admin_update_config(request: CodeUpdateRequest, admin: dict = Depends(get_admin_user)):
    updates = {}
    if request.first_time_code:
        updates["first_time_code"] = request.first_time_code.upper()
    if request.login_code:
        updates["login_code"] = request.login_code.upper()
    
    if updates:
        await db.system_config.update_one({"id": "main"}, {"$set": updates})
        await log_audit(admin["id"], "update_config", "system", "main", updates)
    return {"success": True}

@api_router.post("/admin/force-logout-all")
async def admin_force_logout_all(admin: dict = Depends(get_admin_user)):
    """Force logout all students by invalidating their sessions"""
    await db.users.update_many({}, {"$set": {"online": False}})
    await sio.emit("force_logout", {})
    await log_audit(admin["id"], "force_logout_all", "system", "all")
    return {"success": True}

@api_router.get("/admin/chats")
async def admin_get_all_chats(admin: dict = Depends(get_admin_user)):
    """Get all chats for admin surveillance"""
    chats = await db.chats.find({}, {"_id": 0}).to_list(1000)
    result = []
    for chat in chats:
        # Get member info
        members = await db.users.find(
            {"id": {"$in": chat["members"]}},
            {"_id": 0, "id": 1, "display_name": 1, "username": 1}
        ).to_list(100)
        
        chat_data = {**chat, "member_details": members}
        result.append(chat_data)
    return result

@api_router.get("/admin/chats/{chat_id}/messages")
async def admin_get_chat_messages(chat_id: str, limit: int = 100, admin: dict = Depends(get_admin_user)):
    """Admin can view any chat messages decrypted"""
    messages = await db.messages.find(
        {"chat_id": chat_id},
        {"_id": 0}
    ).sort("created_at", -1).limit(limit).to_list(limit)
    
    result = []
    for msg in reversed(messages):
        content = decrypt_message(msg["encrypted"]) if msg.get("encrypted") else msg.get("content", "")
        sender = await db.users.find_one({"id": msg["sender_id"]}, {"_id": 0, "password_hash": 0})
        result.append({
            "id": msg["id"],
            "sender_id": msg["sender_id"],
            "sender_name": sender["display_name"] if sender else "Unknown",
            "content": content,
            "attachment": msg.get("attachment"),
            "created_at": msg["created_at"],
            "deleted": msg.get("deleted", False)
        })
    return result

@api_router.delete("/admin/messages/{message_id}")
async def admin_delete_message(message_id: str, admin: dict = Depends(get_admin_user)):
    message = await db.messages.find_one({"id": message_id}, {"_id": 0})
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    await db.messages.update_one({"id": message_id}, {"$set": {"deleted": True, "encrypted": encrypt_message("[Deleted by admin]")}})
    await sio.emit("message_deleted", {"message_id": message_id, "chat_id": message["chat_id"]}, room=message["chat_id"])
    await log_audit(admin["id"], "delete_message", "message", message_id, {"chat_id": message["chat_id"]})
    return {"success": True}

@api_router.post("/admin/chats/{chat_id}/freeze")
async def admin_freeze_chat(chat_id: str, frozen: bool = True, admin: dict = Depends(get_admin_user)):
    if chat_id == "global":
        await db.system_config.update_one({"id": "main"}, {"$set": {"chat_frozen": frozen}})
    else:
        await db.chats.update_one({"id": chat_id}, {"$set": {"frozen": frozen}})
    await log_audit(admin["id"], "freeze_chat" if frozen else "unfreeze_chat", "chat", chat_id)
    return {"success": True}

@api_router.post("/admin/chats/{chat_id}/slow-mode")
async def admin_set_slow_mode(chat_id: str, seconds: int = 0, admin: dict = Depends(get_admin_user)):
    if chat_id == "global":
        await db.system_config.update_one({"id": "main"}, {"$set": {"slow_mode_seconds": seconds}})
    await log_audit(admin["id"], "set_slow_mode", "chat", chat_id, {"seconds": seconds})
    return {"success": True}

@api_router.post("/admin/chats/{chat_id}/shadow-mute/{user_id}")
async def admin_shadow_mute(chat_id: str, user_id: str, mute: bool = True, admin: dict = Depends(get_admin_user)):
    if mute:
        await db.chats.update_one({"id": chat_id}, {"$addToSet": {"shadow_muted": user_id}})
    else:
        await db.chats.update_one({"id": chat_id}, {"$pull": {"shadow_muted": user_id}})
    await log_audit(admin["id"], "shadow_mute" if mute else "shadow_unmute", "user", user_id, {"chat_id": chat_id})
    return {"success": True}

@api_router.get("/admin/search/messages")
async def admin_search_messages(q: str, admin: dict = Depends(get_admin_user)):
    """Admin global message search"""
    messages = await db.messages.find(
        {"deleted": {"$ne": True}},
        {"_id": 0}
    ).sort("created_at", -1).limit(500).to_list(500)
    
    results = []
    for msg in messages:
        content = decrypt_message(msg["encrypted"]) if msg.get("encrypted") else msg.get("content", "")
        if q.lower() in content.lower():
            sender = await db.users.find_one({"id": msg["sender_id"]}, {"_id": 0, "password_hash": 0})
            chat = await db.chats.find_one({"id": msg["chat_id"]}, {"_id": 0})
            results.append({
                "id": msg["id"],
                "chat_id": msg["chat_id"],
                "chat_name": chat.get("name", "DM") if chat else "Unknown",
                "sender_name": sender["display_name"] if sender else "Unknown",
                "content": content,
                "created_at": msg["created_at"]
            })
            if len(results) >= 50:
                break
    return results

@api_router.get("/admin/audit-logs")
async def admin_get_audit_logs(limit: int = 100, admin: dict = Depends(get_admin_user)):
    logs = await db.audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit).to_list(limit)
    return logs

# ==================== SOCKET.IO EVENTS ====================

@sio.event
async def connect(sid, environ, auth):
    logger.info(f"Socket connected: {sid}")
    if auth and auth.get("token"):
        try:
            payload = decode_token(auth["token"])
            user_id = payload.get("user_id")
            if user_id:
                await sio.save_session(sid, {"user_id": user_id})
                await db.users.update_one({"id": user_id}, {"$set": {"online": True}})
                # Join all user's chat rooms
                chats = await db.chats.find({"members": user_id}, {"_id": 0, "id": 1}).to_list(100)
                for chat in chats:
                    sio.enter_room(sid, chat["id"])
                # Broadcast online status
                await sio.emit("user_online", {"user_id": user_id})
        except Exception as e:
            logger.error(f"Socket auth error: {e}")

@sio.event
async def disconnect(sid):
    logger.info(f"Socket disconnected: {sid}")
    session = await sio.get_session(sid)
    if session and session.get("user_id"):
        user_id = session["user_id"]
        await db.users.update_one({"id": user_id}, {"$set": {"online": False, "last_seen": datetime.now(timezone.utc).isoformat()}})
        await sio.emit("user_offline", {"user_id": user_id})

@sio.event
async def join_chat(sid, data):
    chat_id = data.get("chat_id")
    if chat_id:
        sio.enter_room(sid, chat_id)
        logger.info(f"Socket {sid} joined chat {chat_id}")

@sio.event
async def leave_chat(sid, data):
    chat_id = data.get("chat_id")
    if chat_id:
        sio.leave_room(sid, chat_id)

@sio.event
async def typing(sid, data):
    session = await sio.get_session(sid)
    if session and session.get("user_id"):
        chat_id = data.get("chat_id")
        user = await db.users.find_one({"id": session["user_id"]}, {"_id": 0, "password_hash": 0})
        if user and chat_id:
            await sio.emit("user_typing", {
                "chat_id": chat_id,
                "user_id": user["id"],
                "display_name": user["display_name"]
            }, room=chat_id, skip_sid=sid)

@sio.event
async def stop_typing(sid, data):
    session = await sio.get_session(sid)
    if session and session.get("user_id"):
        chat_id = data.get("chat_id")
        await sio.emit("user_stop_typing", {
            "chat_id": chat_id,
            "user_id": session["user_id"]
        }, room=chat_id, skip_sid=sid)

@sio.event
async def message_read(sid, data):
    session = await sio.get_session(sid)
    if session and session.get("user_id"):
        message_id = data.get("message_id")
        chat_id = data.get("chat_id")
        user_id = session["user_id"]
        
        await db.messages.update_one(
            {"id": message_id},
            {"$set": {f"read_by.{user_id}": datetime.now(timezone.utc).isoformat()}}
        )
        await sio.emit("message_read_update", {
            "message_id": message_id,
            "chat_id": chat_id,
            "user_id": user_id
        }, room=chat_id)

# ==================== STARTUP ====================

@app.on_event("startup")
async def startup():
    # Create indexes
    await db.users.create_index("username", unique=True)
    await db.users.create_index("id", unique=True)
    await db.students.create_index("id", unique=True)
    await db.messages.create_index("chat_id")
    await db.messages.create_index("message_uuid", unique=True)
    await db.chats.create_index("id", unique=True)
    await db.admins.create_index("username", unique=True)
    
    # Create default admin if not exists
    admin = await db.admins.find_one({"username": "admin"})
    if not admin:
        await db.admins.insert_one({
            "id": str(uuid.uuid4()),
            "username": "admin",
            "password_hash": hash_password("Admin@123"),
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        logger.info("Created default admin: admin / Admin@123")
    
    # Create system config if not exists
    await get_system_config()
    
    # Create main class group if not exists
    main_group = await db.chats.find_one({"type": "main_group"})
    if not main_group:
        await db.chats.insert_one({
            "id": str(uuid.uuid4()),
            "type": "main_group",
            "name": "Class Group",
            "description": "Main class chat for everyone",
            "members": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "shadow_muted": []
        })
        logger.info("Created main class group")
    
    # Seed sample students
    student_count = await db.students.count_documents({})
    if student_count == 0:
        sample_students = [
            {"full_name": "Alice Johnson", "password": "alice123"},
            {"full_name": "Bob Smith", "password": "bob123"},
            {"full_name": "Charlie Brown", "password": "charlie123"},
            {"full_name": "Diana Ross", "password": "diana123"},
            {"full_name": "Edward King", "password": "edward123"},
            {"full_name": "Fiona Green", "password": "fiona123"},
            {"full_name": "George White", "password": "george123"},
            {"full_name": "Hannah Lee", "password": "hannah123"},
        ]
        for s in sample_students:
            await db.students.insert_one({
                "id": str(uuid.uuid4()),
                "full_name": s["full_name"],
                "password_hash": hash_password(s["password"]),
                "registered": False,
                "locked": False,
                "user_id": None,
                "created_at": datetime.now(timezone.utc).isoformat()
            })
        logger.info(f"Seeded {len(sample_students)} sample students")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Include the router
app.include_router(api_router)

# Mount uploads
app.mount("/api/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create ASGI app with Socket.IO
socket_app = socketio.ASGIApp(sio, app)

# For uvicorn to use
application = socket_app
