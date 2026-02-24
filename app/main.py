from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse

import os
import asyncio
import asyncpg
import json

from passlib.hash import argon2
from jose import JWTError, jwt
from datetime import datetime, timedelta


app = FastAPI()
security = HTTPBearer()

# ── CORS: 개발 단계에서 모든 origin 허용 ──
# allow_credentials=True 일 때 allow_origins=["*"] 는 CORS 스펙 위반이므로
# credentials=False로 설정. Bearer 토큰은 allow_headers로 허용.
CORS_ORIGINS = ["*"]

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60


# =========================================================
# Common Utilities
# =========================================================

_pool_lock = asyncio.Lock()

async def _ensure_pool():
  """Create the asyncpg pool if it doesn't exist yet (lazy init / reconnect)."""
  if getattr(app.state, "db", None) is not None:
    return app.state.db
  async with _pool_lock:
    # Double-check after acquiring lock
    if getattr(app.state, "db", None) is not None:
      return app.state.db
    if not DATABASE_URL:
      raise HTTPException(status_code=500, detail="DATABASE_URL is not configured")
    try:
      app.state.db = await asyncpg.create_pool(
        DATABASE_URL, min_size=0, max_size=1,
        max_inactive_connection_lifetime=30,  # 30초 후 유휴 연결 해제
        command_timeout=15,
      )
      print("DB pool (re)created successfully")
    except Exception as e:
      print(f"DB pool creation failed: {e}")
      raise HTTPException(status_code=500, detail="Cannot connect with DB")
  return app.state.db


def get_db():
  db = getattr(app.state, "db", None)
  if db is None:
    raise HTTPException(status_code=500, detail="Cannot connect with DB")
  return db


def hash_password(password: str) -> str:
  return argon2.hash(password)


def verify_password(password: str, hashed: str) -> bool:
  return argon2.verify(password, hashed)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
  to_encode = data.copy()
  expire = datetime.utcnow() + (
    expires_delta if expires_delta else timedelta(minutes=15)
  )
  to_encode.update({"exp": expire})
  return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)


def decode_token(token: str) -> str:
  try:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    user_id = payload.get("sub")
    if not user_id:
      raise HTTPException(status_code=401, detail="Invalid token")
    return user_id
  except JWTError:
    raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(
  credentials: HTTPAuthorizationCredentials = Depends(security)
):
  return decode_token(credentials.credentials)


# =========================================================
# Lifecycle
# =========================================================

@app.on_event("startup")
async def startup():
  try:
    app.state.db = await asyncpg.create_pool(
      DATABASE_URL, min_size=0, max_size=1,
      max_inactive_connection_lifetime=30,  # 30초 후 유휴 연결 해제
      command_timeout=15,
    )
    print("Success connecting with DB")
  except Exception as e:
    print(f"DATABASE_URL is [ {DATABASE_URL} ]")
    print(f"Failed connecting with DB: [ {e} ]")
    # Pool will be retried lazily via _ensure_pool() on first request
    app.state.db = None


@app.on_event("shutdown")
async def shutdown():
  if getattr(app.state, "db", None):
    await app.state.db.close()
    print("Close DB")


@app.middleware("http")
async def ensure_db_middleware(request: Request, call_next):
  # Handle CORS preflight immediately
  if request.method == "OPTIONS":
    return await call_next(request)
  # Skip DB pool check for endpoints that don't need DB
  if request.url.path in ("/healthcheck", "/guest-token"):
    return await call_next(request)
  try:
    await _ensure_pool()
  except HTTPException as exc:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
  try:
    return await call_next(request)
  except Exception as exc:
    import traceback
    traceback.print_exc()
    return JSONResponse(status_code=500, content={"detail": str(exc) or "Internal server error"})


# CORSMiddleware must be added AFTER @app.middleware so it becomes
# the outermost layer and adds CORS headers to ALL responses.
app.add_middleware(
  CORSMiddleware,
  allow_origins=CORS_ORIGINS,
  allow_methods=["*"],
  allow_headers=["*"],
  allow_credentials=False
)


@app.get("/healthcheck")
async def healthcheck():
  return {"status": "ok"}


# =========================================================
# Auth
# =========================================================

@app.get("/guest-token")
async def guest_token():
  """비로그인 사용자가 Agent Server 공개 API(목록·검색 등)를 사용할 수 있도록
  1시간짜리 게스트 JWT를 발급합니다."""
  token = create_access_token(
    data={"sub": "guest"},
    expires_delta=timedelta(hours=1)
  )
  return {"access_token": token}


@app.post("/signup")
async def sign_up(request: Request):
  db = get_db()
  body = await request.json()

  user_id = body.get("id")
  pwd = body.get("pwd")
  username = body.get("username")

  if not all([user_id, pwd, username]):
    raise HTTPException(status_code=400, detail="id, pwd, username are required")

  async with db.acquire() as conn:
    async with conn.transaction():
      try:
        await conn.execute(
          """
          INSERT INTO "user" (id, username, pwd)
          VALUES ($1, $2, $3)
          """,
          user_id,
          username,
          hash_password(pwd)
        )
      except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {e}")

  return {"status": "success", "message": "User created"}


@app.post("/signin")
async def sign_in(request: Request):
  db = get_db()
  body = await request.json()

  user_id = body.get("id")
  pwd = body.get("pwd")

  async with db.acquire() as conn:
    row = await conn.fetchrow(
      'SELECT username, pwd FROM "user" WHERE id=$1',
      user_id
    )

  if row is None:
    raise HTTPException(status_code=401, detail="User not found")

  if not verify_password(pwd, row["pwd"]):
    raise HTTPException(status_code=401, detail="Incorrect password")

  access_token = create_access_token(
    data={"sub": user_id},
    expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
  )

  return {
    "status": "success",
    "username": row["username"],
    "access_token": access_token,
    "token_type": "bearer"
  }


# =========================================================
# Subscriptions
# =========================================================

@app.post("/users/subscriptions/list")
async def list_subscriptions(user_id: str = Depends(get_current_user)):
  db = get_db()

  async with db.acquire() as conn:
    rows = await conn.fetch(
      """
      SELECT slug
      FROM user_subscription
      WHERE user_id = $1
      """,
      user_id
    )

  return {
    "status": "success",
    "subscriptions": [row["slug"] for row in rows]
  }


@app.post("/users/subscriptions")
async def update_subscriptions(request: Request, user_id: str = Depends(get_current_user)):
  db = get_db()
  body = await request.json()

  subscriptions = body.get("subscriptions")
  if not subscriptions or not isinstance(subscriptions, list):
    raise HTTPException(status_code=400, detail="subscriptions must be a list")

  async with db.acquire() as conn:
    user = await conn.fetchrow(
      'SELECT id FROM "user" WHERE id = $1',
      user_id
    )

    if not user:
      raise HTTPException(status_code=404, detail="User not found")

    inserted_count = 0
    async with conn.transaction():
      for slug in subscriptions:
        row = await conn.fetchrow(
          """
          INSERT INTO user_subscription (user_id, slug)
          VALUES ($1, $2)
          ON CONFLICT (user_id, slug) DO NOTHING
          RETURNING id
          """,
          user_id,
          slug
        )
        if row:
          inserted_count += 1

  return {"status": "success", "inserted_rows": inserted_count}


@app.delete("/users/subscriptions")
async def delete_subscription(request: Request, user_id: str = Depends(get_current_user)):
  db = get_db()
  body = await request.json()

  slug = body.get("slug")
  if not slug:
    raise HTTPException(status_code=400, detail="slug required")

  async with db.acquire() as conn:
    async with conn.transaction():
      result = await conn.execute(
        """
        DELETE FROM user_subscription
        WHERE user_id = $1 AND slug = $2
        """,
        user_id,
        slug
      )

      deleted_sub_count = int(result.split(" ")[1])
      if deleted_sub_count == 0:
        raise HTTPException(status_code=404, detail="Subscription not found")

      result = await conn.execute(
        """
        DELETE FROM chat_messages
        WHERE user_id = $1 AND slug = $2
        """,
        user_id,
        slug
      )

      deleted_chat_count = int(result.split(" ")[1])

  return {
    "status": "success",
    "deleted_subscriptions": deleted_sub_count,
    "deleted_chat_messages": deleted_chat_count
  }


# =========================================================
# Agents
# =========================================================

@app.post("/users/agents")
async def list_agents(user_id: str = Depends(get_current_user)):
  db = get_db()

  async with db.acquire() as conn:
    rows = await conn.fetch(
      """
      SELECT slug, name, description, version, price, icon
      FROM agents
      WHERE user_id = $1
      ORDER BY created_at DESC
      """,
      user_id
    )

  agents = [dict(row) for row in rows]

  return {"status": "success", "agents": agents}


# =========================================================
# Chat
# =========================================================

@app.post("/users/chat/history")
async def get_chat_history(request: Request, user_id: str = Depends(get_current_user)):
  db = get_db()
  body = await request.json()

  slug = body.get("slug")
  if not slug:
    raise HTTPException(status_code=400, detail="Slug is required")

  async with db.acquire() as conn:
    rows = await conn.fetch(
      """
      SELECT id, slug, sender, content, raw_content, status,
             EXTRACT(EPOCH FROM created_at) * 1000 AS timestamp
      FROM chat_messages
      WHERE user_id = $1 AND slug = $2
      ORDER BY created_at ASC
      """,
      user_id,
      slug
    )

  def _parse_json_field(val):
    """json 타입 컬럼은 asyncpg가 raw string 반환 → 역직렬화 필요."""
    if val is None:
      return None
    try:
      return json.loads(val)
    except (json.JSONDecodeError, TypeError):
      return val

  chat_history = [
    {
      "id": str(row["id"]),
      "slug": row["slug"],
      "sender": row["sender"],
      "content": _parse_json_field(row["content"]),
      "raw_content": _parse_json_field(row["raw_content"]),
      "status": row["status"],
      "timestamp": int(row["timestamp"])
    }
    for row in rows
  ]

  return {"status": "success", "chat_history": chat_history}


@app.post("/users/chat/save")
async def save_chat_history(request: Request, user_id: str = Depends(get_current_user)):
  db = get_db()
  body = await request.json()

  slug = body.get("slug")
  chat_history = body.get("chat_history")

  if not slug:
    raise HTTPException(status_code=400, detail="Slug is required")
  if not chat_history or not isinstance(chat_history, list):
    raise HTTPException(status_code=400, detail="Chat History must be a list")

  async with db.acquire() as conn:
    async with conn.transaction():
      for msg in chat_history:
        if not all(k in msg for k in ("id", "sender", "content", "timestamp")):
          continue

        content = msg.get("content")
        raw_content = msg.get("raw_content")

        await conn.execute(
          """
          INSERT INTO chat_messages
          (id, user_id, slug, sender, content, raw_content, status, created_at)
          VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, to_timestamp($8 / 1000.0))
          ON CONFLICT (id) DO NOTHING
          """,
          msg["id"],
          user_id,
          slug,
          msg["sender"],
          json.dumps(content) if content is not None else None,
          json.dumps(raw_content) if raw_content is not None else None,
          msg.get("status"),
          msg["timestamp"]
        )

  return {"status": "success", "saved": len(chat_history)}