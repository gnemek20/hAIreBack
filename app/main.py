from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import os
import asyncpg
import json

from passlib.hash import argon2
from jose import JWTError, jwt
from datetime import datetime, timedelta


app = FastAPI()
security = HTTPBearer()

app.add_middleware(
  CORSMiddleware,
  allow_origins=["*"],
  allow_methods=["*"],
  allow_headers=["*"],
  allow_credentials=True
)

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60


# =========================================================
# Common Utilities
# =========================================================

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


async def get_user_id_from_body(body: dict) -> str:
  token = body.get("access_token")
  if not token:
    raise HTTPException(status_code=401, detail="Access token required")
  return decode_token(token)


# =========================================================
# Lifecycle
# =========================================================

@app.on_event("startup")
async def startup():
  try:
    app.state.db = await asyncpg.create_pool(DATABASE_URL)
    print("Success connecting with DB")
  except Exception as e:
    print(f"DATABASE_URL is [ {DATABASE_URL} ]")
    print(f"Failed connecting with DB: [ {e} ]")


@app.on_event("shutdown")
async def shutdown():
  if getattr(app.state, "db", None):
    await app.state.db.close()
    print("Close DB")


@app.get("/healthcheck")
async def healthcheck():
  return {"status": "ok"}


# =========================================================
# Auth
# =========================================================

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
async def list_subscriptions(request: Request):
  db = get_db()
  body = await request.json()
  user_id = await get_user_id_from_body(body)

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
async def update_subscriptions(request: Request):
  db = get_db()
  body = await request.json()
  user_id = await get_user_id_from_body(body)

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
async def delete_subscription(request: Request):
  db = get_db()
  body = await request.json()
  user_id = await get_user_id_from_body(body)

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

@app.post("/users/agents/list")
async def list_agents(request: Request):
  db = get_db()
  body = await request.json()
  user_id = await get_user_id_from_body(body)

  async with db.acquire() as conn:
    rows = await conn.fetch(
      """
      SELECT agent
      FROM user_agent
      WHERE user_id = $1
      """,
      user_id
    )

  agents = [
    json.loads(row["agent"]) if isinstance(row["agent"], str)
    else row["agent"]
    for row in rows
  ]

  return {"status": "success", "agents": agents}


@app.post("/users/agents")
async def add_agent(request: Request):
  db = get_db()
  body = await request.json()
  user_id = await get_user_id_from_body(body)

  agent = body.get("agent")
  if not agent:
    raise HTTPException(status_code=400, detail="agent JSON is required")

  async with db.acquire() as conn:
    async with conn.transaction():
      row = await conn.fetchrow(
        """
        INSERT INTO user_agent (user_id, agent)
        VALUES ($1, $2::jsonb)
        ON CONFLICT (user_id, agent) DO NOTHING
        RETURNING id
        """,
        user_id,
        json.dumps(agent)
      )

  return {
    "status": "success",
    "inserted": bool(row),
    "agent_id": row["id"] if row else None
  }


@app.delete("/users/agents")
async def delete_agent(request: Request):
  db = get_db()
  body = await request.json()
  user_id = await get_user_id_from_body(body)

  agent = body.get("agent")
  if agent is None:
    raise HTTPException(status_code=400, detail="agent JSON is required")

  async with db.acquire() as conn:
    async with conn.transaction():
      result = await conn.execute(
        """
        DELETE FROM user_agent
        WHERE user_id = $1 AND agent = $2::jsonb
        """,
        user_id,
        json.dumps(agent)
      )

      deleted_count = int(result.split(" ")[1])
      if deleted_count == 0:
        raise HTTPException(status_code=404, detail="Agent not found")

  return {"status": "success", "deleted": True, "deleted_count": deleted_count}


# =========================================================
# Chat
# =========================================================

@app.post("/users/chat/history")
async def get_chat_history(request: Request):
  db = get_db()
  body = await request.json()
  user_id = await get_user_id_from_body(body)

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

  chat_history = [
    {
      "id": str(row["id"]),
      "slug": row["slug"],
      "sender": row["sender"],
      "content": row["content"],
      "raw_content": row["raw_content"],
      "status": row["status"],
      "timestamp": int(row["timestamp"])
    }
    for row in rows
  ]

  return {"status": "success", "chat_history": chat_history}


@app.post("/users/chat/save")
async def save_chat_history(request: Request):
  db = get_db()
  body = await request.json()
  user_id = await get_user_id_from_body(body)

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

        await conn.execute(
          """
          INSERT INTO chat_messages
          (id, user_id, slug, sender, content, raw_content, status, created_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8 / 1000.0))
          ON CONFLICT (id) DO NOTHING
          """,
          msg["id"],
          user_id,
          slug,
          msg["sender"],
          msg.get("content"),
          msg.get("raw_content"),
          msg.get("status"),
          msg["timestamp"]
        )

  return {"status": "success", "saved": len(chat_history)}