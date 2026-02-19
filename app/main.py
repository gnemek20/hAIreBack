from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import os
import requests
import asyncpg

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
ACCESS_TOKEN_EXPIRE_MINUTES = 6 * 60

OAUTH_ID = os.getenv("OAUTH_ID")
OAUTH_SECRET = os.getenv("OAUTH_SECRET")

def hash_password(password: str) -> str:
  return argon2.hash(password)

def verify_password(password: str, hashed: str) -> bool:
  return argon2.verify(password, hashed)

def create_access_token(
  data: dict,
  expires_delta: timedelta | None = None
):
  to_encode = data.copy()
  if expires_delta:
    expire = datetime.utcnow() + expires_delta
  else:
    expire = datetime.utcnow() + timedelta(minutes=15)
  to_encode.update({"exp": expire})
  encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)
  return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
  token = credentials.credentials
  try:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    user_id = payload.get("sub")
    if user_id is None:
      raise HTTPException(status_code=401, detail="Invalid token")
    return user_id
  except JWTError:
    raise HTTPException(status_code=401, detail="Invalid token")

@app.on_event("startup")
async def startup():
  try:
    app.state.db = await asyncpg.create_pool(DATABASE_URL)
    print("Success connecting with DB")
  except Exception as e:
    print(f"DATABASE_URL is [ {DATABASE_URL} ]")
    print(f"Failed connectiong with DB: [ {e} ]",)

@app.on_event("shutdown")
async def shutdown():
  if getattr(app.state, "db", None):
    await app.state.db.close()
    print("Close DB")

@app.get("/healthcheck")
async def healthcheck():
  print("health check")
  return { "status": "ok" }

@app.post("/signup")
async def sign_up(request: Request):
  if not hasattr(app.state, "db") or app.state.db is None:
    raise HTTPException(status_code=500, detail="Cannot connect with DB")

  body = await request.json()
  
  id = body.get("id")
  pwd = body.get("pwd")
  username = body.get("username")

  if not all([id, pwd, username]):
    raise HTTPException(status_code=400, detail="id, pwd, username are required")

  hashed_pwd = hash_password(pwd)

  async with app.state.db.acquire() as conn:
    async with conn.transaction():
      try:
        await conn.execute(
          """
          INSERT INTO "user" (id, username, pwd)
          VALUES ($1, $2, $3)
          """,
          id, username, hashed_pwd
        )
      except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {e}")
  
  print(f"User created: {username}")
  return {"status": "success", "message": "User created"}

@app.post("/signin")
async def sign_in(request: Request):
  if not hasattr(app.state, "db") or app.state.db is None:
    raise HTTPException(status_code=500, detail="Cannot connect with DB")

  body = await request.json()

  id = body.get("id")
  pwd = body.get("pwd")

  async with app.state.db.acquire() as conn:
    row = await conn.fetchrow(
      'SELECT username, pwd FROM "user" WHERE id=$1',
      id
    )

    if row is None:
      raise HTTPException(status_code=401, detail="User not found")

    username = row["username"]
    hashed_pwd = row["pwd"]
    if not verify_password(pwd, hashed_pwd):
      raise HTTPException(status_code=401, detail="Incorrect password")

  access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
  access_token = create_access_token(
    data={"sub": id},
    expires_delta=access_token_expires
  )

  return {"status": "success", "username": username, "access_token": access_token, "token_type": "bearer"}

@app.post("/users/subscriptions/list")
async def list_subscriptions(request: Request):
  if not hasattr(app.state, "db") or app.state.db is None:
    raise HTTPException(status_code=500, detail="Cannot connect with DB")

  body = await request.json()
  token = body.get("access_token")

  if not token:
    raise HTTPException(status_code=401, detail="Token required")

  try:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    user_id = payload.get("sub")
    if user_id is None:
      raise HTTPException(status_code=401, detail="Invalid token")
  except JWTError:
    raise HTTPException(status_code=401, detail="Invalid token")

  async with app.state.db.acquire() as conn:
    rows = await conn.fetch(
      """
      SELECT slug
      FROM user_subscription
      WHERE user_id = $1
      """,
      user_id
    )

  subscriptions = [row["slug"] for row in rows]

  return {
    "status": "success",
    "subscriptions": subscriptions
  }

@app.post("/users/subscriptions")
async def update_subscriptions(request: Request):
  if not hasattr(app.state, "db") or app.state.db is None:
    raise HTTPException(status_code=500, detail="Cannot connect with DB")

  body = await request.json()

  token = body.get("access_token")
  subscriptions = body.get("subscriptions")

  if not token:
    raise HTTPException(status_code=401, detail="Token required")

  if not subscriptions or not isinstance(subscriptions, list):
    raise HTTPException(status_code=400, detail="subscriptions must be a list")

  try:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    user_id = payload.get("sub")

    if user_id is None:
      raise HTTPException(status_code=401, detail="Invalid token")

  except JWTError:
    raise HTTPException(status_code=401, detail="Invalid token")

  async with app.state.db.acquire() as conn:
    # 유저 존재 확인
    user = await conn.fetchrow(
      'SELECT id FROM "user" WHERE id = $1',
      user_id
    )

    if not user:
      raise HTTPException(status_code=404, detail="User not found")

    async with conn.transaction():
      inserted_count = 0

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

  return {
    "status": "success",
    "inserted_rows": inserted_count
  }

@app.delete("/users/subscriptions")
async def delete_subscription(request: Request):
  if not hasattr(app.state, "db") or app.state.db is None:
    raise HTTPException(status_code=500, detail="Cannot connect with DB")

  body = await request.json()

  token = body.get("access_token")
  slug = body.get("slug")

  if not token:
    raise HTTPException(status_code=401, detail="Token required")

  if not slug:
    raise HTTPException(status_code=400, detail="slug required")

  try:
    payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    user_id = payload.get("sub")

    if user_id is None:
      raise HTTPException(status_code=401, detail="Invalid token")

  except JWTError:
    raise HTTPException(status_code=401, detail="Invalid token")

  async with app.state.db.acquire() as conn:
    result = await conn.execute(
      """
      DELETE FROM user_subscription
      WHERE user_id = $1
      AND slug = $2
      """,
      user_id,
      slug
    )

    deleted_count = int(result.split(" ")[1])

    if deleted_count == 0:
      raise HTTPException(status_code=404, detail="Subscription not found")

  return {
    "status": "success",
    "deleted_rows": deleted_count
  }

# @app.post("/test")
# async def test_repo(request: Request):
#   body = await request.json()
#   code = body.get("code")

#   token_url = "https://github.com/login/oauth/access_token"
#   r = requests.post(
#     token_url,
#     data={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code": code},
#     headers={"Accept": "application/json"},
#   )
#   access_token = r.json().get("access_token")

#   repo_url = "https://api.github.com/user/repos"
#   headers = {"Authorization": f"token {access_token}"}
#   res = requests.post(repo_url, json={"name": "testSuccess"}, headers=headers)
#   return res.json()
