from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import os
import requests
import asyncpg

from passlib.hash import argon2

from jose import JWTError, jwt
from datetime import datetime, timedelta

app = FastAPI()

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
