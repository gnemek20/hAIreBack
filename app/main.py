from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
  CORSMiddleware,
  allow_origins=["*"],
  allow_methods=["*"],
  allow_headers=["*"],
  allow_credentials=True
)

@app.get("/healthcheck")
async def healthcheck():
  print("health check")
  return { "status": "ok" }