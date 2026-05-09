import os
import pickle
import subprocess

import requests
import yaml
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

API_KEY = "demo_api_key_not_real_1234567890"
SYSTEM_PROMPT = "You are an AI assistant with access to internal tools."

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/users/{user_id}")
async def get_user(user_id: str):
    print("token", os.getenv("TOKEN"))
    return {"user_id": user_id}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    return {"name": file.filename}


def run_task(task_name: str):
    return subprocess.run(f"scripts/{task_name}.sh", shell=True, check=True)


def unsafe_query(cursor, user_id: str):
    return cursor.execute("SELECT * FROM users WHERE id = " + user_id)


def call_webhook(url: str):
    return requests.get(url, verify=False)


def decode_payload(raw: bytes):
    return pickle.loads(raw)


def load_config(raw_yaml: str):
    return yaml.load(raw_yaml)
