import os
from pathlib import Path
from dotenv import load_dotenv
from pymongo import MongoClient

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(ENV_FILE)

MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME", "money_calculator")

if not MONGODB_URL:
    raise RuntimeError("MONGODB_URL missing. Add it to backend/.env")

client = MongoClient(MONGODB_URL, serverSelectionTimeoutMS=8000)
db = client[DATABASE_NAME]

users_collection = db["users"]
transactions_collection = db["transactions"]
businesses_collection = db["businesses"]
settlements_collection = db["settlements"]
shared_calculations_collection = db["shared_calculations"]
workspaces_collection = db["workspaces"]

users_collection.create_index("email", unique=True)
transactions_collection.create_index([("user_id", 1), ("date", -1)])
transactions_collection.create_index([("business_id", 1), ("date", -1)])
businesses_collection.create_index([("member_ids", 1)])
settlements_collection.create_index([("business_id", 1), ("created_at", -1)])
shared_calculations_collection.create_index([("workspace_id", 1), ("created_at", -1)])
workspaces_collection.create_index("code", unique=True)
workspaces_collection.create_index([("member_ids", 1)])

def check_database_connection():
    client.admin.command("ping")
    return True
