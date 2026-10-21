import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

import jwt
from bson import ObjectId
from bson.errors import InvalidId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from pymongo.errors import DuplicateKeyError

from app.database import (
    users_collection,
    transactions_collection,
    businesses_collection,
    settlements_collection,
    shared_calculations_collection,
    workspaces_collection,
)

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(ENV_FILE)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY missing. Add it to backend/.env")

JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "1440"))

app = FastAPI(title="Money Calculator API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def now_utc():
    return datetime.now(timezone.utc)


def as_id(value: str):
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        raise HTTPException(status_code=400, detail="Invalid ID")


def create_access_token(user_id: str):
    now = now_utc()
    return jwt.encode(
        {"sub": user_id, "iat": now, "exp": now + timedelta(minutes=TOKEN_EXPIRE_MINUTES)},
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = users_collection.find_one({"_id": as_id(user_id)}, {"password_hash": 0})
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {
        "user_id": str(user["_id"]),
        "name": user["name"],
        "email": user["email"],
        "created_at": user.get("created_at"),
        "workspace_id": user.get("workspace_id"),
    }


def require_business_member(business_id: str, user_id: str):
    business = businesses_collection.find_one({
        "_id": as_id(business_id),
        "status": "active",
        "member_ids": user_id,
    })
    if not business:
        raise HTTPException(status_code=404, detail="Business not found or you are not a member")
    return business


def business_public(b):
    member_ids = b.get("member_ids", [])
    shares = b.get("shares") or {}
    return {
        "id": str(b["_id"]),
        "name": b["name"],
        "description": b.get("description", ""),
        "owner_id": b["owner_id"],
        "member_ids": member_ids,
        "shares": shares,
        "created_at": b.get("created_at"),
        "status": b.get("status", "active"),
    }


def date_bounds(period: str):
    now = now_utc()
    if period == "daily":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == "weekly":
        start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == "monthly":
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    elif period == "all-time":
        return None, None
    else:
        raise HTTPException(status_code=422, detail="period must be daily, weekly, monthly, or all-time")
    return start, now + timedelta(seconds=1)


def totals_for(query):
    pipeline = [
        {"$match": query},
        {"$group": {"_id": "$type", "total": {"$sum": "$amount"}, "count": {"$sum": 1}}},
    ]
    results = list(transactions_collection.aggregate(pipeline))
    income = expense = income_count = expense_count = 0
    for r in results:
        if r["_id"] == "income":
            income, income_count = r["total"], r["count"]
        elif r["_id"] == "expense":
            expense, expense_count = r["total"], r["count"]
    return {
        "total_income": round(income, 2),
        "total_expense": round(expense, 2),
        "net_profit": round(income - expense, 2),
        "income_records": income_count,
        "expense_records": expense_count,
    }


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class PersonalTransactionRequest(BaseModel):
    type: Literal["income", "expense"]
    amount: float = Field(gt=0, allow_inf_nan=False)
    description: str = Field(min_length=1, max_length=200)
    date: datetime | None = None


class BusinessCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=300)


class AddBusinessPartnerRequest(BaseModel):
    business_id: str = Field(min_length=1, max_length=100)
    partner_email: EmailStr


class BusinessTransactionRequest(BaseModel):
    type: Literal["income", "expense"]
    amount: float = Field(gt=0, allow_inf_nan=False)
    description: str = Field(min_length=1, max_length=200)
    date: datetime | None = None


class SharesRequest(BaseModel):
    shares: dict[str, float]


class SharedCalculationRequest(BaseModel):
    sadique_amount: float = Field(ge=0, allow_inf_nan=False)
    sadique_received: float = Field(ge=0, allow_inf_nan=False)
    arshad_amount: float = Field(ge=0, allow_inf_nan=False)
    arshad_received: float = Field(ge=0, allow_inf_nan=False)


class SettlementRequest(BaseModel):
    from_user_id: str
    to_user_id: str
    amount: float = Field(gt=0, allow_inf_nan=False)
    note: str = Field(default="", max_length=200)


@app.get("/")
def home():
    return {"message": "Money Calculator API is running", "docs": "/docs"}


@app.get("/health")
def health():
    from app.database import check_database_connection
    try:
        check_database_connection()
        return {"status": "ok", "database": "connected"}
    except Exception:
        raise HTTPException(status_code=503, detail="Database connection failed")


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest):
    name = data.name.strip()
    email = str(data.email).lower().strip()
    if len(name) < 2:
        raise HTTPException(status_code=422, detail="Name must contain at least 2 characters")
    try:
        result = users_collection.insert_one({
            "name": name,
            "email": email,
            "password_hash": password_hash.hash(data.password),
            "created_at": now_utc(),
        })
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Email already registered")
    return {"message": "Registration successful", "user_id": str(result.inserted_id), "name": name, "email": email}


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    email = form_data.username.lower().strip()
    user = users_collection.find_one({"email": email})
    if not user or not password_hash.verify(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password",
                            headers={"WWW-Authenticate": "Bearer"})
    return {
        "access_token": create_access_token(str(user["_id"])),
        "token_type": "bearer",
        "expires_in": TOKEN_EXPIRE_MINUTES * 60,
    }


@app.get("/me")
def me(user=Depends(get_current_user)):
    return user


@app.post("/transactions", status_code=status.HTTP_201_CREATED)
def create_personal_transaction(data: PersonalTransactionRequest, user=Depends(get_current_user)):
    description = data.description.strip()
    if not description:
        raise HTTPException(status_code=422, detail="Description cannot be empty")
    date = data.date or now_utc()
    result = transactions_collection.insert_one({
        "user_id": user["user_id"], "type": data.type, "amount": data.amount,
        "description": description, "date": date, "created_at": now_utc(),
    })
    return {"message": "Personal transaction saved", "id": str(result.inserted_id)}


@app.get("/transactions")
def list_personal_transactions(user=Depends(get_current_user), limit: int = Query(200, ge=1, le=1000)):
    records = transactions_collection.find({
        "user_id": user["user_id"], "business_id": {"$exists": False}
    }).sort("date", -1).limit(limit)
    return {"transactions": [{
        "id": str(r["_id"]), "type": r["type"], "amount": r["amount"],
        "description": r["description"], "date": r["date"],
    } for r in records]}


@app.get("/transactions/summary")
def personal_summary(period: str = "all-time", user=Depends(get_current_user)):
    start, end = date_bounds(period)
    query = {"user_id": user["user_id"], "business_id": {"$exists": False}}
    if start:
        query["date"] = {"$gte": start, "$lt": end}
    return {"period": period, **totals_for(query)}


@app.get("/transactions/report")
def personal_report(period: str = "all-time", user=Depends(get_current_user)):
    start, end = date_bounds(period)
    query = {"user_id": user["user_id"], "business_id": {"$exists": False}}
    if start:
        query["date"] = {"$gte": start, "$lt": end}
    records = list(transactions_collection.find(query).sort("date", -1))
    return {
        "period": period,
        **totals_for(query),
        "transactions": [{
            "id": str(r["_id"]), "type": r["type"], "amount": r["amount"],
            "description": r["description"], "date": r["date"],
        } for r in records],
    }


@app.post("/businesses", status_code=status.HTTP_201_CREATED)
def create_business(data: BusinessCreateRequest, user=Depends(get_current_user)):
    name = data.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=422, detail="Business name must contain at least 2 characters")
    business = {
        "name": name,
        "description": data.description.strip(),
        "owner_id": user["user_id"],
        "member_ids": [user["user_id"]],
        "shares": {user["user_id"]: 100.0},
        "created_at": now_utc(),
        "status": "active",
    }
    result = businesses_collection.insert_one(business)
    business["_id"] = result.inserted_id
    return {"message": "Business created successfully", "business": business_public(business)}


@app.get("/businesses")
def list_businesses(user=Depends(get_current_user)):
    records = businesses_collection.find({"member_ids": user["user_id"]}).sort("created_at", -1)
    return {"total_businesses": businesses_collection.count_documents({"member_ids": user["user_id"]}),
            "businesses": [business_public(b) for b in records]}


@app.post("/businesses/partners")
def add_business_partner(data: AddBusinessPartnerRequest, user=Depends(get_current_user)):
    business = businesses_collection.find_one({"_id": as_id(data.business_id), "status": "active"})
    if not business:
        raise HTTPException(status_code=404, detail="Business not found")
    if business["owner_id"] != user["user_id"]:
        raise HTTPException(status_code=403, detail="Only the business owner can add partners")
    email = str(data.partner_email).lower().strip()
    partner = users_collection.find_one({"email": email})
    if not partner:
        raise HTTPException(status_code=404, detail="Partner account not found. Ask them to register first.")
    partner_id = str(partner["_id"])
    if partner_id in business.get("member_ids", []):
        raise HTTPException(status_code=400, detail="This user is already a business member")
    old_shares = business.get("shares") or {}
    member_ids = business.get("member_ids", []) + [partner_id]
    # Preserve prior shares proportionally; newly added partner gets an equal split by default.
    if len(member_ids) == 2:
        shares = {member_ids[0]: 50.0, member_ids[1]: 50.0}
    else:
        each = round(100 / len(member_ids), 2)
        shares = {member_id: each for member_id in member_ids}
        shares[member_ids[-1]] = round(100 - sum(shares[m] for m in member_ids[:-1]), 2)
    businesses_collection.update_one({"_id": business["_id"]}, {
        "$addToSet": {"member_ids": partner_id},
        "$set": {"shares": shares},
    })
    return {"message": "Partner added successfully", "business_id": data.business_id,
            "business_name": business["name"], "partner_name": partner["name"], "partner_email": email,
            "shares": shares}


@app.put("/businesses/{business_id}/shares")
def update_business_shares(business_id: str, data: SharesRequest, user=Depends(get_current_user)):
    business = require_business_member(business_id, user["user_id"])
    if business["owner_id"] != user["user_id"]:
        raise HTTPException(status_code=403, detail="Only the business owner can change shares")
    shares = data.shares
    members = set(business.get("member_ids", []))
    if set(shares.keys()) != members:
        raise HTTPException(status_code=422, detail="Provide a percentage for every business member and no others")
    if any(not isinstance(v, (int, float)) or v < 0 or v > 100 for v in shares.values()):
        raise HTTPException(status_code=422, detail="Shares must be between 0 and 100")
    if abs(sum(shares.values()) - 100) > 0.01:
        raise HTTPException(status_code=422, detail="All member shares must add up to 100")
    businesses_collection.update_one({"_id": business["_id"]}, {"$set": {"shares": shares}})
    return {"message": "Business shares updated", "shares": shares}


@app.post("/businesses/{business_id}/transactions", status_code=status.HTTP_201_CREATED)
def create_business_transaction(business_id: str, data: BusinessTransactionRequest, user=Depends(get_current_user)):
    business = require_business_member(business_id, user["user_id"])
    description = data.description.strip()
    if not description:
        raise HTTPException(status_code=422, detail="Description cannot be empty")
    date = data.date or now_utc()
    result = transactions_collection.insert_one({
        "business_id": str(business["_id"]), "business_name": business["name"],
        "user_id": user["user_id"], "created_by_name": user["name"],
        "type": data.type, "amount": data.amount, "description": description,
        "date": date, "created_at": now_utc(),
    })
    return {"message": "Business transaction saved", "id": str(result.inserted_id)}


@app.get("/businesses/{business_id}/transactions")
def list_business_transactions(business_id: str, user=Depends(get_current_user), limit: int = Query(200, ge=1, le=1000)):
    business = require_business_member(business_id, user["user_id"])
    records = transactions_collection.find({"business_id": str(business["_id"])}).sort("date", -1).limit(limit)
    return {"business_id": str(business["_id"]), "business_name": business["name"], "transactions": [{
        "id": str(r["_id"]), "created_by": r["user_id"], "created_by_name": r.get("created_by_name", "Unknown"),
        "type": r["type"], "amount": r["amount"], "description": r["description"], "date": r["date"],
    } for r in records]}


@app.get("/businesses/{business_id}/summary")
def business_summary(business_id: str, period: str = "all-time", user=Depends(get_current_user)):
    business = require_business_member(business_id, user["user_id"])
    start, end = date_bounds(period)
    query = {"business_id": str(business["_id"])}
    if start:
        query["date"] = {"$gte": start, "$lt": end}
    totals = totals_for(query)
    shares = business.get("shares") or {}
    members = []
    member_users = list(users_collection.find({"_id": {"$in": [as_id(uid) for uid in business.get("member_ids", [])]}}, {"password_hash": 0}))
    name_map = {str(m["_id"]): m["name"] for m in member_users}
    # Old businesses without configured shares get equal shares.
    ids = business.get("member_ids", [])
    if not shares and ids:
        each = round(100 / len(ids), 2)
        shares = {uid: each for uid in ids}
    for uid in ids:
        percent = float(shares.get(uid, 0))
        members.append({
            "user_id": uid, "name": name_map.get(uid, "Former member"),
            "share_percent": percent,
            "profit_share": round(totals["net_profit"] * percent / 100, 2),
        })
    return {"business_id": str(business["_id"]), "business_name": business["name"],
            "period": period, **totals, "members": members, "shares": shares}


@app.get("/businesses/{business_id}/report")
def business_report(business_id: str, period: str = "all-time", user=Depends(get_current_user)):
    business = require_business_member(business_id, user["user_id"])
    start, end = date_bounds(period)
    query = {"business_id": str(business["_id"])}
    if start:
        query["date"] = {"$gte": start, "$lt": end}
    records = list(transactions_collection.find(query).sort("date", -1))
    totals = totals_for(query)
    return {"period": period, **totals, "transactions": [{
        "id": str(r["_id"]), "type": r["type"], "amount": r["amount"],
        "description": r["description"], "created_by_name": r.get("created_by_name", ""),
        "date": r["date"],
    } for r in records]}


@app.post("/businesses/{business_id}/settlements", status_code=status.HTTP_201_CREATED)
def create_settlement(business_id: str, data: SettlementRequest, user=Depends(get_current_user)):
    business = require_business_member(business_id, user["user_id"])
    members = set(business.get("member_ids", []))
    if data.from_user_id not in members or data.to_user_id not in members:
        raise HTTPException(status_code=422, detail="Both people must be members of this business")
    if data.from_user_id == data.to_user_id:
        raise HTTPException(status_code=422, detail="Payer and receiver must be different")
    payer = users_collection.find_one({"_id": as_id(data.from_user_id)}, {"name": 1})
    receiver = users_collection.find_one({"_id": as_id(data.to_user_id)}, {"name": 1})
    settlement = {
        "business_id": str(business["_id"]), "from_user_id": data.from_user_id,
        "from_name": payer["name"] if payer else "Unknown",
        "to_user_id": data.to_user_id, "to_name": receiver["name"] if receiver else "Unknown",
        "amount": data.amount, "note": data.note.strip(), "recorded_by": user["user_id"],
        "created_at": now_utc(),
    }
    result = settlements_collection.insert_one(settlement)
    return {"message": "Settlement recorded", "settlement_id": str(result.inserted_id)}


@app.get("/businesses/{business_id}/settlements")
def list_settlements(business_id: str, user=Depends(get_current_user)):
    business = require_business_member(business_id, user["user_id"])
    records = settlements_collection.find({"business_id": str(business["_id"])}).sort("created_at", -1)
    return {"settlements": [{
        "id": str(r["_id"]), "from_user_id": r["from_user_id"], "from_name": r["from_name"],
        "to_user_id": r["to_user_id"], "to_name": r["to_name"], "amount": r["amount"],
        "note": r.get("note", ""), "created_at": r["created_at"],
    } for r in records]}


class WorkspaceJoinRequest(BaseModel):
    code: str = Field(min_length=4, max_length=20)


def workspace_public(w):
    members = []
    for uid in w.get("member_ids", []):
        u = users_collection.find_one({"_id": as_id(uid)}, {"name": 1, "email": 1})
        if u:
            members.append({"user_id": uid, "name": u.get("name", "User"), "email": u.get("email", "")})
    return {"id": str(w["_id"]), "name": w["name"], "code": w["code"], "members": members}


def current_workspace(user):
    ws_id = user.get("workspace_id")
    if not ws_id:
        raise HTTPException(status_code=409, detail="Create a shared dashboard or join with an access code first")
    w = workspaces_collection.find_one({"_id": as_id(ws_id), "member_ids": user["user_id"]})
    if not w:
        raise HTTPException(status_code=404, detail="Shared dashboard not found")
    return w


@app.post("/workspaces", status_code=status.HTTP_201_CREATED)
def create_workspace(user=Depends(get_current_user)):
    if user.get("workspace_id"):
        existing = workspaces_collection.find_one({"_id": as_id(user["workspace_id"]), "member_ids": user["user_id"]})
        if existing:
            return {"message": "You are already connected to a shared dashboard", "workspace": workspace_public(existing)}
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(10):
        code = "".join(secrets.choice(alphabet) for _ in range(6))
        try:
            result = workspaces_collection.insert_one({
                "name": "Shared Money Calculator", "code": code,
                "owner_id": user["user_id"], "member_ids": [user["user_id"]],
                "created_at": now_utc(),
            })
            workspaces_collection.update_one({"_id": result.inserted_id}, {"$set": {"id": str(result.inserted_id)}})
            users_collection.update_one({"_id": as_id(user["user_id"])}, {"$set": {"workspace_id": str(result.inserted_id)}})
            w = workspaces_collection.find_one({"_id": result.inserted_id})
            return {"message": "Shared dashboard created", "workspace": workspace_public(w)}
        except DuplicateKeyError:
            continue
    raise HTTPException(status_code=500, detail="Could not generate an access code. Try again.")


@app.post("/workspaces/join")
def join_workspace(data: WorkspaceJoinRequest, user=Depends(get_current_user)):
    code = data.code.strip().upper()
    w = workspaces_collection.find_one({"code": code})
    if not w:
        raise HTTPException(status_code=404, detail="Access code not found")
    if user["user_id"] in w.get("member_ids", []):
        users_collection.update_one({"_id": as_id(user["user_id"])}, {"$set": {"workspace_id": str(w["_id"])}})
        return {"message": "Already connected", "workspace": workspace_public(w)}
    if len(w.get("member_ids", [])) >= 2:
        raise HTTPException(status_code=409, detail="This shared dashboard already has two partners")
    users_collection.update_one({"_id": as_id(user["user_id"])}, {"$set": {"workspace_id": str(w["_id"])}})
    workspaces_collection.update_one({"_id": w["_id"]}, {"$addToSet": {"member_ids": user["user_id"]}})
    w = workspaces_collection.find_one({"_id": w["_id"]})
    return {"message": "Joined shared dashboard", "workspace": workspace_public(w)}


@app.get("/workspaces/current")
def get_current_workspace(user=Depends(get_current_user)):
    w = current_workspace(user)
    return {"workspace": workspace_public(w)}


@app.post("/shared-calculations", status_code=status.HTTP_201_CREATED)
def save_shared_calculation(data: SharedCalculationRequest, user=Depends(get_current_user)):
    workspace = current_workspace(user)
    members = workspace.get("member_ids", [])
    if len(members) < 2:
        raise HTTPException(status_code=409, detail="Share the access code with your business partner and ask them to join first")
    member_names = []
    for uid in members:
        u = users_collection.find_one({"_id": as_id(uid)}, {"name": 1})
        member_names.append(u.get("name", "Partner") if u else "Partner")
    first_name, second_name = (member_names + ["Partner 2", "Partner 2"])[:2]
    total_amount = data.sadique_amount + data.arshad_amount
    total_received = data.sadique_received + data.arshad_received
    profit = total_received - total_amount
    share = profit / 2
    sadique_final = data.sadique_amount + share
    arshad_final = data.arshad_amount + share
    if sadique_final > data.sadique_received:
        payment = {"message": f"{second_name} pays {first_name}", "amount": round(sadique_final-data.sadique_received, 2)}
    elif arshad_final > data.arshad_received:
        payment = {"message": f"{first_name} pays {second_name}", "amount": round(arshad_final-data.arshad_received, 2)}
    else:
        payment = {"message": "No payment required", "amount": 0}
    record = {
        "workspace_id": str(workspace["_id"]),
        "partner1_id": members[0], "partner2_id": members[1],
        "partner1_name": first_name, "partner2_name": second_name,
        "sadique_amount": data.sadique_amount, "sadique_received": data.sadique_received,
        "arshad_amount": data.arshad_amount, "arshad_received": data.arshad_received,
        "total_profit": round(profit, 2), "sadique_share": round(share, 2),
        "arshad_share": round(share, 2), "payment": payment,
        "saved_by": user["user_id"], "saved_by_name": user["name"],
        "created_at": now_utc(),
    }
    result = shared_calculations_collection.insert_one(record)
    return {"message": "Calculation saved", "id": str(result.inserted_id)}


@app.get("/shared-calculations")
def list_shared_calculations(
    period: str = "daily", start_date: str | None = None, end_date: str | None = None,
    user=Depends(get_current_user),
):
    workspace = current_workspace(user)
    query = {"workspace_id": str(workspace["_id"])}
    if start_date or end_date:
        try:
            start = datetime.fromisoformat(start_date).replace(tzinfo=timezone.utc) if start_date else None
            end = (datetime.fromisoformat(end_date) + timedelta(days=1)).replace(tzinfo=timezone.utc) if end_date else None
        except ValueError:
            raise HTTPException(status_code=422, detail="Dates must use YYYY-MM-DD format")
        if start and end and start >= end:
            raise HTTPException(status_code=422, detail="Start date must be before end date")
        created = {}
        if start: created["$gte"] = start
        if end: created["$lt"] = end
        query["created_at"] = created
        period_label = "custom"
    else:
        start, end = date_bounds(period)
        if start:
            query["created_at"] = {"$gte": start, "$lt": end}
        period_label = period
    records = list(shared_calculations_collection.find(query).sort("created_at", -1).limit(1000))
    profit = sum(float(r.get("total_profit", 0)) for r in records)
    first_share = sum(float(r.get("sadique_share", 0)) for r in records)
    second_share = sum(float(r.get("arshad_share", 0)) for r in records)
    members = workspace.get("member_ids", [])
    names = []
    for uid in members:
        u = users_collection.find_one({"_id": as_id(uid)}, {"name": 1})
        names.append(u.get("name", "Partner") if u else "Partner")
    names = (names + ["Partner 2", "Partner 2"])[:2]
    return {
        "period": period_label, "count": len(records), "total_profit": round(profit, 2),
        "partner1_name": names[0], "partner2_name": names[1],
        "partner1_share": round(first_share, 2), "partner2_share": round(second_share, 2),
        "calculations": [{
            "id": str(r["_id"]), "sadique_amount": r["sadique_amount"],
            "sadique_received": r["sadique_received"], "arshad_amount": r["arshad_amount"],
            "arshad_received": r["arshad_received"], "total_profit": r["total_profit"],
            "sadique_share": r["sadique_share"], "arshad_share": r["arshad_share"],
            "partner1_name": r.get("partner1_name", names[0]), "partner2_name": r.get("partner2_name", names[1]),
            "payment": r["payment"], "saved_by_name": r.get("saved_by_name", "User"),
            "created_at": r["created_at"],
        } for r in records],
    }
