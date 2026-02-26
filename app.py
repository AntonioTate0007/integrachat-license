"""
IntegraChat Cloud Licensing Server v1.1.0
Deploy to Railway / Render / Fly.io (free tier works for ~1,000 seats)

Endpoints:
  POST /activate    - activate a license key on a hardware fingerprint
  POST /refresh     - renew a 30-day token (called monthly by server)
  POST /deactivate  - emergency kill: invalidate all active tokens for a key
  GET  /status      - check key status (admin)
  POST /keys/create - (admin) generate a new license key

Environment variables required:
  JWT_SECRET      - random 64-char hex string (never commit this)
  ADMIN_TOKEN     - bearer token for /keys/create and /status
  DATABASE_URL    - SQLite path or Postgres URL (e.g. sqlite:///./licenses.db)
"""
import os, hashlib, secrets, json
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# ── Config ────────────────────────────────────────────────────────────────────
JWT_SECRET    = os.environ.get("JWT_SECRET", "CHANGE_ME_in_production_use_64_hex_chars")
ADMIN_TOKEN   = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
DATABASE_URL  = os.environ.get("DATABASE_URL", "sqlite:///./licenses.db")
TOKEN_TTL_DAYS = 35   # token valid 35 days; server renews every 30

TIER_SEATS = {"starter": 5, "professional": 15, "enterprise": 9999, "developer": 3}

# ── Database ──────────────────────────────────────────────────────────────────
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class LicenseKey(Base):
    __tablename__ = "license_keys"
    key        = Column(String(64), primary_key=True)
    tier       = Column(String(32), default="starter")
    seats      = Column(Integer, default=5)
    active     = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)   # None = never expires
    notes      = Column(Text, default="")


class Activation(Base):
    __tablename__ = "activations"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    key           = Column(String(64), index=True)
    hw_fingerprint= Column(String(64))  # SHA-256 of MAC+hostname
    device_name   = Column(String(128), default="")
    activated_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen     = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    revoked       = Column(Boolean, default=False)


Base.metadata.create_all(bind=engine)

# Seed a developer key on first run
def _seed():
    with SessionLocal() as db:
        if not db.get(LicenseKey, "DEV-INTEGRACHAT-2025-ANT"):
            db.add(LicenseKey(
                key="DEV-INTEGRACHAT-2025-ANT",
                tier="developer",
                seats=3,
                active=True,
                notes="Built-in developer key",
            ))
            db.commit()
_seed()

# ── FastAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(title="IntegraChat License Server", version="1.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _require_admin(authorization: str = Header(...)):
    if authorization.removeprefix("Bearer ") != ADMIN_TOKEN:
        raise HTTPException(403, "Invalid admin token")


# ── Schemas ───────────────────────────────────────────────────────────────────
class ActivateRequest(BaseModel):
    license_key:    str
    hw_fingerprint: str   # SHA-256(MAC+hostname) computed client-side
    device_name:    str = ""


class RefreshRequest(BaseModel):
    license_key:    str
    hw_fingerprint: str


class DeactivateRequest(BaseModel):
    license_key: str


class CreateKeyRequest(BaseModel):
    tier:  str = "starter"
    notes: str = ""
    expires_days: Optional[int] = 365


# ── Helpers ───────────────────────────────────────────────────────────────────
def _issue_token(key: str, hw: str, tier: str, seats: int) -> str:
    payload = {
        "key":   key,
        "hw":    hw,
        "tier":  tier,
        "seats": seats,
        "exp":   datetime.now(timezone.utc) + timedelta(days=TOKEN_TTL_DAYS),
        "iat":   datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _active_seat_count(db: Session, key: str) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=TOKEN_TTL_DAYS + 5)
    return db.query(Activation).filter(
        Activation.key == key,
        Activation.revoked == False,
        Activation.last_seen >= cutoff,
    ).count()


# ── Routes ────────────────────────────────────────────────────────────────────
@app.post("/activate")
def activate(req: ActivateRequest, db: Session = Depends(get_db)):
    lic = db.get(LicenseKey, req.license_key)
    if not lic:
        raise HTTPException(404, "License key not found")
    if not lic.active:
        raise HTTPException(403, "License key is deactivated")
    if lic.expires_at and lic.expires_at < datetime.now(timezone.utc):
        raise HTTPException(403, "License key has expired")

    # Check existing activation for this hardware fingerprint
    existing = db.query(Activation).filter_by(
        key=req.license_key, hw_fingerprint=req.hw_fingerprint, revoked=False
    ).first()

    if existing:
        # Re-activation for same hardware — just refresh last_seen
        existing.last_seen = datetime.now(timezone.utc)
        if req.device_name:
            existing.device_name = req.device_name
        db.commit()
    else:
        # New hardware — check seat count
        used = _active_seat_count(db, req.license_key)
        if used >= lic.seats:
            raise HTTPException(402, f"Seat limit reached ({lic.seats} seats). "
                                     f"Deactivate an unused device or upgrade your plan.")
        db.add(Activation(
            key=req.license_key,
            hw_fingerprint=req.hw_fingerprint,
            device_name=req.device_name,
        ))
        db.commit()

    token = _issue_token(req.license_key, req.hw_fingerprint, lic.tier, lic.seats)
    return {
        "status": "activated",
        "token": token,
        "tier": lic.tier,
        "seats_total": lic.seats,
        "seats_used": _active_seat_count(db, req.license_key),
        "expires_at": (lic.expires_at.isoformat() if lic.expires_at else None),
    }


@app.post("/refresh")
def refresh(req: RefreshRequest, db: Session = Depends(get_db)):
    lic = db.get(LicenseKey, req.license_key)
    if not lic or not lic.active:
        raise HTTPException(403, "License key inactive or not found")
    if lic.expires_at and lic.expires_at < datetime.now(timezone.utc):
        raise HTTPException(403, "License key has expired — please renew your subscription")

    act = db.query(Activation).filter_by(
        key=req.license_key, hw_fingerprint=req.hw_fingerprint, revoked=False
    ).first()
    if not act:
        raise HTTPException(403, "Hardware not registered — please re-activate")

    act.last_seen = datetime.now(timezone.utc)
    db.commit()

    token = _issue_token(req.license_key, req.hw_fingerprint, lic.tier, lic.seats)
    return {"status": "refreshed", "token": token, "tier": lic.tier}


@app.post("/deactivate")
def deactivate(req: DeactivateRequest, db: Session = Depends(get_db),
               _: None = Depends(_require_admin)):
    rows = db.query(Activation).filter_by(key=req.license_key, revoked=False).all()
    for row in rows:
        row.revoked = True
    db.commit()
    return {"status": "deactivated", "revoked_count": len(rows)}


@app.get("/status")
def status(license_key: str, db: Session = Depends(get_db),
           _: None = Depends(_require_admin)):
    lic = db.get(LicenseKey, license_key)
    if not lic:
        raise HTTPException(404, "Key not found")
    activations = db.query(Activation).filter_by(key=license_key).all()
    return {
        "key":       lic.key,
        "tier":      lic.tier,
        "seats":     lic.seats,
        "active":    lic.active,
        "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
        "notes":     lic.notes,
        "activations": [
            {
                "hw":         a.hw_fingerprint[:16] + "...",
                "device":     a.device_name,
                "last_seen":  a.last_seen.isoformat(),
                "revoked":    a.revoked,
            }
            for a in activations
        ],
    }


@app.post("/keys/create")
def create_key(req: CreateKeyRequest, db: Session = Depends(get_db),
               _: None = Depends(_require_admin)):
    if req.tier not in TIER_SEATS:
        raise HTTPException(400, f"Unknown tier. Choose from: {list(TIER_SEATS.keys())}")
    key = "IC-" + secrets.token_hex(10).upper()
    expires = (datetime.now(timezone.utc) + timedelta(days=req.expires_days)
               if req.expires_days else None)
    db.add(LicenseKey(
        key=key,
        tier=req.tier,
        seats=TIER_SEATS[req.tier],
        active=True,
        expires_at=expires,
        notes=req.notes,
    ))
    db.commit()
    return {
        "key": key,
        "tier": req.tier,
        "seats": TIER_SEATS[req.tier],
        "expires_at": expires.isoformat() if expires else None,
    }


@app.get("/health")
def health():
    return {"status": "ok", "version": "1.1.0"}
