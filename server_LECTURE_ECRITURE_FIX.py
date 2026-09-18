import os
import json
import io
import hmac
import hashlib
import secrets
import threading
import socket
import http.client
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, MetaData, Table, Column, Integer, String, Text,
    Boolean, ForeignKey, select, insert, update, delete, func, text, LargeBinary
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.engine import Engine

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_RIGHT, TA_CENTER
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table as RLTable, TableStyle, Image as RLImage


APP_NAME = "HexTune Engineering Central API"

HEXTUNE_CONNECT_LATEST_VERSION = os.getenv("HEXTUNE_CONNECT_LATEST_VERSION", "16.66.3").strip()
HEXTUNE_CONNECT_UPDATE_URL = os.getenv("HEXTUNE_CONNECT_UPDATE_URL", "").strip()
HEXTUNE_CONNECT_UPDATE_SHA256 = os.getenv("HEXTUNE_CONNECT_UPDATE_SHA256", "").strip().lower()
HEXTUNE_CONNECT_UPDATE_MANDATORY = os.getenv("HEXTUNE_CONNECT_UPDATE_MANDATORY", "false").strip().lower() in {"1", "true", "yes", "on"}

HEXTUNE_FILES_MANAGER_LATEST_VERSION = os.getenv("HEXTUNE_FILES_MANAGER_LATEST_VERSION", "16.66.17").strip()
HEXTUNE_FILES_MANAGER_UPDATE_URL = os.getenv("HEXTUNE_FILES_MANAGER_UPDATE_URL", "").strip()
HEXTUNE_FILES_MANAGER_UPDATE_SHA256 = os.getenv("HEXTUNE_FILES_MANAGER_UPDATE_SHA256", "").strip().lower()
HEXTUNE_FILES_MANAGER_UPDATE_MANDATORY = os.getenv("HEXTUNE_FILES_MANAGER_UPDATE_MANDATORY", "false").strip().lower() in {"1", "true", "yes", "on"}

# Notifications push iPhone via ntfy.
# Le nom du topic reste uniquement dans les variables d'environnement Render.
NTFY_SERVER = os.getenv("NTFY_SERVER", "https://ntfy.sh").strip().rstrip("/")
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "").strip()
NTFY_TOKEN = os.getenv("NTFY_TOKEN", "").strip()
PUSHOVER_APP_TOKEN = os.getenv("PUSHOVER_APP_TOKEN", "").strip()
PUSHOVER_USER_KEY = os.getenv("PUSHOVER_USER_KEY", "").strip()


def _ntfy_header_text(value: str) -> str:
    """Rend un header HTTP compatible avec requests/latin-1 sans casser le corps UTF-8."""
    text = str(value or "")
    # Les headers HTTP de requests sont encodes en latin-1. Remplacer les signes
    # typographiques Unicode courants qui provoquent UnicodeEncodeError.
    replacements = {
        "\u2014": "-",  # tiret cadratin
        "\u2013": "-",  # tiret demi-cadratin
        "\u2022": "-",  # puce
        "\u00a0": " ",  # espace insecable
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text.encode("latin-1", errors="replace").decode("latin-1")



def _post_ntfy_ipv4(url: str, body: bytes, headers: dict, timeout: int = 10):
    """Fallback HTTPS IPv4 pour ntfy, sans modifier le réseau des autres services (PayPal, etc.)."""
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise RuntimeError("Le fallback ntfy IPv4 exige HTTPS.")

    hostname = parsed.hostname
    if not hostname:
        raise RuntimeError("Hôte ntfy invalide.")
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    ipv4 = socket.getaddrinfo(
        hostname, port,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
    )
    if not ipv4:
        raise OSError(f"Aucune adresse IPv4 trouvée pour {hostname}")

    # http.client garde le nom DNS pour TLS/SNI et la vérification du certificat,
    # mais la connexion TCP est explicitement ouverte vers l'adresse IPv4.
    class _IPv4HTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            last_error = None
            for info in ipv4:
                address = info[4]
                sock = None
                try:
                    sock = socket.create_connection(address, self.timeout)
                    self.sock = self._context.wrap_socket(
                        sock,
                        server_hostname=hostname,
                    )
                    return
                except OSError as exc:
                    last_error = exc
                    if sock is not None:
                        try:
                            sock.close()
                        except Exception:
                            pass
            raise last_error or OSError("Connexion IPv4 ntfy impossible.")

    conn = _IPv4HTTPSConnection(hostname, port=port, timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers=headers)
        response = conn.getresponse()
        response_body = response.read().decode("utf-8", errors="replace")
        return int(response.status), response_body
    finally:
        conn.close()


def _send_ntfy_now(title: str, message: str, priority: str = "default", tags: str = ""):
    """Compatibilité historique : les notifications sont désormais envoyées via Pushover."""
    if not PUSHOVER_APP_TOKEN or not PUSHOVER_USER_KEY:
        print("[pushover] SKIP: PUSHOVER_APP_TOKEN ou PUSHOVER_USER_KEY absent", flush=True)
        return False

    # Pushover : -2..2. On reste volontairement sur normal/élevé sans mode urgence.
    p = str(priority or "").strip().lower()
    pushover_priority = 1 if p in {"high", "max", "urgent", "4", "5"} else 0

    payload = {
        "token": PUSHOVER_APP_TOKEN,
        "user": PUSHOVER_USER_KEY,
        "title": str(title or "HexTune Engineering")[:250],
        "message": str(message or "")[:1024],
        "priority": pushover_priority,
    }

    try:
        print(
            "[pushover] SEND "
            f"token_configured={'yes' if PUSHOVER_APP_TOKEN else 'no'} "
            f"user_configured={'yes' if PUSHOVER_USER_KEY else 'no'}",
            flush=True,
        )
        response = requests.post(
            "https://api.pushover.net/1/messages.json",
            data=payload,
            timeout=15,
        )
        body = response.text or ""
        ok = response.status_code == 200
        if ok:
            try:
                ok = int(response.json().get("status", 0)) == 1
            except Exception:
                ok = False

        print(f"[pushover] HTTP status={response.status_code} ok={ok}", flush=True)
        if not ok:
            print(f"[pushover] ERROR body={body[:500]}", flush=True)
            return False
        return True
    except Exception as exc:
        print(f"[pushover] ERROR: {type(exc).__name__}: {exc}", flush=True)
        return False

def send_ntfy(title: str, message: str, tags: str = "bell", priority: str = "high") -> None:
    """Compatibilité historique : lance désormais Pushover en arrière-plan."""
    if not PUSHOVER_APP_TOKEN or not PUSHOVER_USER_KEY:
        print("[pushover] SKIP: configuration absente", flush=True)
        return
    threading.Thread(
        target=_send_ntfy_now,
        args=(title, message, priority, tags),
        daemon=True,
    ).start()

INVOICE_SELLER_NAME = "HexTune Engineering by FKR Performance"
INVOICE_SELLER_ADDRESS = "Zone Ecopole 57320 Bouzonville"
INVOICE_SELLER_SIRET = "84212781300025"
INVOICE_SELLER_SIREN = "842127813"
INVOICE_SELLER_VAT = "FR21842127813"
INVOICE_SELLER_EMAIL = "contact@hextune-engineering.com"
INVOICE_VAT_RATE = float(os.getenv("HEXTUNE_INVOICE_VAT_RATE", "20.0"))
ADMIN_KEY = os.getenv("HEXTUNE_ADMIN_KEY", "")

PAYPAL_MODE = os.getenv("PAYPAL_MODE", "sandbox").strip().lower()
PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
PAYPAL_WEBHOOK_ID = os.getenv("PAYPAL_WEBHOOK_ID", "")
PUBLIC_BASE_URL = os.getenv(
    "HEXTUNE_PUBLIC_URL",
    "https://hextune-central-server.onrender.com"
).rstrip("/")

PAYPAL_API_BASE = (
    "https://api-m.paypal.com"
    if PAYPAL_MODE == "live"
    else "https://api-m.sandbox.paypal.com"
)

# Render PostgreSQL fournit typiquement DATABASE_URL.
# En local uniquement, SQLite reste disponible comme solution de secours.
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///hextune_local.db"

# Certains hébergeurs donnent encore postgres:// ; SQLAlchemy attend postgresql+psycopg://.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]

engine: Engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    future=True,
)

metadata = MetaData()

clients = Table(
    "clients", metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(120), nullable=False, unique=True),
    Column("password_hash", Text, nullable=False),
    Column("company", Text, nullable=False, default=""),
    Column("last_name", Text, nullable=False, default=""),
    Column("first_name", Text, nullable=False, default=""),
    Column("address", Text, nullable=False, default=""),
    Column("phone", Text, nullable=False, default=""),
    Column("email", Text, nullable=False, default=""),
    Column("siret", Text, nullable=False, default=""),
    Column("vat_number", Text, nullable=False, default=""),
    Column("billing_country", String(2), nullable=False, default="FR"),
    Column("active", Boolean, nullable=False, default=True),
    Column("tokens", Integer, nullable=False, default=0),
    Column("created_at", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
)

tokens_table = Table(
    "tokens", metadata,
    Column("token", String(255), primary_key=True),
    Column("client_id", Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False),
    Column("expires_at", Text, nullable=False),
    Column("created_at", Text, nullable=False),
)

requests_table = Table(
    "requests", metadata,
    Column("id", Integer, primary_key=True),
    Column("client_id", Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False),
    Column("created_at", Text, nullable=False),
    Column("vehicle_type", Text, nullable=False, default=""),
    Column("vehicle_brand", Text, nullable=False, default=""),
    Column("vehicle_model", Text, nullable=False, default=""),
    Column("vehicle_year", Text, nullable=False, default=""),
    Column("engine", Text, nullable=False, default=""),
    Column("original_power", Text, nullable=False, default=""),
    Column("ecu", Text, nullable=False, default=""),
    Column("read_write_tool", Text, nullable=False, default=""),
    Column("read_write_tool_choice", Text, nullable=False, default=""),
    Column("read_write_mode", Text, nullable=False, default=""),
    Column("read_write_mode_choice", Text, nullable=False, default=""),
    Column("modifications", Text, nullable=False, default=""),
    Column("comment", Text, nullable=False, default=""),
    Column("original_filename", Text, nullable=False, default=""),
    Column("original_file_data", LargeBinary, nullable=True),
    Column("original_file_size", Integer, nullable=False, default=0),
    Column("response_filename", Text, nullable=False, default=""),
    Column("response_file_data", LargeBinary, nullable=True),
    Column("response_file_size", Integer, nullable=False, default=0),
    Column("responded_at", Text, nullable=False, default=""),
    Column("status", Text, nullable=False, default="new"),
)

request_response_files = Table(
    "request_response_files", metadata,
    Column("id", Integer, primary_key=True),
    Column("request_id", Integer, ForeignKey("requests.id", ondelete="CASCADE"), nullable=False),
    Column("filename", Text, nullable=False, default=""),
    Column("file_data", LargeBinary, nullable=False),
    Column("file_size", Integer, nullable=False, default=0),
    Column("created_at", Text, nullable=False),
)

request_messages = Table(
    "request_messages", metadata,
    Column("id", Integer, primary_key=True),
    Column("request_id", Integer, ForeignKey("requests.id", ondelete="CASCADE"), nullable=False),
    Column("sender_type", String(20), nullable=False),  # client / engineer
    Column("sender_name", Text, nullable=False, default=""),
    Column("message", Text, nullable=False),
    Column("created_at", Text, nullable=False),
)

request_message_files = Table(
    "request_message_files", metadata,
    Column("id", Integer, primary_key=True),
    Column("message_id", Integer, ForeignKey("request_messages.id", ondelete="CASCADE"), nullable=False),
    Column("request_id", Integer, ForeignKey("requests.id", ondelete="CASCADE"), nullable=False),
    Column("filename", Text, nullable=False, default=""),
    Column("file_data", LargeBinary, nullable=False),
    Column("file_size", Integer, nullable=False, default=0),
    Column("created_at", Text, nullable=False),
)


service_status = Table(
    "service_status", metadata,
    Column("id", Integer, primary_key=True),
    Column("is_open", Boolean, nullable=False, default=True),
    Column("eta_code", String(32), nullable=False, default="lt10"),
    Column("updated_at", Text, nullable=False),
)


notifications_table = Table(
    "notifications", metadata,
    Column("id", Integer, primary_key=True),
    Column("recipient_type", String(20), nullable=False),  # engineer / client
    Column("client_id", Integer, nullable=True),
    Column("request_id", Integer, nullable=True),
    Column("kind", String(50), nullable=False),
    Column("title", Text, nullable=False),
    Column("body", Text, nullable=False, default=""),
    Column("created_at", Text, nullable=False),
    Column("read_at", Text, nullable=False, default=""),
)



modification_prices = Table(
    "modification_prices", metadata,
    Column("modification", Text, primary_key=True),
    Column("token_price", Integer, nullable=False, default=0),
    Column("updated_at", Text, nullable=False),
)

vehicle_modification_prices = Table(
    "vehicle_modification_prices", metadata,
    Column("vehicle_type", String(80), primary_key=True),
    Column("modification", Text, primary_key=True),
    Column("token_price", Integer, nullable=False, default=0),
    Column("active", Boolean, nullable=False, default=False),
    Column("updated_at", Text, nullable=False),
)

token_ledger = Table(
    "token_ledger", metadata,
    Column("id", Integer, primary_key=True),
    Column("client_id", Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False),
    Column("delta", Integer, nullable=False),
    Column("reason", Text, nullable=False, default=""),
    Column("created_at", Text, nullable=False),
)

token_packages = Table(
    "token_packages", metadata,
    Column("tokens", Integer, primary_key=True),
    Column("price_eur_cents", Integer, nullable=False, default=0),
    Column("active", Boolean, nullable=False, default=True),
    Column("updated_at", Text, nullable=False),
)

invoice_counter = Table(
    "invoice_counter", metadata,
    Column("id", Integer, primary_key=True),
    Column("next_number", Integer, nullable=False, default=1),
)

invoices = Table(
    "invoices", metadata,
    Column("id", Integer, primary_key=True),
    Column("invoice_number", String(64), nullable=False, unique=True),
    Column("client_id", Integer, ForeignKey("clients.id", ondelete="RESTRICT"), nullable=False),
    Column("paypal_order_id", String(255), nullable=False, unique=True),
    Column("capture_id", String(255), nullable=False, default=""),
    Column("issued_at", Text, nullable=False),
    Column("paid_at", Text, nullable=False),
    Column("client_company", Text, nullable=False, default=""),
    Column("client_last_name", Text, nullable=False, default=""),
    Column("client_first_name", Text, nullable=False, default=""),
    Column("client_address", Text, nullable=False, default=""),
    Column("client_email", Text, nullable=False, default=""),
    Column("client_siret", Text, nullable=False, default=""),
    Column("client_vat_number", Text, nullable=False, default=""),
    Column("client_country", String(2), nullable=False, default="FR"),
    Column("vat_reverse_charge", Boolean, nullable=False, default=False),
    Column("package_tokens", Integer, nullable=False),
    Column("amount_ttc_cents", Integer, nullable=False),
    Column("amount_ht_cents", Integer, nullable=False),
    Column("vat_cents", Integer, nullable=False),
    Column("vat_rate", Text, nullable=False, default="20.00"),
    Column("currency", Text, nullable=False, default="EUR"),
    Column("status", Text, nullable=False, default="PAID"),
    Column("pdf_data", LargeBinary, nullable=True),
)

paypal_orders = Table(
    "paypal_orders", metadata,
    Column("order_id", String(255), primary_key=True),
    Column("client_id", Integer, ForeignKey("clients.id", ondelete="CASCADE"), nullable=False),
    Column("package_tokens", Integer, nullable=False),
    Column("price_eur_cents", Integer, nullable=False),  # prix catalogue HT
    Column("amount_ht_cents", Integer, nullable=False, default=0),
    Column("vat_cents", Integer, nullable=False, default=0),
    Column("amount_ttc_cents", Integer, nullable=False, default=0),
    Column("vat_rate", Text, nullable=False, default="20.00"),
    Column("vat_reverse_charge", Boolean, nullable=False, default=False),
    Column("billing_country", String(2), nullable=False, default="FR"),
    Column("vat_number_snapshot", Text, nullable=False, default=""),
    Column("status", Text, nullable=False, default="CREATED"),
    Column("capture_id", String(255), unique=True),
    Column("credited", Boolean, nullable=False, default=False),
    Column("created_at", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
)

DEFAULT_MODIFICATIONS = [
    "Stage 1 moteur",
    "Stage 2 moteur",
    "Conversion Flex E85",
    "Conversion Flex E85 + Stage 1 moteur",
    "Conversion Flex E85 + Stage 2 moteur",
    "EGR Off",
    "DPF Off",
    "OPF/GPF Off",
    "Ad Blue Off",
    "Vmax Off",
    "Bridage Vmax",
    "Start and Stop Off",
    "COD Off",
    "Flaps Off",
    "TVA Off",
    "Lambda Off",
    "Cata Off",
    "MAF Off",
    "Correction Cold Start TDI",
    "Launch Control",
    "Rupteur Diesel",
    "Pop and Bang",
    "Désactivation clapet d'échappement",
    "Remise d'origine d'un calculateur",
    "Stage 1 boîte de vitesse auto",
    "Stage 2 boîte de vitesse auto",
]

VEHICLE_TYPES = [
    "Voitures",
    "Utilitaires",
    "Motos / Quad / SSV",
    "Poids lourds",
    "Engins de TP",
    "Engins agricoles",
]

DEFAULT_PACKAGES = {
    10: 1000,
    25: 2500,
    50: 5000,
    100: 10000,
    275: 25000,
    550: 50000,
}

TOKEN_DAYS = 30
app = FastAPI(title=APP_NAME, version="6.0.0")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def create_notification(
    conn,
    recipient_type,
    kind,
    title,
    body="",
    request_id=None,
    client_id=None,
):
    conn.execute(
        insert(notifications_table).values(
            recipient_type=recipient_type,
            client_id=client_id,
            request_id=request_id,
            kind=kind,
            title=title,
            body=body,
            created_at=now_iso(),
            read_at="",
        )
    )


def notification_to_dict(row):
    m = row._mapping if hasattr(row, "_mapping") else row
    return {
        "id": int(m["id"]),
        "recipient_type": m["recipient_type"],
        "client_id": m["client_id"],
        "request_id": m["request_id"],
        "kind": m["kind"],
        "title": m["title"],
        "body": m["body"] or "",
        "created_at": m["created_at"],
        "read": bool(m["read_at"]),
        "read_at": m["read_at"] or "",
    }


def init_db():
    metadata.create_all(engine)
    # V16.66 - colonnes de facturation ajoutées sans supprimer les données existantes.
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            for sql in [
                "ALTER TABLE clients ADD COLUMN IF NOT EXISTS billing_country VARCHAR(2) NOT NULL DEFAULT 'FR'",
                "ALTER TABLE paypal_orders ADD COLUMN IF NOT EXISTS amount_ht_cents INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE paypal_orders ADD COLUMN IF NOT EXISTS vat_cents INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE paypal_orders ADD COLUMN IF NOT EXISTS amount_ttc_cents INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE paypal_orders ADD COLUMN IF NOT EXISTS vat_rate TEXT NOT NULL DEFAULT '20.00'",
                "ALTER TABLE paypal_orders ADD COLUMN IF NOT EXISTS vat_reverse_charge BOOLEAN NOT NULL DEFAULT FALSE",
                "ALTER TABLE paypal_orders ADD COLUMN IF NOT EXISTS billing_country VARCHAR(2) NOT NULL DEFAULT 'FR'",
                "ALTER TABLE paypal_orders ADD COLUMN IF NOT EXISTS vat_number_snapshot TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS client_country VARCHAR(2) NOT NULL DEFAULT 'FR'",
                "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS vat_reverse_charge BOOLEAN NOT NULL DEFAULT FALSE",
                "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS pdf_data BYTEA",
            ]: conn.execute(text(sql))
    now = now_iso()
    with engine.begin() as conn:
        counter = conn.execute(select(invoice_counter.c.id).where(invoice_counter.c.id == 1)).first()
        if not counter:
            conn.execute(insert(invoice_counter).values(id=1, next_number=1))

def messages_with_attachments(conn, request_id):
    rows = conn.execute(
        select(request_messages)
        .where(request_messages.c.request_id == request_id)
        .order_by(request_messages.c.id.asc())
    ).all()

    result = []
    for row in rows:
        m = row._mapping
        files = conn.execute(
            select(
                request_message_files.c.id,
                request_message_files.c.filename,
                request_message_files.c.file_size,
                request_message_files.c.created_at,
            )
            .where(request_message_files.c.message_id == m["id"])
            .order_by(request_message_files.c.id.asc())
        ).all()

        result.append({
            "id": int(m["id"]),
            "sender_type": m["sender_type"],
            "sender_name": m["sender_name"] or "",
            "message": m["message"],
            "created_at": m["created_at"],
            "attachments": [
                {
                    "id": int(f._mapping["id"]),
                    "filename": f._mapping["filename"] or "",
                    "file_size": int(f._mapping["file_size"] or 0),
                    "created_at": f._mapping["created_at"] or "",
                }
                for f in files
            ],
        })
    return result



    with engine.begin() as conn:
        if DATABASE_URL.startswith("postgresql"):
            conn.execute(text(
                "ALTER TABLE requests "
                "ADD COLUMN IF NOT EXISTS vehicle_type TEXT NOT NULL DEFAULT ''"
            ))
            conn.execute(text(
                "ALTER TABLE requests "
                "ADD COLUMN IF NOT EXISTS read_write_tool TEXT NOT NULL DEFAULT ''"
            ))
            conn.execute(text(
                "ALTER TABLE requests "
                "ADD COLUMN IF NOT EXISTS read_write_tool_choice TEXT NOT NULL DEFAULT ''"
            ))
            conn.execute(text(
                "ALTER TABLE requests "
                "ADD COLUMN IF NOT EXISTS read_write_mode TEXT NOT NULL DEFAULT ''"
            ))
            conn.execute(text(
                "ALTER TABLE requests "
                "ADD COLUMN IF NOT EXISTS read_write_mode_choice TEXT NOT NULL DEFAULT ''"
            ))
            conn.execute(text(
                "ALTER TABLE requests ADD COLUMN IF NOT EXISTS original_file_data BYTEA"
            ))
            conn.execute(text(
                "ALTER TABLE requests ADD COLUMN IF NOT EXISTS original_file_size INTEGER NOT NULL DEFAULT 0"
            ))
            conn.execute(text(
                "ALTER TABLE requests ADD COLUMN IF NOT EXISTS response_filename TEXT NOT NULL DEFAULT ''"
            ))
            conn.execute(text(
                "ALTER TABLE requests ADD COLUMN IF NOT EXISTS response_file_data BYTEA"
            ))
            conn.execute(text(
                "ALTER TABLE requests ADD COLUMN IF NOT EXISTS response_file_size INTEGER NOT NULL DEFAULT 0"
            ))
            conn.execute(text(
                "ALTER TABLE requests ADD COLUMN IF NOT EXISTS responded_at TEXT NOT NULL DEFAULT ''"
            ))
        else:
            # Local SQLite migration for development installations.
            existing = {
                r[1] for r in conn.execute(text("PRAGMA table_info(requests)")).fetchall()
            }
            sqlite_columns = {
                "response_filename": "TEXT NOT NULL DEFAULT ''",
                "response_file_data": "BLOB",
                "response_file_size": "INTEGER NOT NULL DEFAULT 0",
                "responded_at": "TEXT NOT NULL DEFAULT ''",
            }
            for column_name, column_type in sqlite_columns.items():
                if column_name not in existing:
                    conn.execute(text(
                        f"ALTER TABLE requests ADD COLUMN {column_name} {column_type}"
                    ))
        # Migrate the legacy single response into the multi-response table once.
        legacy_rows = conn.execute(
            select(
                requests_table.c.id,
                requests_table.c.response_filename,
                requests_table.c.response_file_data,
                requests_table.c.response_file_size,
                requests_table.c.responded_at,
            ).where(
                requests_table.c.response_file_size > 0
            )
        ).all()

        for legacy in legacy_rows:
            lm = legacy._mapping
            exists_response = conn.execute(
                select(func.count(request_response_files.c.id))
                .where(request_response_files.c.request_id == lm["id"])
            ).scalar_one()

            if not exists_response and lm["response_file_data"]:
                conn.execute(
                    insert(request_response_files).values(
                        request_id=lm["id"],
                        filename=lm["response_filename"] or f"demande_{lm['id']}_modifie.bin",
                        file_data=lm["response_file_data"],
                        file_size=int(lm["response_file_size"] or 0),
                        created_at=lm["responded_at"] or now,
                    )
                )

        for mod in DEFAULT_MODIFICATIONS:
            exists = conn.execute(
                select(modification_prices.c.modification).where(
                    modification_prices.c.modification == mod
                )
            ).first()
            if not exists:
                conn.execute(
                    insert(modification_prices).values(
                        modification=mod,
                        token_price=0,
                        updated_at=now,
                    )
                )

        # Catalogue par type de véhicule.
        # Les tarifs globaux existants sont repris automatiquement pour
        # Voitures et Utilitaires lors de la première migration.
        global_prices = {
            r._mapping["modification"]: int(r._mapping["token_price"] or 0)
            for r in conn.execute(
                select(
                    modification_prices.c.modification,
                    modification_prices.c.token_price,
                )
            ).all()
        }

        for vehicle_type in VEHICLE_TYPES:
            for mod in DEFAULT_MODIFICATIONS:
                exists = conn.execute(
                    select(vehicle_modification_prices.c.modification).where(
                        vehicle_modification_prices.c.vehicle_type == vehicle_type,
                        vehicle_modification_prices.c.modification == mod,
                    )
                ).first()
                if not exists:
                    inherited = (
                        global_prices.get(mod, 0)
                        if vehicle_type in ("Voitures", "Utilitaires")
                        else 0
                    )
                    conn.execute(
                        insert(vehicle_modification_prices).values(
                            vehicle_type=vehicle_type,
                            modification=mod,
                            token_price=inherited,
                            active=bool(
                                vehicle_type in ("Voitures", "Utilitaires")
                                and inherited > 0
                            ),
                            updated_at=now,
                        )
                    )

        # Réparation V15.5 :
        # certaines bases déjà migrées possèdent les lignes Voitures/Utilitaires
        # mais toutes sont inactives. Dans ce cas uniquement, on restaure le
        # catalogue depuis les tarifs globaux historiques, sans écraser un
        # catalogue par véhicule déjà configuré dans A.
        for vehicle_type in ("Voitures", "Utilitaires"):
            active_count = conn.execute(
                select(func.count()).select_from(
                    vehicle_modification_prices
                ).where(
                    vehicle_modification_prices.c.vehicle_type == vehicle_type,
                    vehicle_modification_prices.c.active == True,
                )
            ).scalar_one()

            if int(active_count or 0) == 0:
                for mod in DEFAULT_MODIFICATIONS:
                    inherited = int(global_prices.get(mod, 0) or 0)

                    row = conn.execute(
                        select(vehicle_modification_prices).where(
                            vehicle_modification_prices.c.vehicle_type == vehicle_type,
                            vehicle_modification_prices.c.modification == mod,
                        )
                    ).first()

                    if row:
                        conn.execute(
                            update(vehicle_modification_prices).where(
                                vehicle_modification_prices.c.vehicle_type == vehicle_type,
                                vehicle_modification_prices.c.modification == mod,
                            ).values(
                                token_price=inherited,
                                active=True,
                                updated_at=now,
                            )
                        )
                    else:
                        conn.execute(
                            insert(vehicle_modification_prices).values(
                                vehicle_type=vehicle_type,
                                modification=mod,
                                token_price=inherited,
                                active=True,
                                updated_at=now,
                            )
                        )

        for qty, cents in DEFAULT_PACKAGES.items():
            exists = conn.execute(
                select(token_packages.c.tokens).where(
                    token_packages.c.tokens == qty
                )
            ).first()
            if not exists:
                conn.execute(
                    insert(token_packages).values(
                        tokens=qty,
                        price_eur_cents=cents,
                        active=True,
                        updated_at=now,
                    )
                )


def backfill_missing_invoices():
    """Create invoices for historical credited PayPal orders, oldest first."""
    with engine.connect() as conn:
        rows = conn.execute(
            select(paypal_orders)
            .where(paypal_orders.c.credited == True)
            .order_by(paypal_orders.c.created_at.asc())
        ).all()
    for row in rows:
        m=row._mapping
        with engine.begin() as conn:
            existing=conn.execute(
                select(invoices.c.id).where(invoices.c.paypal_order_id == m["order_id"])
            ).first()
            if existing:
                continue
            issued=m.get("updated_at") or m.get("created_at") or now_iso()
            _create_invoice_for_paypal_order(conn,m,m.get("capture_id") or "",issued)


@app.on_event("startup")
def startup():
    init_db()
    backfill_missing_invoices()


def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        260000,
    )
    return salt.hex() + "$" + derived.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, expected = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        actual = hash_password(password, salt).split("$", 1)[1]
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def client_dict(row):
    m = row._mapping if hasattr(row, "_mapping") else row
    return {
        "id": m["id"],
        "username": m["username"],
        "company": m["company"],
        "last_name": m["last_name"],
        "first_name": m["first_name"],
        "address": m["address"],
        "phone": m["phone"],
        "email": m["email"],
        "siret": m["siret"],
        "vat_number": m["vat_number"],
        "billing_country": m.get("billing_country", "FR") or "FR",
        "active": bool(m["active"]),
        "tokens": int(m["tokens"] or 0),
        "created_at": m["created_at"],
        "updated_at": m["updated_at"],
    }


def require_admin(x_admin_key: str | None):
    if not ADMIN_KEY:
        raise HTTPException(500, "HEXTUNE_ADMIN_KEY n'est pas configurée.")
    if not x_admin_key or not hmac.compare_digest(x_admin_key, ADMIN_KEY):
        raise HTTPException(401, "Clé administrateur invalide.")


def bearer_client(authorization: str | None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authentification requise.")

    token_value = authorization.split(" ", 1)[1].strip()
    now = datetime.now(timezone.utc)

    with engine.connect() as conn:
        row = conn.execute(
            select(
                clients,
                tokens_table.c.expires_at
            ).join(
                tokens_table,
                clients.c.id == tokens_table.c.client_id
            ).where(
                tokens_table.c.token == token_value
            )
        ).first()

    if not row:
        raise HTTPException(401, "Session invalide.")

    m = row._mapping
    if not m["active"]:
        raise HTTPException(403, "Compte désactivé.")

    try:
        if datetime.fromisoformat(m["expires_at"]) < now:
            raise HTTPException(401, "Session expirée.")
    except ValueError:
        raise HTTPException(401, "Session invalide.")

    return m


class ClientCreate(BaseModel):
    username: str
    password: str
    company: str = ""
    last_name: str = ""
    first_name: str = ""
    address: str = ""
    phone: str = ""
    email: str = ""
    siret: str = ""
    vat_number: str = ""
    billing_country: str = "FR"
    active: bool = True


class Login(BaseModel):
    username: str
    password: str


class ResetPassword(BaseModel):
    new_password: str


class TokenAdjustment(BaseModel):
    delta: int
    reason: str = ""


class PriceUpdate(BaseModel):
    modification: str
    token_price: int


class VehiclePriceUpdate(BaseModel):
    vehicle_type: str
    modification: str
    token_price: int
    active: bool = True


class TokenPackageUpdate(BaseModel):
    tokens: int
    price_eur_cents: int
    active: bool = True


class ServiceStatusPatch(BaseModel):
    is_open: bool | None = None
    eta_code: str | None = None


class ClientPatch(BaseModel):
    company: str | None = None
    last_name: str | None = None
    first_name: str | None = None
    address: str | None = None
    phone: str | None = None
    email: str | None = None
    siret: str | None = None
    vat_number: str | None = None
    billing_country: str | None = None
    active: bool | None = None


class RequestCreate(BaseModel):
    vehicle_type: str = ""
    vehicle_brand: str = ""
    vehicle_model: str = ""
    vehicle_year: str = ""
    engine: str = ""
    original_power: str = ""
    ecu: str = ""
    read_write_tool: str = ""
    read_write_tool_choice: str = ""
    read_write_mode: str = ""
    read_write_mode_choice: str = ""
    modifications: list[str] = []
    comment: str = ""
    original_filename: str = ""


class RequestStatusUpdate(BaseModel):
    status: str


class RequestMessageCreate(BaseModel):
    message: str



def paypal_access_token():
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET:
        raise HTTPException(503, "PayPal n'est pas encore configuré sur le serveur.")

    response = requests.post(
        PAYPAL_API_BASE + "/v1/oauth2/token",
        auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
        data={"grant_type": "client_credentials"},
        timeout=20,
    )
    if response.status_code >= 400:
        raise HTTPException(502, "Impossible d'obtenir un jeton d'accès PayPal.")
    return response.json()["access_token"]


def paypal_headers():
    return {
        "Authorization": f"Bearer {paypal_access_token()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def find_capture(order_data):
    try:
        captures = order_data["purchase_units"][0]["payments"]["captures"]
        if not captures:
            return None, None
        capture = captures[0]
        return capture.get("id"), capture.get("status")
    except Exception:
        return None, None


def _invoice_next_number(conn):
    row = conn.execute(
        select(invoice_counter.c.next_number)
        .where(invoice_counter.c.id == 1)
        .with_for_update()
    ).first()
    if not row:
        conn.execute(insert(invoice_counter).values(id=1, next_number=2))
        return 1
    value = int(row._mapping["next_number"] or 1)
    conn.execute(
        update(invoice_counter)
        .where(invoice_counter.c.id == 1)
        .values(next_number=value + 1)
    )
    return value


def _create_invoice_for_paypal_order(conn, order_row, capture_id, now):
    existing = conn.execute(
        select(invoices.c.id).where(invoices.c.paypal_order_id == order_row["order_id"])
    ).first()
    if existing:
        return existing._mapping["id"]

    client_row = conn.execute(
        select(clients).where(clients.c.id == order_row["client_id"])
    ).first()
    if not client_row:
        raise RuntimeError("Client introuvable pour la génération de facture.")
    c = client_row._mapping

    seq = _invoice_next_number(conn)
    invoice_number = f"HTE-{seq:06d}"
    ht = int(order_row.get("amount_ht_cents") or order_row["price_eur_cents"])
    vat = int(order_row.get("vat_cents") or 0)
    ttc = int(order_row.get("amount_ttc_cents") or (ht + vat))
    rate = float(order_row.get("vat_rate") or 0)
    reverse_charge = bool(order_row.get("vat_reverse_charge") or False)

    result = conn.execute(
        insert(invoices).values(
            invoice_number=invoice_number,
            client_id=int(order_row["client_id"]),
            paypal_order_id=order_row["order_id"],
            capture_id=capture_id or "",
            issued_at=now,
            paid_at=now,
            client_company=c.get("company") or "",
            client_last_name=c.get("last_name") or "",
            client_first_name=c.get("first_name") or "",
            client_address=c.get("address") or "",
            client_email=c.get("email") or "",
            client_siret=c.get("siret") or "",
            client_vat_number=_normalize_vat(order_row.get("vat_number_snapshot") or c.get("vat_number") or ""),
            client_country=order_row.get("billing_country") or c.get("billing_country") or "FR",
            vat_reverse_charge=reverse_charge,
            package_tokens=int(order_row["package_tokens"]),
            amount_ttc_cents=ttc,
            amount_ht_cents=ht,
            vat_cents=vat,
            vat_rate=f"{rate:.2f}",
            currency="EUR",
            status="PAID",
        )
    )
    return result.inserted_primary_key[0]


def _invoice_dict(m):
    return {
        "id": int(m["id"]),
        "invoice_number": m["invoice_number"],
        "client_id": int(m["client_id"]),
        "issued_at": m["issued_at"],
        "paid_at": m["paid_at"],
        "client_company": m["client_company"],
        "client_name": (f"{m['client_first_name']} {m['client_last_name']}").strip(),
        "client_address": m["client_address"],
        "client_email": m["client_email"],
        "client_siret": m["client_siret"],
        "client_vat_number": m["client_vat_number"],
        "client_country": m.get("client_country", "FR") or "FR",
        "vat_reverse_charge": bool(m.get("vat_reverse_charge", False)),
        "package_tokens": int(m["package_tokens"]),
        "amount_ht": int(m["amount_ht_cents"]) / 100.0,
        "vat_amount": int(m["vat_cents"]) / 100.0,
        "vat_rate": float(m["vat_rate"] or 0),
        "amount_ttc": int(m["amount_ttc_cents"]) / 100.0,
        "currency": m["currency"],
        "status": m["status"],
        "paypal_order_id": m.get("paypal_order_id", "") or "",
        "paypal_capture_id": m.get("capture_id", "") or "",
        "pdf_path": f"/invoices/{int(m['id'])}/pdf",
        "admin_pdf_path": f"/admin/invoices/{int(m['id'])}/pdf",
    }


def _invoice_pdf_bytes(m):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm,
        topMargin=14*mm, bottomMargin=16*mm,
        title=f"Facture {m['invoice_number']}",
        author=INVOICE_SELLER_NAME,
    )
    styles = getSampleStyleSheet()
    normal = ParagraphStyle("InvNormal", parent=styles["Normal"], fontName="Helvetica",
                            fontSize=9, leading=12, textColor=colors.HexColor("#262626"))
    small = ParagraphStyle("InvSmall", parent=normal, fontSize=7.5, leading=10)
    title = ParagraphStyle("InvTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                           fontSize=22, leading=25, textColor=colors.HexColor("#9B7418"))
    right = ParagraphStyle("InvRight", parent=normal, alignment=TA_RIGHT)
    center = ParagraphStyle("InvCenter", parent=small, alignment=TA_CENTER)
    story=[]

    logo_path=os.path.join(os.path.dirname(__file__), "hextune_logo.png")
    logo = RLImage(logo_path, width=38*mm, height=20*mm) if os.path.exists(logo_path) else Paragraph("<b>HEXTUNE</b>", title)
    seller = Paragraph(
        f"<b>{INVOICE_SELLER_NAME}</b><br/>{INVOICE_SELLER_ADDRESS}<br/>"
        f"SIREN : {INVOICE_SELLER_SIREN} - SIRET : {INVOICE_SELLER_SIRET}<br/>"
        f"TVA intracommunautaire : {INVOICE_SELLER_VAT}<br/>{INVOICE_SELLER_EMAIL}", normal)
    heading = Paragraph(f"FACTURE<br/><font size='11'>{m['invoice_number']}</font>", right)
    head=RLTable([[logo,seller,heading]], colWidths=[42*mm,92*mm,42*mm])
    head.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"TOP"),("ALIGN",(2,0),(2,0),"RIGHT")]))
    story += [head, Spacer(1,8*mm)]

    client_name=(f"{m['client_first_name']} {m['client_last_name']}").strip()
    client_siren=(m["client_siret"] or "")[:9]
    seller_box=Paragraph(
        f"<b>ÉMETTEUR</b><br/>{INVOICE_SELLER_NAME}<br/>{INVOICE_SELLER_ADDRESS}<br/>"
        f"SIRET : {INVOICE_SELLER_SIRET}<br/>TVA : {INVOICE_SELLER_VAT}", normal)
    client_lines=[f"<b>CLIENT / FACTURATION</b>",
                  m["client_company"] or client_name or "Client",
                  client_name if m["client_company"] and client_name else "",
                  m["client_address"] or "Adresse non renseignée",
                  f"E-mail : {m['client_email']}" if m["client_email"] else "",
                  f"SIRET : {m['client_siret']}" if m["client_siret"] else "",
                  f"SIREN : {client_siren}" if client_siren else "",
                  f"TVA : {m['client_vat_number']}" if m["client_vat_number"] else ""]
    client_box=Paragraph("<br/>".join(x for x in client_lines if x), normal)
    boxes=RLTable([[seller_box,client_box]], colWidths=[88*mm,88*mm],
                  style=[("BOX",(0,0),(-1,-1),0.6,colors.HexColor("#B9B9B9")),
                         ("INNERGRID",(0,0),(-1,-1),0.3,colors.HexColor("#DDDDDD")),
                         ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F8F8F8")),
                         ("VALIGN",(0,0),(-1,-1),"TOP"),
                         ("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8),
                         ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8)])
    story += [boxes, Spacer(1,6*mm)]

    issued=(m["issued_at"] or "").replace("T"," ")[:19]
    paid=(m["paid_at"] or "").replace("T"," ")[:19]
    paypal_ref=(m.get("capture_id") or m.get("paypal_order_id") or "").strip()
    infos_rows=[
        ["Date d'émission", issued, "Date de paiement", paid],
        ["Mode de paiement", "PayPal - paiement comptant", "Catégorie", "Prestation de services"],
    ]
    if paypal_ref:
        infos_rows.append(["Référence PayPal", paypal_ref, "Devise", m.get("currency") or "EUR"])
    infos=RLTable(infos_rows, colWidths=[32*mm,56*mm,32*mm,56*mm])
    infos.setStyle(TableStyle([
        ("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTSIZE",(0,0),(-1,-1),8.5),
        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F3E9C9")),
        ("BACKGROUND",(2,0),(2,-1),colors.HexColor("#F3E9C9")),
        ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#C8C8C8")),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),("LEFTPADDING",(0,0),(-1,-1),6),
        ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)
    ]))
    story += [infos, Spacer(1,7*mm)]

    ht=int(m["amount_ht_cents"])/100
    vat=int(m["vat_cents"])/100
    ttc=int(m["amount_ttc_cents"])/100
    rate=float(m["vat_rate"] or 0)
    data=[
        ["Désignation","Qté","Prix unitaire HT","Total HT"],
        [f"Pack de {int(m['package_tokens'])} jetons HexTune Connect","1",f"{ht:.2f} €",f"{ht:.2f} €"],
    ]
    table=RLTable(data,colWidths=[92*mm,20*mm,34*mm,34*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#181C20")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTNAME",(0,1),(-1,-1),"Helvetica"),("FONTSIZE",(0,0),(-1,-1),9),
        ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#BDBDBD")),
        ("ALIGN",(1,1),(-1,-1),"RIGHT"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING",(0,0),(-1,-1),7),("BOTTOMPADDING",(0,0),(-1,-1),7)
    ]))
    story += [table, Spacer(1,5*mm)]

    totals=RLTable([
        ["Total HT",f"{ht:.2f} €"],
        [f"TVA {rate:.2f} %",f"{vat:.2f} €"],
        ["TOTAL TTC",f"{ttc:.2f} €"],
    ], colWidths=[45*mm,35*mm], hAlign="RIGHT")
    totals.setStyle(TableStyle([
        ("FONTNAME",(0,0),(-1,-2),"Helvetica"),("FONTNAME",(0,-1),(-1,-1),"Helvetica-Bold"),
        ("BACKGROUND",(0,-1),(-1,-1),colors.HexColor("#F3E9C9")),
        ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#BDBDBD")),
        ("ALIGN",(1,0),(1,-1),"RIGHT"),("FONTSIZE",(0,0),(-1,-1),9),
        ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)
    ]))
    story += [totals, Spacer(1,5*mm)]
    if bool(m.get("vat_reverse_charge", False)):
        story += [Paragraph("<b>TVA non facturée — autoliquidation par le preneur (reverse charge).</b>", normal), Spacer(1,4*mm)]

    legal=(
        "<b>Facture acquittée - règlement comptant par PayPal.</b><br/>"
        "Aucun escompte pour paiement anticipé. En cas de retard de paiement, des pénalités sont exigibles "
        "au taux de refinancement de la BCE majoré de 10 points, ainsi qu'une indemnité forfaitaire de 40 € "
        "pour frais de recouvrement lorsqu'elle est applicable entre professionnels (art. D. 441-5 du Code de commerce).<br/>"
        "Numérotation chronologique et continue sur l'ensemble des factures HexTune. "
        "Document généré électroniquement par HexTune Engineering.<br/>"
        "Pour la facturation électronique : catégorie d'opération = prestation de services. "
        "Les données d'identification client sont reprises du compte HexTune Connect."
    )
    story += [Paragraph(legal, small), Spacer(1,4*mm),
              Paragraph("HexTune Engineering - contact@hextune-engineering.com", center)]
    doc.build(story)
    return buf.getvalue()


def credit_paypal_order(order_id, capture_id, capture_status):
    if capture_status != "COMPLETED":
        return False

    now = now_iso()

    with engine.begin() as conn:
        row = conn.execute(
            select(paypal_orders).where(
                paypal_orders.c.order_id == order_id
            ).with_for_update()
        ).first()

        if not row:
            return False

        m = row._mapping
        if m["credited"]:
            return True

        conn.execute(
            update(clients).where(
                clients.c.id == m["client_id"]
            ).values(
                tokens=clients.c.tokens + int(m["package_tokens"]),
                updated_at=now
            )
        )
        conn.execute(
            insert(token_ledger).values(
                client_id=m["client_id"],
                delta=int(m["package_tokens"]),
                reason=f"Achat PayPal {order_id}",
                created_at=now,
            )
        )
        conn.execute(
            update(paypal_orders).where(
                paypal_orders.c.order_id == order_id
            ).values(
                status="COMPLETED",
                capture_id=capture_id,
                credited=True,
                updated_at=now,
            )
        )
        invoice_id = _create_invoice_for_paypal_order(conn, m, capture_id, now)
        inv = conn.execute(select(invoices).where(invoices.c.id == invoice_id)).first()
        if inv and not inv._mapping.get("pdf_data"):
            pdf = _invoice_pdf_bytes(inv._mapping)
            conn.execute(update(invoices).where(invoices.c.id == invoice_id).values(pdf_data=pdf))
    return True


def _version_tuple(value: str):
    parts = []
    for item in str(value or "0").replace("-", ".").split("."):
        digits = "".join(ch for ch in item if ch.isdigit())
        parts.append(int(digits or 0))
    return tuple((parts + [0, 0, 0])[:4])


@app.get("/updates/hextune-connect")
def hextune_connect_update(current_version: str = "0"):
    latest = HEXTUNE_CONNECT_LATEST_VERSION or "0"
    configured = bool(HEXTUNE_CONNECT_UPDATE_URL and len(HEXTUNE_CONNECT_UPDATE_SHA256) == 64)
    available = configured and _version_tuple(latest) > _version_tuple(current_version)
    return {"product": "HexTune Connect", "version": latest, "current_version": current_version,
            "update_available": available, "mandatory": bool(HEXTUNE_CONNECT_UPDATE_MANDATORY and available),
            "download_url": HEXTUNE_CONNECT_UPDATE_URL if available else "",
            "sha256": HEXTUNE_CONNECT_UPDATE_SHA256 if available else ""}


@app.get("/updates/hextune-files-manager")
def hextune_files_manager_update(current_version: str = "0"):
    latest = HEXTUNE_FILES_MANAGER_LATEST_VERSION or "0"
    configured = bool(HEXTUNE_FILES_MANAGER_UPDATE_URL and len(HEXTUNE_FILES_MANAGER_UPDATE_SHA256) == 64)
    available = configured and _version_tuple(latest) > _version_tuple(current_version)
    return {"product": "HexTune Files Manager", "version": latest, "current_version": current_version,
            "update_available": available, "mandatory": bool(HEXTUNE_FILES_MANAGER_UPDATE_MANDATORY and available),
            "download_url": HEXTUNE_FILES_MANAGER_UPDATE_URL if available else "",
            "sha256": HEXTUNE_FILES_MANAGER_UPDATE_SHA256 if available else ""}


@app.get("/health")
def health():
    return {
        "ok": True,
        "service": APP_NAME,
        "database": "postgresql" if DATABASE_URL.startswith("postgresql") else "sqlite-local",
    }


SERVICE_ETA_LABELS = {
    "lt10": "Moins de 10 min",
    "30m": "Environ 30 min",
    "45_60m": "45 min à 1 h",
}

def _service_status_payload(conn):
    row = conn.execute(select(service_status).where(service_status.c.id == 1)).first()
    if not row:
        now = now_iso()
        conn.execute(insert(service_status).values(
            id=1, is_open=True, eta_code="lt10", updated_at=now
        ))
        return {
            "is_open": True, "eta_code": "lt10",
            "eta_label": SERVICE_ETA_LABELS["lt10"], "updated_at": now,
        }
    m = row._mapping
    code = str(m.get("eta_code") or "lt10")
    return {
        "is_open": bool(m.get("is_open")),
        "eta_code": code,
        "eta_label": SERVICE_ETA_LABELS.get(code, code),
        "updated_at": m.get("updated_at") or "",
    }

@app.get("/service-status")
def public_service_status():
    """Statut public lu par HexTune Connect, sans clé administrateur."""
    with engine.begin() as conn:
        return _service_status_payload(conn)

@app.get("/admin/service-status")
def admin_service_status(x_admin_key: str | None = Header(None)):
    require_admin(x_admin_key)
    with engine.begin() as conn:
        return _service_status_payload(conn)

@app.patch("/admin/service-status")
def admin_update_service_status(
    data: ServiceStatusPatch,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)
    values = data.model_dump(exclude_none=True)
    if "eta_code" in values and values["eta_code"] not in SERVICE_ETA_LABELS:
        raise HTTPException(400, "Délai estimatif invalide.")
    with engine.begin() as conn:
        current = _service_status_payload(conn)
        merged = {
            "is_open": values.get("is_open", current["is_open"]),
            "eta_code": values.get("eta_code", current["eta_code"]),
            "updated_at": now_iso(),
        }
        conn.execute(
            update(service_status).where(service_status.c.id == 1).values(**merged)
        )
        return _service_status_payload(conn)


@app.get("/admin/clients")
def admin_clients(x_admin_key: str | None = Header(None)):
    require_admin(x_admin_key)
    with engine.connect() as conn:
        rows = conn.execute(
            select(clients).order_by(
                clients.c.company,
                clients.c.last_name,
                clients.c.first_name
            )
        ).all()
    return [client_dict(r) for r in rows]


@app.post("/admin/clients")
def admin_create_client(data: ClientCreate, x_admin_key: str | None = Header(None)):
    require_admin(x_admin_key)
    username = data.username.strip()

    if len(username) < 3:
        raise HTTPException(400, "Identifiant trop court.")
    if len(data.password) < 8:
        raise HTTPException(400, "Mot de passe : 8 caractères minimum.")

    now = now_iso()

    try:
        with engine.begin() as conn:
            result = conn.execute(
                insert(clients).values(
                    username=username,
                    password_hash=hash_password(data.password),
                    company=data.company.strip(),
                    last_name=data.last_name.strip(),
                    first_name=data.first_name.strip(),
                    address=data.address.strip(),
                    phone=data.phone.strip(),
                    email=data.email.strip(),
                    siret=data.siret.strip(),
                    vat_number=data.vat_number.strip(),
                    active=bool(data.active),
                    tokens=0,
                    created_at=now,
                    updated_at=now,
                )
            )
            client_id = result.inserted_primary_key[0]
            row = conn.execute(
                select(clients).where(clients.c.id == client_id)
            ).first()
    except IntegrityError:
        raise HTTPException(409, "Cet identifiant existe déjà.")

    return client_dict(row)


@app.patch("/admin/clients/{client_id}")
def admin_patch_client(
    client_id: int,
    data: ClientPatch,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    values = data.model_dump(exclude_none=True)
    if not values:
        raise HTTPException(400, "Aucune modification.")

    values["updated_at"] = now_iso()

    with engine.begin() as conn:
        conn.execute(
            update(clients).where(clients.c.id == client_id).values(**values)
        )
        row = conn.execute(
            select(clients).where(clients.c.id == client_id)
        ).first()

    if not row:
        raise HTTPException(404, "Client introuvable.")
    return client_dict(row)


@app.post("/admin/clients/{client_id}/reset-password")
def admin_reset_password(
    client_id: int,
    data: ResetPassword,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    if len(data.new_password) < 8:
        raise HTTPException(400, "Mot de passe : 8 caractères minimum.")

    with engine.begin() as conn:
        row = conn.execute(
            select(clients.c.id).where(clients.c.id == client_id)
        ).first()
        if not row:
            raise HTTPException(404, "Client introuvable.")

        conn.execute(
            update(clients).where(
                clients.c.id == client_id
            ).values(
                password_hash=hash_password(data.new_password),
                updated_at=now_iso(),
            )
        )
        conn.execute(
            delete(tokens_table).where(tokens_table.c.client_id == client_id)
        )

    return {"ok": True}


@app.post("/admin/clients/{client_id}/tokens")
def admin_adjust_tokens(
    client_id: int,
    data: TokenAdjustment,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    if data.delta == 0:
        raise HTTPException(400, "La variation de jetons ne peut pas être nulle.")

    now = now_iso()

    with engine.begin() as conn:
        row = conn.execute(
            select(clients).where(clients.c.id == client_id).with_for_update()
        ).first()

        if not row:
            raise HTTPException(404, "Client introuvable.")

        balance = int(row._mapping["tokens"] or 0)
        new_balance = balance + int(data.delta)

        if new_balance < 0:
            raise HTTPException(400, "Le solde de jetons ne peut pas devenir négatif.")

        conn.execute(
            update(clients).where(
                clients.c.id == client_id
            ).values(
                tokens=new_balance,
                updated_at=now,
            )
        )
        conn.execute(
            insert(token_ledger).values(
                client_id=client_id,
                delta=int(data.delta),
                reason=data.reason.strip(),
                created_at=now,
            )
        )

    return {"ok": True, "tokens": new_balance}


@app.get("/admin/prices")
def admin_prices(x_admin_key: str | None = Header(None)):
    require_admin(x_admin_key)

    with engine.connect() as conn:
        rows = conn.execute(
            select(modification_prices).order_by(
                modification_prices.c.modification
            )
        ).all()

    return [
        {
            "modification": r._mapping["modification"],
            "token_price": int(r._mapping["token_price"]),
            "updated_at": r._mapping["updated_at"],
        }
        for r in rows
    ]


@app.post("/admin/prices")
def admin_set_price(data: PriceUpdate, x_admin_key: str | None = Header(None)):
    require_admin(x_admin_key)

    if data.token_price < 0:
        raise HTTPException(400, "Le tarif ne peut pas être négatif.")

    now = now_iso()

    with engine.begin() as conn:
        exists = conn.execute(
            select(modification_prices.c.modification).where(
                modification_prices.c.modification == data.modification
            )
        ).first()

        if exists:
            conn.execute(
                update(modification_prices).where(
                    modification_prices.c.modification == data.modification
                ).values(
                    token_price=int(data.token_price),
                    updated_at=now,
                )
            )
        else:
            conn.execute(
                insert(modification_prices).values(
                    modification=data.modification,
                    token_price=int(data.token_price),
                    updated_at=now,
                )
            )

    return {"ok": True}



@app.get("/admin/vehicle-prices")
def admin_vehicle_prices(
    vehicle_type: str | None = None,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    if vehicle_type and vehicle_type not in VEHICLE_TYPES:
        raise HTTPException(400, "Type de véhicule invalide.")

    stmt = select(vehicle_modification_prices)
    if vehicle_type:
        stmt = stmt.where(
            vehicle_modification_prices.c.vehicle_type == vehicle_type
        )
    stmt = stmt.order_by(
        vehicle_modification_prices.c.vehicle_type,
        vehicle_modification_prices.c.modification,
    )

    with engine.connect() as conn:
        rows = conn.execute(stmt).all()

    return [
        {
            "vehicle_type": r._mapping["vehicle_type"],
            "modification": r._mapping["modification"],
            "token_price": int(r._mapping["token_price"] or 0),
            "active": bool(r._mapping["active"]),
            "updated_at": r._mapping["updated_at"],
        }
        for r in rows
    ]


@app.post("/admin/vehicle-prices")
def admin_set_vehicle_price(
    data: VehiclePriceUpdate,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    if data.vehicle_type not in VEHICLE_TYPES:
        raise HTTPException(400, "Type de véhicule invalide.")
    if data.token_price < 0:
        raise HTTPException(400, "Le tarif ne peut pas être négatif.")

    now = now_iso()

    with engine.begin() as conn:
        exists = conn.execute(
            select(vehicle_modification_prices.c.modification).where(
                vehicle_modification_prices.c.vehicle_type == data.vehicle_type,
                vehicle_modification_prices.c.modification == data.modification,
            )
        ).first()

        if exists:
            conn.execute(
                update(vehicle_modification_prices).where(
                    vehicle_modification_prices.c.vehicle_type == data.vehicle_type,
                    vehicle_modification_prices.c.modification == data.modification,
                ).values(
                    token_price=int(data.token_price),
                    active=bool(data.active),
                    updated_at=now,
                )
            )
        else:
            conn.execute(
                insert(vehicle_modification_prices).values(
                    vehicle_type=data.vehicle_type,
                    modification=data.modification,
                    token_price=int(data.token_price),
                    active=bool(data.active),
                    updated_at=now,
                )
            )

    return {"ok": True}


@app.get("/admin/token-packages")
def admin_token_packages(x_admin_key: str | None = Header(None)):
    require_admin(x_admin_key)

    with engine.connect() as conn:
        rows = conn.execute(
            select(token_packages).order_by(token_packages.c.tokens)
        ).all()

    return [
        {
            "tokens": int(r._mapping["tokens"]),
            "price_eur_cents": int(r._mapping["price_eur_cents"]),
            "active": bool(r._mapping["active"]),
            "updated_at": r._mapping["updated_at"],
        }
        for r in rows
    ]


@app.post("/admin/token-packages")
def admin_set_token_package(
    data: TokenPackageUpdate,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    if data.tokens not in (10, 25, 50, 100, 275, 550):
        raise HTTPException(400, "Pack de jetons non autorisé.")
    if data.price_eur_cents < 0:
        raise HTTPException(400, "Prix invalide.")

    now = now_iso()

    with engine.begin() as conn:
        exists = conn.execute(
            select(token_packages.c.tokens).where(
                token_packages.c.tokens == data.tokens
            )
        ).first()

        if exists:
            conn.execute(
                update(token_packages).where(
                    token_packages.c.tokens == data.tokens
                ).values(
                    price_eur_cents=int(data.price_eur_cents),
                    active=bool(data.active),
                    updated_at=now,
                )
            )
        else:
            conn.execute(
                insert(token_packages).values(
                    tokens=int(data.tokens),
                    price_eur_cents=int(data.price_eur_cents),
                    active=bool(data.active),
                    updated_at=now,
                )
            )

    return {"ok": True}


@app.get("/token-packages")
def public_token_packages(authorization: str | None = Header(None)):
    bearer_client(authorization)

    with engine.connect() as conn:
        rows = conn.execute(
            select(
                token_packages.c.tokens,
                token_packages.c.price_eur_cents,
            ).where(
                token_packages.c.active == True,
                token_packages.c.price_eur_cents > 0,
            ).order_by(
                token_packages.c.tokens
            )
        ).all()

    return [
        {
            "tokens": int(r._mapping["tokens"]),
            "price_eur_cents": int(r._mapping["price_eur_cents"]),
        }
        for r in rows
    ]


@app.get("/prices")
def public_prices(authorization: str | None = Header(None)):
    bearer_client(authorization)

    with engine.connect() as conn:
        rows = conn.execute(
            select(
                modification_prices.c.modification,
                modification_prices.c.token_price
            ).order_by(
                modification_prices.c.modification
            )
        ).all()

    return {
        r._mapping["modification"]: int(r._mapping["token_price"])
        for r in rows
    }


@app.get("/vehicle-prices/{vehicle_type}")
def public_vehicle_prices(
    vehicle_type: str,
    authorization: str | None = Header(None),
):
    bearer_client(authorization)

    if vehicle_type not in VEHICLE_TYPES:
        raise HTTPException(400, "Type de véhicule invalide.")

    with engine.connect() as conn:
        rows = conn.execute(
            select(
                vehicle_modification_prices.c.modification,
                vehicle_modification_prices.c.token_price,
            ).where(
                vehicle_modification_prices.c.vehicle_type == vehicle_type,
                vehicle_modification_prices.c.active == True,
            ).order_by(
                vehicle_modification_prices.c.modification
            )
        ).all()

    return {
        r._mapping["modification"]: int(r._mapping["token_price"])
        for r in rows
    }


@app.post("/auth/login")
def login(data: Login):
    username = data.username.strip()

    with engine.begin() as conn:
        row = conn.execute(
            select(clients).where(
                func.lower(clients.c.username) == username.lower()
            )
        ).first()

        if not row or not verify_password(data.password, row._mapping["password_hash"]):
            raise HTTPException(401, "Identifiant ou mot de passe incorrect.")

        if not row._mapping["active"]:
            raise HTTPException(403, "Compte désactivé.")

        token_value = secrets.token_urlsafe(40)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=TOKEN_DAYS)

        conn.execute(
            insert(tokens_table).values(
                token=token_value,
                client_id=row._mapping["id"],
                expires_at=expires.isoformat(),
                created_at=now.isoformat(),
            )
        )

    return {
        "token": token_value,
        "client": client_dict(row),
    }


@app.get("/me")
def me(authorization: str | None = Header(None)):
    row = bearer_client(authorization)
    return client_dict(row)


class BillingProfilePatch(BaseModel):
    company: str = ""
    last_name: str = ""
    first_name: str = ""
    address: str = ""
    email: str = ""
    siret: str = ""
    vat_number: str = ""
    billing_country: str = "FR"

@app.patch("/me/billing")
def update_my_billing(data: BillingProfilePatch, authorization: str | None = Header(None)):
    client=bearer_client(authorization)
    country=(data.billing_country or "FR").strip().upper()
    if country == "GR": country="EL"
    if len(country) != 2:
        raise HTTPException(400, "Code pays de facturation invalide (2 lettres, ex. FR, DE, BE).")
    vat=_normalize_vat(data.vat_number)
    with engine.begin() as conn:
        conn.execute(update(clients).where(clients.c.id == client["id"]).values(
            company=data.company.strip(), last_name=data.last_name.strip(), first_name=data.first_name.strip(),
            address=data.address.strip(), email=data.email.strip(), siret=data.siret.strip(),
            vat_number=vat, billing_country=country, updated_at=now_iso()))
        row=conn.execute(select(clients).where(clients.c.id == client["id"])).first()
    return client_dict(row)

@app.post("/requests")
def create_request(
    data: RequestCreate,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)
    now = now_iso()

    allowed_tools = {"Autotuner", "Flex", "KESSV2", "KTAG", "KESS3", "Newgenius", "CMDflash", "MPPS", "AUTRE"}
    tool_choice = (data.read_write_tool_choice or "").strip()
    tool_name = (data.read_write_tool or "").strip()

    if tool_choice not in allowed_tools:
        raise HTTPException(400, "Outil de lecture/écriture invalide.")
    if tool_choice == "AUTRE":
        if not tool_name:
            raise HTTPException(400, "Le nom de l'outil est obligatoire.")
        if len(tool_name) > 30:
            raise HTTPException(400, "Le nom de l'outil est limité à 30 caractères.")
    else:
        tool_name = tool_choice

    allowed_modes = {"OBD", "Bench", "Boot", "Jtag", "BDM", "AUTRE"}
    mode_choice = (data.read_write_mode_choice or "").strip()
    mode_name = (data.read_write_mode or "").strip()

    if mode_choice not in allowed_modes:
        raise HTTPException(400, "Mode de lecture/écriture invalide.")
    if mode_choice == "AUTRE":
        if not mode_name:
            raise HTTPException(400, "Le mode de lecture/écriture est obligatoire.")
        if len(mode_name) > 30:
            raise HTTPException(400, "Le mode de lecture/écriture est limité à 30 caractères.")
    else:
        mode_name = mode_choice

    with engine.begin() as conn:
        if data.vehicle_type not in VEHICLE_TYPES:
            raise HTTPException(400, "Type de véhicule invalide.")

        price_rows = conn.execute(
            select(
                vehicle_modification_prices.c.modification,
                vehicle_modification_prices.c.token_price,
            ).where(
                vehicle_modification_prices.c.vehicle_type == data.vehicle_type,
                vehicle_modification_prices.c.active == True,
            )
        ).all()

        prices = {
            r._mapping["modification"]: int(r._mapping["token_price"])
            for r in price_rows
        }

        unknown = [m for m in data.modifications if m not in prices]
        if unknown:
            raise HTTPException(
                400,
                "Tarif introuvable pour : " + ", ".join(unknown)
            )

        total_cost = sum(prices[m] for m in data.modifications)

        client_row = conn.execute(
            select(clients).where(
                clients.c.id == client["id"]
            ).with_for_update()
        ).first()

        balance = int(client_row._mapping["tokens"] or 0)

        if balance < total_cost:
            raise HTTPException(
                402,
                f"Solde insuffisant : {balance} jeton(s) disponibles, "
                f"{total_cost} jeton(s) nécessaires."
            )

        new_balance = balance - total_cost

        result = conn.execute(
            insert(requests_table).values(
                client_id=client["id"],
                created_at=now,
                vehicle_type=data.vehicle_type,
                vehicle_brand=data.vehicle_brand,
                vehicle_model=data.vehicle_model,
                vehicle_year=data.vehicle_year,
                engine=data.engine,
                original_power=data.original_power,
                ecu=data.ecu,
                read_write_tool=tool_name,
                read_write_tool_choice=tool_choice,
                read_write_mode=mode_name,
                read_write_mode_choice=mode_choice,
                modifications="\n".join(data.modifications),
                comment=data.comment,
                original_filename=data.original_filename,
                status="new",
            )
        )

        request_id = result.inserted_primary_key[0]

        if total_cost > 0:
            conn.execute(
                update(clients).where(
                    clients.c.id == client["id"]
                ).values(
                    tokens=new_balance,
                    updated_at=now,
                )
            )
            conn.execute(
                insert(token_ledger).values(
                    client_id=client["id"],
                    delta=-total_cost,
                    reason=f"Demande #{request_id}",
                    created_at=now,
                )
            )

    with engine.begin() as conn:
        create_notification(
            conn,
            recipient_type="engineer",
            kind="new_request",
            title=f"Nouvelle demande n° {request_id}",
            body=(
                f"{client.get('company') or client.get('username','Client')} — "
                f"{data.vehicle_brand} {data.vehicle_model}"
            ),
            request_id=request_id,
            client_id=int(client["id"]),
        )

    client_label = client.get("company") or client.get("username", "Client")
    send_ntfy(
        "HexTune — Nouvelle demande",
        f"{client_label} • Demande #{request_id} • {data.vehicle_brand} {data.vehicle_model}",
        tags="bell,car",
        priority="high",
    )

    return {
        "ok": True,
        "request_id": request_id,
        "created_at": now,
        "token_cost": total_cost,
        "tokens_remaining": new_balance,
    }



MAX_ORIGINAL_FILE_BYTES = 50 * 1024 * 1024


@app.put("/requests/{request_id}/file")
async def upload_request_file(
    request_id: int,
    request_obj: Request,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)
    data = await request_obj.body()
    if not data:
        raise HTTPException(400, "Le fichier envoyé est vide.")
    if len(data) > MAX_ORIGINAL_FILE_BYTES:
        raise HTTPException(413, "Fichier trop volumineux (maximum 50 Mo).")

    with engine.begin() as conn:
        row = conn.execute(
            select(requests_table.c.id, requests_table.c.client_id)
            .where(requests_table.c.id == request_id)
        ).first()
        if not row:
            raise HTTPException(404, "Demande introuvable.")
        if int(row._mapping["client_id"]) != int(client["id"]):
            raise HTTPException(403, "Cette demande n'appartient pas à ce client.")
        conn.execute(
            update(requests_table)
            .where(requests_table.c.id == request_id)
            .values(original_file_data=data, original_file_size=len(data))
        )
    return {"ok": True, "size": len(data)}


@app.get("/admin/requests/{request_id}/file")
def admin_download_request_file(
    request_id: int,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)
    with engine.connect() as conn:
        row = conn.execute(
            select(
                requests_table.c.original_filename,
                requests_table.c.original_file_data,
            ).where(requests_table.c.id == request_id)
        ).first()
    if not row:
        raise HTTPException(404, "Demande introuvable.")
    data = row._mapping["original_file_data"]
    filename = row._mapping["original_filename"] or f"demande_{request_id}.bin"
    if not data:
        raise HTTPException(404, "Aucun fichier n'est disponible pour cette demande.")
    from fastapi.responses import Response
    safe_name = filename.replace('"', "_").replace("\r", "_").replace("\n", "_")
    return Response(
        content=bytes(data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


MAX_RESPONSE_FILE_BYTES = 50 * 1024 * 1024


@app.put("/admin/requests/{request_id}/response-file")
async def admin_upload_response_file(
    request_id: int,
    request_obj: Request,
    filename: str = "",
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    data = await request_obj.body()
    if not data:
        raise HTTPException(400, "Le fichier de réponse est vide.")
    if len(data) > MAX_RESPONSE_FILE_BYTES:
        raise HTTPException(413, "Fichier de réponse trop volumineux (maximum 50 Mo).")

    safe_filename = os.path.basename(filename or f"demande_{request_id}_modifie.bin")
    safe_filename = safe_filename.replace("\r", "_").replace("\n", "_")
    now = now_iso()

    with engine.begin() as conn:
        row = conn.execute(
            select(requests_table.c.id).where(requests_table.c.id == request_id)
        ).first()
        if not row:
            raise HTTPException(404, "Demande introuvable.")

        inserted = conn.execute(
            insert(request_response_files).values(
                request_id=request_id,
                filename=safe_filename,
                file_data=data,
                file_size=len(data),
                created_at=now,
            )
        )
        response_id = inserted.inserted_primary_key[0]

        # Keep legacy latest-response columns for backward compatibility.
        conn.execute(
            update(requests_table)
            .where(requests_table.c.id == request_id)
            .values(
                response_filename=safe_filename,
                response_file_data=data,
                response_file_size=len(data),
                responded_at=now,
                status="processed",
            )
        )

        client_row = conn.execute(
            select(requests_table.c.client_id)
            .where(requests_table.c.id == request_id)
        ).first()
        if client_row:
            create_notification(
                conn,
                recipient_type="client",
                client_id=int(client_row._mapping["client_id"]),
                request_id=request_id,
                kind="file_response",
                title=f"Nouveau fichier pour la demande n° {request_id}",
                body=safe_filename,
            )

    return {
        "ok": True,
        "request_id": request_id,
        "response_id": int(response_id),
        "filename": safe_filename,
        "size": len(data),
        "status": "processed",
        "responded_at": now,
    }


@app.get("/requests/{request_id}/response-file")
def client_download_response_file(
    request_id: int,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)

    with engine.connect() as conn:
        req_row = conn.execute(
            select(requests_table.c.client_id)
            .where(requests_table.c.id == request_id)
        ).first()
        if not req_row:
            raise HTTPException(404, "Demande introuvable.")
        if int(req_row._mapping["client_id"]) != int(client["id"]):
            raise HTTPException(403, "Cette demande n'appartient pas à ce client.")

        row = conn.execute(
            select(request_response_files)
            .where(request_response_files.c.request_id == request_id)
            .order_by(request_response_files.c.id.desc())
            .limit(1)
        ).first()

    if not row:
        raise HTTPException(404, "Aucun fichier modifié n'est encore disponible.")

    m = row._mapping
    from fastapi.responses import Response
    safe_name = (m["filename"] or f"demande_{request_id}_modifie.bin").replace('"', "_")
    return Response(
        content=bytes(m["file_data"]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@app.get("/requests/{request_id}/files")
def client_request_files(
    request_id: int,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)

    with engine.connect() as conn:
        req_row = conn.execute(
            select(
                requests_table.c.client_id,
                requests_table.c.original_filename,
                requests_table.c.original_file_size,
                requests_table.c.created_at,
            ).where(requests_table.c.id == request_id)
        ).first()
        if not req_row:
            raise HTTPException(404, "Demande introuvable.")
        if int(req_row._mapping["client_id"]) != int(client["id"]):
            raise HTTPException(403, "Cette demande n'appartient pas à ce client.")

        replies = conn.execute(
            select(
                request_response_files.c.id,
                request_response_files.c.filename,
                request_response_files.c.file_size,
                request_response_files.c.created_at,
            )
            .where(request_response_files.c.request_id == request_id)
            .order_by(request_response_files.c.id.asc())
        ).all()

    r = req_row._mapping
    return {
        "original": {
            "filename": r["original_filename"] or f"demande_{request_id}.bin",
            "file_size": int(r["original_file_size"] or 0),
            "created_at": r["created_at"] or "",
            "download_path": f"/requests/{request_id}/original-file",
        },
        "responses": [
            {
                "id": int(row._mapping["id"]),
                "filename": row._mapping["filename"] or "",
                "file_size": int(row._mapping["file_size"] or 0),
                "created_at": row._mapping["created_at"] or "",
                "download_path": (
                    f"/requests/{request_id}/response-files/"
                    f"{int(row._mapping['id'])}"
                ),
            }
            for row in replies
        ],
    }


@app.get("/requests/{request_id}/original-file")
def client_download_original_file(
    request_id: int,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)

    with engine.connect() as conn:
        row = conn.execute(
            select(
                requests_table.c.client_id,
                requests_table.c.original_filename,
                requests_table.c.original_file_data,
            ).where(requests_table.c.id == request_id)
        ).first()

    if not row:
        raise HTTPException(404, "Demande introuvable.")
    if int(row._mapping["client_id"]) != int(client["id"]):
        raise HTTPException(403, "Cette demande n'appartient pas à ce client.")

    data = row._mapping["original_file_data"]
    if not data:
        raise HTTPException(404, "Fichier Original indisponible.")

    from fastapi.responses import Response
    filename = row._mapping["original_filename"] or f"demande_{request_id}.bin"
    safe_name = filename.replace('"', "_")
    return Response(
        content=bytes(data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@app.get("/requests/{request_id}/response-files/{response_id}")
def client_download_response_by_id(
    request_id: int,
    response_id: int,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)

    with engine.connect() as conn:
        req_row = conn.execute(
            select(requests_table.c.client_id)
            .where(requests_table.c.id == request_id)
        ).first()
        if not req_row:
            raise HTTPException(404, "Demande introuvable.")
        if int(req_row._mapping["client_id"]) != int(client["id"]):
            raise HTTPException(403, "Cette demande n'appartient pas à ce client.")

        row = conn.execute(
            select(request_response_files)
            .where(
                request_response_files.c.id == response_id,
                request_response_files.c.request_id == request_id,
            )
        ).first()

    if not row:
        raise HTTPException(404, "Fichier de réponse introuvable.")

    m = row._mapping
    from fastapi.responses import Response
    safe_name = (m["filename"] or f"reponse_{response_id}.bin").replace('"', "_")
    return Response(
        content=bytes(m["file_data"]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@app.get("/admin/requests/{request_id}/files")
def admin_request_files(
    request_id: int,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    with engine.connect() as conn:
        req_row = conn.execute(
            select(
                requests_table.c.original_filename,
                requests_table.c.original_file_size,
                requests_table.c.created_at,
            ).where(requests_table.c.id == request_id)
        ).first()
        if not req_row:
            raise HTTPException(404, "Demande introuvable.")

        replies = conn.execute(
            select(
                request_response_files.c.id,
                request_response_files.c.filename,
                request_response_files.c.file_size,
                request_response_files.c.created_at,
            )
            .where(request_response_files.c.request_id == request_id)
            .order_by(request_response_files.c.id.asc())
        ).all()

    r = req_row._mapping
    return {
        "original": {
            "filename": r["original_filename"] or f"demande_{request_id}.bin",
            "file_size": int(r["original_file_size"] or 0),
            "created_at": r["created_at"] or "",
        },
        "responses": [
            {
                "id": int(row._mapping["id"]),
                "filename": row._mapping["filename"] or "",
                "file_size": int(row._mapping["file_size"] or 0),
                "created_at": row._mapping["created_at"] or "",
            }
            for row in replies
        ],
    }


@app.get("/admin/requests/{request_id}/response-files/{response_id}")
def admin_download_response_by_id(
    request_id: int,
    response_id: int,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    with engine.connect() as conn:
        row = conn.execute(
            select(request_response_files)
            .where(
                request_response_files.c.id == response_id,
                request_response_files.c.request_id == request_id,
            )
        ).first()

    if not row:
        raise HTTPException(404, "Fichier de réponse introuvable.")

    m = row._mapping
    from fastapi.responses import Response
    safe_name = (m["filename"] or f"reponse_{response_id}.bin").replace('"', "_")
    return Response(
        content=bytes(m["file_data"]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )






def _request_has_response(conn, request_id: int) -> bool:
    return conn.execute(
        select(func.count(request_response_files.c.id))
        .where(request_response_files.c.request_id == request_id)
    ).scalar_one() > 0


@app.get("/requests/{request_id}/messages")
def client_get_request_messages(
    request_id: int,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)

    with engine.connect() as conn:
        req_row = conn.execute(
            select(requests_table.c.client_id)
            .where(requests_table.c.id == request_id)
        ).first()
        if not req_row:
            raise HTTPException(404, "Demande introuvable.")
        if int(req_row._mapping["client_id"]) != int(client["id"]):
            raise HTTPException(403, "Cette demande n'appartient pas à ce client.")

        rows = conn.execute(
            select(request_messages)
            .where(request_messages.c.request_id == request_id)
            .order_by(request_messages.c.id.asc())
        ).all()

    return [
        {
            "id": int(row._mapping["id"]),
            "sender_type": row._mapping["sender_type"],
            "sender_name": row._mapping["sender_name"] or "",
            "message": row._mapping["message"],
            "created_at": row._mapping["created_at"],
        }
        for row in rows
    ]


@app.post("/requests/{request_id}/messages")
def client_send_request_message(
    request_id: int,
    data: RequestMessageCreate,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)
    message = (data.message or "").strip()
    if not message:
        raise HTTPException(400, "Le message est vide.")
    if len(message) > 5000:
        raise HTTPException(400, "Message trop long (maximum 5000 caractères).")

    with engine.begin() as conn:
        req_row = conn.execute(
            select(requests_table.c.client_id)
            .where(requests_table.c.id == request_id)
        ).first()
        if not req_row:
            raise HTTPException(404, "Demande introuvable.")
        if int(req_row._mapping["client_id"]) != int(client["id"]):
            raise HTTPException(403, "Cette demande n'appartient pas à ce client.")

        now = now_iso()
        sender_name = (
            client.get("company")
            or f"{client.get('first_name','')} {client.get('last_name','')}".strip()
            or client.get("username","Client")
        )
        result = conn.execute(
            insert(request_messages).values(
                request_id=request_id,
                sender_type="client",
                sender_name=sender_name,
                message=message,
                created_at=now,
            )
        )

        create_notification(
            conn,
            recipient_type="engineer",
            client_id=int(client["id"]),
            request_id=request_id,
            kind="client_chat",
            title=f"Nouveau message client — demande n° {request_id}",
            body=message[:250],
        )

    send_ntfy(
        "HexTune — Nouveau message",
        f"{sender_name} • Demande #{request_id}\n{message[:300]}",
        tags="speech_balloon",
        priority="high",
    )

    return {"ok": True, "id": int(result.inserted_primary_key[0]), "created_at": now}


@app.get("/admin/requests/{request_id}/messages")
def admin_get_request_messages(
    request_id: int,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    with engine.connect() as conn:
        req_row = conn.execute(
            select(requests_table.c.id).where(requests_table.c.id == request_id)
        ).first()
        if not req_row:
            raise HTTPException(404, "Demande introuvable.")

        rows = conn.execute(
            select(request_messages)
            .where(request_messages.c.request_id == request_id)
            .order_by(request_messages.c.id.asc())
        ).all()

    return [
        {
            "id": int(row._mapping["id"]),
            "sender_type": row._mapping["sender_type"],
            "sender_name": row._mapping["sender_name"] or "",
            "message": row._mapping["message"],
            "created_at": row._mapping["created_at"],
        }
        for row in rows
    ]


@app.post("/admin/requests/{request_id}/messages")
def admin_send_request_message(
    request_id: int,
    data: RequestMessageCreate,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)
    message = (data.message or "").strip()
    if not message:
        raise HTTPException(400, "Le message est vide.")
    if len(message) > 5000:
        raise HTTPException(400, "Message trop long (maximum 5000 caractères).")

    with engine.begin() as conn:
        req_row = conn.execute(
            select(requests_table.c.id).where(requests_table.c.id == request_id)
        ).first()
        if not req_row:
            raise HTTPException(404, "Demande introuvable.")

        now = now_iso()
        result = conn.execute(
            insert(request_messages).values(
                request_id=request_id,
                sender_type="engineer",
                sender_name="Ingénieur HexTune",
                message=message,
                created_at=now,
            )
        )

        client_row = conn.execute(
            select(requests_table.c.client_id)
            .where(requests_table.c.id == request_id)
        ).first()
        if client_row:
            create_notification(
                conn,
                recipient_type="client",
                client_id=int(client_row._mapping["client_id"]),
                request_id=request_id,
                kind="engineer_chat",
                title=f"Réponse de l'ingénieur — demande n° {request_id}",
                body=message[:250],
            )

    return {"ok": True, "id": int(result.inserted_primary_key[0]), "created_at": now}




@app.get("/notifications")
def client_notifications(
    unread_only: bool = False,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)

    stmt = (
        select(notifications_table)
        .where(
            notifications_table.c.recipient_type == "client",
            notifications_table.c.client_id == int(client["id"]),
        )
        .order_by(notifications_table.c.id.desc())
        .limit(100)
    )
    if unread_only:
        stmt = stmt.where(notifications_table.c.read_at == "")

    with engine.connect() as conn:
        rows = conn.execute(stmt).all()

    return [notification_to_dict(row) for row in rows]


@app.post("/notifications/mark-read")
def client_mark_notifications_read(
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)
    now = now_iso()

    with engine.begin() as conn:
        conn.execute(
            update(notifications_table)
            .where(
                notifications_table.c.recipient_type == "client",
                notifications_table.c.client_id == int(client["id"]),
                notifications_table.c.read_at == "",
            )
            .values(read_at=now)
        )

    return {"ok": True, "read_at": now}


@app.get("/admin/notifications")
def admin_notifications(
    unread_only: bool = False,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    stmt = (
        select(notifications_table)
        .where(notifications_table.c.recipient_type == "engineer")
        .order_by(notifications_table.c.id.desc())
        .limit(100)
    )
    if unread_only:
        stmt = stmt.where(notifications_table.c.read_at == "")

    with engine.connect() as conn:
        rows = conn.execute(stmt).all()

    return [notification_to_dict(row) for row in rows]


@app.post("/admin/notifications/mark-read")
def admin_mark_notifications_read(
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)
    now = now_iso()

    with engine.begin() as conn:
        conn.execute(
            update(notifications_table)
            .where(
                notifications_table.c.recipient_type == "engineer",
                notifications_table.c.read_at == "",
            )
            .values(read_at=now)
        )

    return {"ok": True, "read_at": now}




MAX_CHAT_FILE_BYTES = 50 * 1024 * 1024


@app.put("/requests/{request_id}/messages/file")
async def client_send_request_file(
    request_id: int,
    request_obj: Request,
    filename: str = "",
    message: str = "",
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)
    data = await request_obj.body()
    if not data:
        raise HTTPException(400, "Le fichier joint est vide.")
    if len(data) > MAX_CHAT_FILE_BYTES:
        raise HTTPException(413, "Pièce jointe trop volumineuse (maximum 50 Mo).")

    safe_filename = os.path.basename(filename or "piece_jointe.bin").replace("\r", "_").replace("\n", "_")
    text_message = (message or "").strip()
    now = now_iso()

    with engine.begin() as conn:
        req_row = conn.execute(
            select(requests_table.c.client_id)
            .where(requests_table.c.id == request_id)
        ).first()
        if not req_row:
            raise HTTPException(404, "Demande introuvable.")
        if int(req_row._mapping["client_id"]) != int(client["id"]):
            raise HTTPException(403, "Cette demande n'appartient pas à ce client.")

        sender_name = (
            client.get("company")
            or f"{client.get('first_name','')} {client.get('last_name','')}".strip()
            or client.get("username","Client")
        )
        msg_result = conn.execute(
            insert(request_messages).values(
                request_id=request_id,
                sender_type="client",
                sender_name=sender_name,
                message=text_message or f"Fichier joint : {safe_filename}",
                created_at=now,
            )
        )
        message_id = int(msg_result.inserted_primary_key[0])

        file_result = conn.execute(
            insert(request_message_files).values(
                message_id=message_id,
                request_id=request_id,
                filename=safe_filename,
                file_data=data,
                file_size=len(data),
                created_at=now,
            )
        )

        create_notification(
            conn,
            recipient_type="engineer",
            client_id=int(client["id"]),
            request_id=request_id,
            kind="client_chat_file",
            title=f"Nouveau fichier client — demande n° {request_id}",
            body=safe_filename,
        )

    extra = f" — {text_message[:200]}" if text_message else ""
    send_ntfy(
        "HexTune — Nouveau fichier chat",
        f"{sender_name} • Demande #{request_id} • {safe_filename}{extra}",
        tags="paperclip",
        priority="high",
    )

    return {
        "ok": True,
        "message_id": message_id,
        "attachment_id": int(file_result.inserted_primary_key[0]),
        "filename": safe_filename,
        "size": len(data),
        "created_at": now,
    }


@app.put("/admin/requests/{request_id}/messages/file")
async def admin_send_request_file(
    request_id: int,
    request_obj: Request,
    filename: str = "",
    message: str = "",
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    data = await request_obj.body()
    if not data:
        raise HTTPException(400, "Le fichier joint est vide.")
    if len(data) > MAX_CHAT_FILE_BYTES:
        raise HTTPException(413, "Pièce jointe trop volumineuse (maximum 50 Mo).")

    safe_filename = os.path.basename(filename or "piece_jointe.bin").replace("\r", "_").replace("\n", "_")
    text_message = (message or "").strip()
    now = now_iso()

    with engine.begin() as conn:
        req_row = conn.execute(
            select(requests_table.c.client_id)
            .where(requests_table.c.id == request_id)
        ).first()
        if not req_row:
            raise HTTPException(404, "Demande introuvable.")

        msg_result = conn.execute(
            insert(request_messages).values(
                request_id=request_id,
                sender_type="engineer",
                sender_name="Ingénieur HexTune",
                message=text_message or f"Fichier joint : {safe_filename}",
                created_at=now,
            )
        )
        message_id = int(msg_result.inserted_primary_key[0])

        file_result = conn.execute(
            insert(request_message_files).values(
                message_id=message_id,
                request_id=request_id,
                filename=safe_filename,
                file_data=data,
                file_size=len(data),
                created_at=now,
            )
        )

        create_notification(
            conn,
            recipient_type="client",
            client_id=int(req_row._mapping["client_id"]),
            request_id=request_id,
            kind="engineer_chat_file",
            title=f"Nouveau fichier de l'ingénieur — demande n° {request_id}",
            body=safe_filename,
        )

    return {
        "ok": True,
        "message_id": message_id,
        "attachment_id": int(file_result.inserted_primary_key[0]),
        "filename": safe_filename,
        "size": len(data),
        "created_at": now,
    }


@app.get("/requests/{request_id}/messages/files/{attachment_id}")
def client_download_message_file(
    request_id: int,
    attachment_id: int,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)

    with engine.connect() as conn:
        req_row = conn.execute(
            select(requests_table.c.client_id)
            .where(requests_table.c.id == request_id)
        ).first()
        if not req_row:
            raise HTTPException(404, "Demande introuvable.")
        if int(req_row._mapping["client_id"]) != int(client["id"]):
            raise HTTPException(403, "Cette demande n'appartient pas à ce client.")

        row = conn.execute(
            select(request_message_files)
            .where(
                request_message_files.c.id == attachment_id,
                request_message_files.c.request_id == request_id,
            )
        ).first()

    if not row:
        raise HTTPException(404, "Pièce jointe introuvable.")

    m = row._mapping
    from fastapi.responses import Response
    safe_name = (m["filename"] or f"piece_jointe_{attachment_id}.bin").replace('"', "_")
    return Response(
        content=bytes(m["file_data"]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@app.get("/admin/requests/{request_id}/messages/files/{attachment_id}")
def admin_download_message_file(
    request_id: int,
    attachment_id: int,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    with engine.connect() as conn:
        row = conn.execute(
            select(request_message_files)
            .where(
                request_message_files.c.id == attachment_id,
                request_message_files.c.request_id == request_id,
            )
        ).first()

    if not row:
        raise HTTPException(404, "Pièce jointe introuvable.")

    m = row._mapping
    from fastapi.responses import Response
    safe_name = (m["filename"] or f"piece_jointe_{attachment_id}.bin").replace('"', "_")
    return Response(
        content=bytes(m["file_data"]),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@app.get("/admin/invoices")
def admin_invoices(x_admin_key: str | None = Header(None)):
    require_admin(x_admin_key)
    with engine.connect() as conn:
        rows = conn.execute(
            select(invoices).order_by(invoices.c.id.desc())
        ).all()
    return [_invoice_dict(r._mapping) for r in rows]


@app.get("/admin/invoices/{invoice_id}/pdf")
def admin_invoice_pdf(invoice_id: int, x_admin_key: str | None = Header(None)):
    require_admin(x_admin_key)
    with engine.connect() as conn:
        row=conn.execute(select(invoices).where(invoices.c.id == invoice_id)).first()
    if not row:
        raise HTTPException(404, "Facture introuvable.")
    m=row._mapping
    return Response(
        content=bytes(m["pdf_data"]) if m.get("pdf_data") else _invoice_pdf_bytes(m),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{m["invoice_number"]}.pdf"'}
    )


@app.get("/invoices")
def client_invoices(authorization: str | None = Header(None)):
    client = bearer_client(authorization)
    with engine.connect() as conn:
        rows = conn.execute(
            select(invoices)
            .where(invoices.c.client_id == client["id"])
            .order_by(invoices.c.id.desc())
        ).all()
    return [_invoice_dict(r._mapping) for r in rows]


@app.get("/invoices/{invoice_id}/pdf")
def client_invoice_pdf(invoice_id: int, authorization: str | None = Header(None)):
    client = bearer_client(authorization)
    with engine.connect() as conn:
        row = conn.execute(
            select(invoices).where(
                invoices.c.id == invoice_id,
                invoices.c.client_id == client["id"],
            )
        ).first()
    if not row:
        raise HTTPException(404, "Facture introuvable.")
    m=row._mapping
    data=bytes(m["pdf_data"]) if m.get("pdf_data") else _invoice_pdf_bytes(m)
    filename=f"{m['invoice_number']}.pdf"
    return Response(
        content=data, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/requests/mine")
def client_list_requests(authorization: str | None = Header(None)):
    client = bearer_client(authorization)

    with engine.connect() as conn:
        rows = conn.execute(
            select(
                requests_table.c.id,
                requests_table.c.created_at,
                requests_table.c.vehicle_type,
                requests_table.c.vehicle_brand,
                requests_table.c.vehicle_model,
                requests_table.c.vehicle_year,
                requests_table.c.modifications,
                requests_table.c.original_filename,
                requests_table.c.status,
                requests_table.c.response_filename,
                requests_table.c.response_file_size,
                requests_table.c.responded_at,
            ).where(
                requests_table.c.client_id == client["id"]
            ).order_by(
                requests_table.c.id.desc()
            )
        ).all()

    result = []
    for row in rows:
        m = row._mapping
        result.append({
            "id": int(m["id"]),
            "created_at": m["created_at"],
            "vehicle_type": m["vehicle_type"] or "",
            "vehicle_brand": m["vehicle_brand"] or "",
            "vehicle_model": m["vehicle_model"] or "",
            "vehicle_year": m["vehicle_year"] or "",
            "modifications": [
                x for x in (m["modifications"] or "").splitlines() if x.strip()
            ],
            "original_filename": m["original_filename"] or "",
            "status": m["status"] or "new",
            "response_filename": m["response_filename"] or "",
            "response_file_size": int(m["response_file_size"] or 0),
            "response_available": bool(m["response_file_size"]),
            "responded_at": m["responded_at"] or "",
        })
    return result


@app.get("/admin/requests")
def admin_list_requests(x_admin_key: str | None = Header(None)):
    require_admin(x_admin_key)

    with engine.connect() as conn:
        rows = conn.execute(
            select(
                requests_table.c.id,
                requests_table.c.client_id,
                requests_table.c.created_at,
                requests_table.c.vehicle_type,
                requests_table.c.vehicle_brand,
                requests_table.c.vehicle_model,
                requests_table.c.vehicle_year,
                requests_table.c.engine,
                requests_table.c.original_power,
                requests_table.c.ecu,
                requests_table.c.read_write_tool,
                requests_table.c.read_write_tool_choice,
                requests_table.c.read_write_mode,
                requests_table.c.read_write_mode_choice,
                requests_table.c.modifications,
                requests_table.c.comment,
                requests_table.c.original_filename,
                requests_table.c.original_file_size,
                requests_table.c.status,
                requests_table.c.response_filename,
                requests_table.c.response_file_size,
                requests_table.c.responded_at,
                clients.c.username,
                clients.c.company,
                clients.c.last_name,
                clients.c.first_name,
                clients.c.email,
                clients.c.phone,
            ).join(
                clients,
                clients.c.id == requests_table.c.client_id
            ).order_by(requests_table.c.id.desc())
        ).all()

    result = []
    for row in rows:
        m = row._mapping
        result.append({
            "id": int(m["id"]),
            "client_id": int(m["client_id"]),
            "created_at": m["created_at"],
            "vehicle_type": m["vehicle_type"] or "",
            "vehicle_brand": m["vehicle_brand"] or "",
            "vehicle_model": m["vehicle_model"] or "",
            "vehicle_year": m["vehicle_year"] or "",
            "engine": m["engine"] or "",
            "original_power": m["original_power"] or "",
            "registration_or_vin": m["ecu"] or "",
            "read_write_tool": m["read_write_tool"] or "",
            "read_write_tool_choice": m["read_write_tool_choice"] or "",
            "read_write_mode": m["read_write_mode"] or "",
            "read_write_mode_choice": m["read_write_mode_choice"] or "",
            "modifications": [x for x in (m["modifications"] or "").splitlines() if x.strip()],
            "comment": m["comment"] or "",
            "original_filename": m["original_filename"] or "",
            "original_file_size": int(m["original_file_size"] or 0),
            "file_available": bool(m["original_file_size"]),
            "status": m["status"] or "new",
            "response_filename": m["response_filename"] or "",
            "response_file_size": int(m["response_file_size"] or 0),
            "response_available": bool(m["response_file_size"]),
            "responded_at": m["responded_at"] or "",
            "username": m["username"] or "",
            "company": m["company"] or "",
            "last_name": m["last_name"] or "",
            "first_name": m["first_name"] or "",
            "email": m["email"] or "",
            "phone": m["phone"] or "",
        })
    return result


@app.patch("/admin/requests/{request_id}/status")
def admin_update_request_status(
    request_id: int,
    data: RequestStatusUpdate,
    x_admin_key: str | None = Header(None),
):
    require_admin(x_admin_key)

    if data.status not in {"new", "opened", "processing", "processed"}:
        raise HTTPException(400, "Statut de demande invalide.")

    with engine.begin() as conn:
        row = conn.execute(
            select(requests_table.c.id).where(requests_table.c.id == request_id)
        ).first()
        if not row:
            raise HTTPException(404, "Demande introuvable.")

        conn.execute(
            update(requests_table)
            .where(requests_table.c.id == request_id)
            .values(status=data.status)
        )

    return {"ok": True, "status": data.status}


EU_VAT_COUNTRIES = {"AT","BE","BG","HR","CY","CZ","DE","DK","EE","EL","ES","FI","FR","GR","HU","IE","IT","LT","LU","LV","MT","NL","PL","PT","RO","SE","SI","SK"}

def _normalize_vat(value):
    return "".join(ch for ch in (value or "").upper() if ch.isalnum())

def _vies_validate(vat_number):
    vat=_normalize_vat(vat_number)
    if len(vat) < 4:
        return False
    country=vat[:2]
    number=vat[2:]
    if country == "GR": country="EL"
    if country not in EU_VAT_COUNTRIES:
        return False
    envelope=f"""<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="urn:ec.europa.eu:taxud:vies:services:checkVat:types"><soap:Body><tns:checkVat><tns:countryCode>{country}</tns:countryCode><tns:vatNumber>{number}</tns:vatNumber></tns:checkVat></soap:Body></soap:Envelope>"""
    try:
        r=requests.post("https://ec.europa.eu/taxation_customs/vies/services/checkVatService", data=envelope.encode("utf-8"), headers={"Content-Type":"text/xml; charset=utf-8"}, timeout=15)
        if r.status_code >= 400:
            raise RuntimeError("VIES indisponible")
        root=ET.fromstring(r.content)
        for elem in root.iter():
            if elem.tag.split("}")[-1] == "valid":
                return (elem.text or "").strip().lower() == "true"
        return False
    except Exception as exc:
        raise HTTPException(503, f"Validation TVA VIES temporairement indisponible : {exc}")

def _tax_for_client(client, ht_cents):
    country=(client.get("billing_country") or "FR").strip().upper()
    vat=_normalize_vat(client.get("vat_number") or "")
    if country == "GR": country="EL"
    reverse=False
    rate=float(INVOICE_VAT_RATE)
    if country in EU_VAT_COUNTRIES and country != "FR" and vat:
        if not vat.startswith(country):
            raise HTTPException(400, "Le numéro de TVA ne correspond pas au pays de facturation.")
        if _vies_validate(vat):
            reverse=True; rate=0.0
        else:
            raise HTTPException(400, "Numéro de TVA intracommunautaire invalide selon VIES.")
    vat_cents=int(round(ht_cents * rate / 100.0))
    return country, vat, rate, vat_cents, ht_cents + vat_cents, reverse

@app.post("/paypal/create-order/{package_tokens}")
def paypal_create_order(
    package_tokens: int,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)

    with engine.connect() as conn:
        package = conn.execute(
            select(token_packages).where(
                token_packages.c.tokens == package_tokens
            )
        ).first()

    if not package or not package._mapping["active"] or int(package._mapping["price_eur_cents"]) <= 0:
        raise HTTPException(400, "Ce pack de jetons n'est pas disponible.")

    cents = int(package._mapping["price_eur_cents"])  # HT catalogue
    country, vat_number, vat_rate, vat_cents, ttc_cents, reverse_charge = _tax_for_client(client, cents)
    price = ttc_cents / 100

    payload = {
        "intent": "CAPTURE",
        "purchase_units": [{
            "reference_id": f"client-{client['id']}-tokens-{package_tokens}",
            "description": f"HexTune Engineering - {package_tokens} jetons",
            "custom_id": str(client["id"]),
            "amount": {
                "currency_code": "EUR",
                "value": f"{price:.2f}",
            },
        }],
        "payment_source": {
            "paypal": {
                "experience_context": {
                    "return_url": f"{PUBLIC_BASE_URL}/paypal/return",
                    "cancel_url": f"{PUBLIC_BASE_URL}/paypal/cancel",
                    "user_action": "PAY_NOW",
                    "shipping_preference": "NO_SHIPPING",
                }
            }
        },
    }

    response = requests.post(
        PAYPAL_API_BASE + "/v2/checkout/orders",
        headers=paypal_headers(),
        json=payload,
        timeout=25,
    )

    if response.status_code >= 400:
        raise HTTPException(502, "PayPal a refusé la création de la commande.")

    data = response.json()
    order_id = data["id"]
    approve_url = None

    for link in data.get("links", []):
        if link.get("rel") in ("payer-action", "approve"):
            approve_url = link.get("href")
            break

    if not approve_url:
        raise HTTPException(502, "Lien de paiement PayPal introuvable.")

    now = now_iso()

    with engine.begin() as conn:
        conn.execute(
            insert(paypal_orders).values(
                order_id=order_id,
                client_id=client["id"],
                package_tokens=package_tokens,
                price_eur_cents=cents,
                amount_ht_cents=cents,
                vat_cents=vat_cents,
                amount_ttc_cents=ttc_cents,
                vat_rate=f"{vat_rate:.2f}",
                vat_reverse_charge=reverse_charge,
                billing_country=country,
                vat_number_snapshot=vat_number,
                status="CREATED",
                capture_id=None,
                credited=False,
                created_at=now,
                updated_at=now,
            )
        )

    return {
        "order_id": order_id,
        "approve_url": approve_url,
        "tokens": package_tokens,
        "price_eur_cents": cents,
        "amount_ht_cents": cents,
        "vat_cents": vat_cents,
        "amount_ttc_cents": ttc_cents,
        "vat_rate": vat_rate,
        "vat_reverse_charge": reverse_charge,
    }


@app.get("/paypal/return", response_class=HTMLResponse)
def paypal_return(token: str):
    order_id = token

    response = requests.post(
        PAYPAL_API_BASE + f"/v2/checkout/orders/{order_id}/capture",
        headers=paypal_headers(),
        json={},
        timeout=25,
    )

    if response.status_code >= 400:
        return HTMLResponse(
            """<html><body style="font-family:Segoe UI;background:#080808;color:white;text-align:center;padding:60px">
            <h1 style="color:#B2814E">HexTune Engineering</h1>
            <h2>Paiement non finalisé</h2>
            <p>Retournez dans l'application et réessayez.</p>
            </body></html>""",
            status_code=400
        )

    data = response.json()
    capture_id, capture_status = find_capture(data)

    if capture_status == "COMPLETED":
        credit_paypal_order(order_id, capture_id, capture_status)
        return HTMLResponse(
            """<html><body style="font-family:Segoe UI;background:#080808;color:white;text-align:center;padding:60px">
            <h1 style="color:#B2814E">HexTune Engineering</h1>
            <h2>Paiement confirmé</h2>
            <p>Vos jetons ont été crédités. Vous pouvez fermer cette fenêtre et revenir dans l'application.</p>
            </body></html>"""
        )

    return HTMLResponse(
        """<html><body style="font-family:Segoe UI;background:#080808;color:white;text-align:center;padding:60px">
        <h1 style="color:#B2814E">HexTune Engineering</h1>
        <h2>Paiement en cours de confirmation</h2>
        <p>Revenez dans l'application dans quelques instants.</p>
        </body></html>"""
    )


@app.get("/paypal/cancel", response_class=HTMLResponse)
def paypal_cancel():
    return HTMLResponse(
        """<html><body style="font-family:Segoe UI;background:#080808;color:white;text-align:center;padding:60px">
        <h1 style="color:#B2814E">HexTune Engineering</h1>
        <h2>Paiement annulé</h2>
        <p>Aucun jeton n'a été débité ou crédité.</p>
        </body></html>"""
    )


@app.get("/paypal/order-status/{order_id}")
def paypal_order_status(
    order_id: str,
    authorization: str | None = Header(None),
):
    client = bearer_client(authorization)

    with engine.connect() as conn:
        row = conn.execute(
            select(paypal_orders).where(
                paypal_orders.c.order_id == order_id,
                paypal_orders.c.client_id == client["id"],
            )
        ).first()

        client_row = conn.execute(
            select(clients.c.tokens).where(
                clients.c.id == client["id"]
            )
        ).first()

    if not row:
        raise HTTPException(404, "Commande PayPal introuvable.")

    return {
        "order_id": row._mapping["order_id"],
        "status": row._mapping["status"],
        "credited": bool(row._mapping["credited"]),
        "package_tokens": int(row._mapping["package_tokens"]),
        "tokens_balance": int(client_row._mapping["tokens"]),
    }


@app.post("/paypal/webhook")
async def paypal_webhook(request: Request):
    if not PAYPAL_WEBHOOK_ID:
        raise HTTPException(503, "PAYPAL_WEBHOOK_ID non configuré.")

    event = await request.json()
    headers = request.headers

    verify_payload = {
        "auth_algo": headers.get("paypal-auth-algo"),
        "cert_url": headers.get("paypal-cert-url"),
        "transmission_id": headers.get("paypal-transmission-id"),
        "transmission_sig": headers.get("paypal-transmission-sig"),
        "transmission_time": headers.get("paypal-transmission-time"),
        "webhook_id": PAYPAL_WEBHOOK_ID,
        "webhook_event": event,
    }

    verify = requests.post(
        PAYPAL_API_BASE + "/v1/notifications/verify-webhook-signature",
        headers=paypal_headers(),
        json=verify_payload,
        timeout=25,
    )

    if verify.status_code >= 400:
        raise HTTPException(400, "Signature PayPal non vérifiable.")

    if verify.json().get("verification_status") != "SUCCESS":
        raise HTTPException(400, "Webhook PayPal invalide.")

    if event.get("event_type") == "PAYMENT.CAPTURE.COMPLETED":
        resource = event.get("resource", {})
        capture_id = resource.get("id")
        order_id = (
            resource.get("supplementary_data", {})
            .get("related_ids", {})
            .get("order_id")
        )

        if order_id:
            credit_paypal_order(order_id, capture_id, "COMPLETED")

    return {"ok": True}
