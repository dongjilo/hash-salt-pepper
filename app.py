import hashlib
import os
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

# ----- config -----

PEPPER = os.getenv("PEPPER", "pastil-bukojuice-isaw")
SESSION_SECRET = os.getenv("SESSION_SECRET", "definitely-hinding-hindi-isang-sikreto")
NODE_ENV = os.getenv("NODE_ENV", "development")
SECURE_COOKIES = os.getenv("SECURE_COOKIES", "false").lower() in ("2", "true", "yes")
ENABLE_HSTS = NODE_ENV == "production"

serializer = URLSafeTimedSerializer(SESSION_SECRET)
templates = Jinja2Templates(directory="templates")


# ----- DB helpers -----
def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT UNIQUE,
               password_hash TEXT NOT NULL,
               salt TEXT NOT NULL
           )"""
    )
    conn.commit()
    conn.close()
    yield


app = FastAPI(lifespan=lifespan)


# ----- security headers middleware  -----
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    resp = await call_next(request)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    resp.headers.setdefault("Content-Security-Policy", csp)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    )
    resp.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    if ENABLE_HSTS:
        resp.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"
        )
    return resp


# ----- auth helpers -----
def hash_password_sha256(
    password: str, salt: str, pepper: str, iterations: int = 100_000
) -> str:
    value = (password + salt + pepper).encode("utf-8")
    h = hashlib.sha256(value).digest()
    for _ in range(iterations - 1):
        h = hashlib.sha256(h).digest()
    return h.hex()


def create_session_cookie(username: str) -> str:
    return serializer.dumps({"username": username})


def get_username_from_cookie(request: Request):
    cookie = request.cookies.get("session")
    if not cookie:
        return None
    try:
        data = serializer.loads(cookie, max_age=3600 * 24)
        return data.get("username")
    except BadSignature:
        return None


# ----- username sanitization -----
def sanitize_username_raw(raw: str, max_len: int = 30) -> str:
    if not raw:
        return ""
    s = raw.strip()
    s = re.sub(r"\s+", "_", s)
    s = re.sub(r"[^A-Za-z0-9_]", "", s)
    return s[:max_len]


# ----- routes -----
@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    username = get_username_from_cookie(request)
    return RedirectResponse("/dashboard") if username else RedirectResponse("/login")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    username = get_username_from_cookie(request)
    if not username:
        return RedirectResponse("/login")
    resp = templates.TemplateResponse(
        "dashboard.html", {"request": request, "username": username}
    )
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.get("/register", response_class=HTMLResponse)
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


def validate_password(password: str) -> bool:
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True


@app.post("/register", response_class=HTMLResponse)
def register_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
):
    if not validate_password(password):
        err = "Password must be at least 12 characters and include uppercase, lowercase, digit, and symbol."
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": err}
        )
    if password != confirm:
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": "Passwords do not match."}
        )

    clean = sanitize_username_raw(username)
    if not re.match(r"^[A-Za-z0-9_]{3,30}$", clean):
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": "Username must be 3-30 chars, alphanumeric or underscore.",
            },
        )

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (clean,))
    if cur.fetchone():
        conn.close()
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": f"Username '{clean}' is already taken."},
        )

    salt = secrets.token_hex(16)
    pw_hash = hash_password_sha256(password, salt, PEPPER)
    cur.execute(
        "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
        (clean, pw_hash, salt),
    )
    conn.commit()
    conn.close()

    info_msg = None
    if clean != username:
        info_msg = f"Account created as: {clean}"
    return templates.TemplateResponse(
        "login.html", {"request": request, "info": info_msg}
    )


@app.get("/api/username-available")
def username_available(q: str):
    clean = sanitize_username_raw(q)
    if not re.match(r"^[A-Za-z0-9_]{3,30}$", clean):
        return {"available": False, "clean": clean, "reason": "invalid"}
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (clean,))
    taken = bool(cur.fetchone())
    conn.close()
    return {
        "available": not taken,
        "clean": clean,
        "reason": "taken" if taken else "ok",
    }


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
def login_post(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    if not user:
        conn.close()
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid username or password."}
        )

    salt = user["salt"]
    stored_hash = user["password_hash"]
    if hash_password_sha256(password, salt, PEPPER) != stored_hash:
        conn.close()
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid username or password."}
        )

    session_cookie = create_session_cookie(username)
    resp = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        "session",
        session_cookie,
        httponly=True,
        secure=SECURE_COOKIES,
        samesite="lax",
        max_age=3600 * 24,
    )
    conn.close()
    return resp


@app.get("/logout")
def logout(response: Response):
    resp = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie("session")
    return resp
