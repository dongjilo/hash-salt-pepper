import hashlib
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

# Secret values for pepper and session signing
PEPPER = "pastil-bukojuice-isaw"
SESSION_SECRET = "definitely-hinding-hindi-isang-sikreto"

# Session serializer for secure cookie signing
serializer = URLSafeTimedSerializer(SESSION_SECRET)
# Jinja2 templates directory
templates = Jinja2Templates(directory="templates")

# Helper to get a database connection


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


# Lifespan event: creates users table on app startup


@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    yield
    # No shutdown tasks required


# Create FastAPI app with lifespan handler
app = FastAPI(lifespan=lifespan)

# Validate password complexity according to rules


def validate_password(password):
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


# Hash password using SHA-256, salt, pepper, and many iterations


def hash_password_sha256(password, salt, pepper, iterations=100_000):
    value = (password + salt + pepper).encode("utf-8")
    hash = hashlib.sha256(value).digest()
    for _ in range(iterations - 1):
        hash = hashlib.sha256(hash).digest()
    return hash.hex()


# Create a signed session cookie with username


def create_session_cookie(username):
    return serializer.dumps({"username": username})


# Retrieve username from session cookie (returns None if invalid/expired)


def get_username_from_cookie(request: Request):
    cookie = request.cookies.get("session")
    if not cookie:
        return None
    try:
        data = serializer.loads(cookie, max_age=3600 * 24)  # 24 hour session
        return data["username"]
    except BadSignature:
        return None


# Home/dashboard: only accessible when logged in


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    username = get_username_from_cookie(request)
    if username:
        return templates.TemplateResponse(
            "dashboard.html", {"request": request, "username": username}
        )
    return RedirectResponse("/login")


# Registration page (GET)


@app.get("/register", response_class=HTMLResponse)
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


# Registration logic (POST): validates, hashes, and stores user


@app.post("/register", response_class=HTMLResponse)
def register_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
):
    error = None
    # Enforce password rules
    if not validate_password(password):
        error = "Password must be at least 12 characters and include uppercase, lowercase, digit, and symbol."
    elif password != confirm:
        error = "Passwords do not match."
    else:
        conn = get_db()
        cur = conn.cursor()
        # Check if username already exists
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            error = "Username already exists."
        else:
            # Generate random salt for user
            salt = secrets.token_hex(16)
            # Hash password + salt + pepper
            password_hash = hash_password_sha256(password, salt, PEPPER)
            # Insert new user into DB
            cur.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt),
            )
            conn.commit()
            conn.close()
            # Redirect to login after successful registration
            return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        conn.close()
    # Render registration form with error message if validation fails
    return templates.TemplateResponse(
        "register.html", {"request": request, "error": error}
    )


# Login page (GET)


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


# Login logic (POST): verifies credentials and sets session


@app.post("/login", response_class=HTMLResponse)
def login_post(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    error = None
    conn = get_db()
    cur = conn.cursor()
    # Fetch user by username
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    if not user:
        error = "Invalid username or password."
    else:
        salt = user["salt"]
        stored_hash = user["password_hash"]
        # Hash input password with stored salt and pepper
        password_hash = hash_password_sha256(password, salt, PEPPER)
        if password_hash != stored_hash:
            error = "Invalid username or password."
        else:
            # Successful login: set signed session cookie and redirect to dashboard
            session_cookie = create_session_cookie(username)
            response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
            response.set_cookie(
                "session", session_cookie, httponly=True, max_age=3600 * 24
            )
            return response
    conn.close()
    # Render login form with error message if login fails
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": error}
    )


# Logout: removes session cookie and redirects to login


@app.get("/logout")
def logout(response: Response):
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("session")
    return response
