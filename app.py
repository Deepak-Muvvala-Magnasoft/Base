import os
import pandas as pd
import json
import smtplib
import traceback 
import re
from flask import g
from urllib.parse import urlencode
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, jsonify,
    make_response, session,  redirect, url_for, render_template
)
from urllib.parse import urlencode
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text
from sqlalchemy import func, inspect
from werkzeug.security import generate_password_hash
from flask import request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from config import (
    MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, MYSQL_PORT,
    SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_MAIL,
    VISITOR_BASE_URL, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
    SMTP_FROM_NAME
)
from flask_dance.contrib.google import make_google_blueprint, google
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest
from datetime import timedelta
from functools import wraps
from flask import session, request, redirect, url_for, flash, jsonify
from email.header import Header
from email.utils import formataddr


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "please-change-this-to-a-secure-random-value")

from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("FLASK_SECRET", "super_secret_key")
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config.update(
    SESSION_COOKIE_SECURE=True,        # Only send cookies over HTTPS
    SESSION_COOKIE_HTTPONLY=True,      # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE="None"     # Needed for cross-site requests
)
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=365)

# ----------------- Cookie-based auth helpers (paste after imports) -----------------
from flask import request as _request


def get_current_username():
    """Prefer ?user=... then fallback to cookie (for development)."""
    return request.args.get("user") or _request.cookies.get("auth_user")


def get_current_role():
    """Normalized role (lowercase). Prefer ?role=... then cookie."""
    return (request.args.get("role") or _request.cookies.get("auth_role") or "").strip().lower()


def current_role_authoritative():
    """
    Prefer DB-backed g.current_user.role (if loaded), otherwise prefer request.args role,
    then fallback to cookie. Returns lowercase.
    """
    db_user = getattr(g, "current_user", None)
    if db_user and getattr(db_user, "role", None):
        return (db_user.role or "").strip().lower()
    return (request.args.get("role") or _request.cookies.get("auth_role") or "").strip().lower()


def get_role_display():
    """Role display value (title-case) from request args or cookie."""
    rd = request.args.get("role_display") or _request.cookies.get("auth_role_display") or ""
    return rd


def get_selected_project():
    return _request.cookies.get("selected_project") or ""



def clear_auth_cookies(response):
    # clear with explicit path and no domain so it matches set cookies
    response.delete_cookie("auth_user", path="/")
    response.delete_cookie("auth_role", path="/")
    response.delete_cookie("auth_role_display", path="/")
    response.delete_cookie("selected_project", path="/")
    return response

def set_auth_cookies(response, username, role="", role_display="", selected_project=""):
    # Detect whether request came over HTTPS (directly or via proxy)
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "") or ""
    secure_flag = forwarded_proto.lower() == "https" or request.is_secure

    max_age = 365 * 24 * 3600   # 1 year

    # Use SameSite=None when cookie will be Secure (required by browsers).
    # For non-HTTPS/dev, keep Lax so browser behavior is safe for local testing.
    samesite_val = "None" if secure_flag else "Lax"

    cookie_opts = {
        "httponly": True,
        "samesite": samesite_val,
        "path": "/",
        "max_age": max_age
    }

    # host-only cookie: do NOT set domain
    response.set_cookie("auth_user", username or "", secure=secure_flag, **cookie_opts)
    response.set_cookie("auth_role", (role or "").strip().lower(), secure=secure_flag, **cookie_opts)
    response.set_cookie("auth_role_display", role_display or "", secure=secure_flag, **cookie_opts)
    response.set_cookie("selected_project", selected_project or "", secure=secure_flag, **cookie_opts)
    return response


def _is_strictly_authenticated():
    """
    Strict auth check used for protected pages:
      - Accept g.current_user (DB-backed), OR
      - Accept server session username, OR
      - Accept stored cookie auth_user (host-only cookie)
    IMPORTANT: do NOT accept login via request.args here (prevents ?user=... URL forging).
    """
    # prefer DB-loaded user
    if getattr(g, "current_user", None):
        return True

    # server-side session fallback
    if session.get("username"):
        return True

    # cookie fallback: only accept browser-stored auth_user (not query args)
    if request.cookies.get("auth_user"):
        return True

    return False


def login_required_strict(f):
    """Decorator: block access unless strictly authenticated (no ?user query allowed)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if _is_strictly_authenticated():
            return f(*args, **kwargs)

        # AJAX callers: return JSON 401
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        # normal browser: redirect to login (optionally include next)
        next_url = request.path
        flash("Please login to access that page", "warning")
        return redirect(url_for("login", next=next_url))
    return decorated


def role_required(role_name):
    """
    Decorator: require a normalized role (e.g., 'security', 'admin').
    Uses strict auth first then checks role resolved from DB/session/cookie.
    """
    role_name = (role_name or "").strip().lower()
    def _decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not _is_strictly_authenticated():
                if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify({"success": False, "message": "Unauthorized"}), 401
                flash("Please login to access that page", "warning")
                return redirect(url_for("login", next=request.path))

            # resolve authoritative role: prefer DB user -> session -> cookie
            db_user = getattr(g, "current_user", None)
            if db_user and getattr(db_user, "role", None):
                user_role = (db_user.role or "").strip().lower()
            elif session.get("role"):
                user_role = (session.get("role") or "").strip().lower()
            else:
                user_role = (request.cookies.get("auth_role") or "").strip().lower()

            if user_role != role_name:
                # Forbidden for wrong role
                if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify({"success": False, "message": "Forbidden"}), 403
                flash("Insufficient permissions", "danger")
                return redirect(url_for("landing_page"))
            return f(*args, **kwargs)
        return decorated
    return _decorator


# -----------------------------------------------------------------------------------


@app.before_request
def load_current_user():
    """
    Optional: load a DB-backed User into `g.current_user` when a username cookie exists.
    This lets templates / code use g.current_user safely (avoids trusting cookies only).
    """
    uname = get_current_username()  # returns None or the query/cookie value
    g.current_user = None
    if uname:
        try:
            g.current_user = User.query.filter_by(username=uname).first()
        except Exception:
            # swallow DB errors here — injector will still work using query params
            g.current_user = None




@app.context_processor
def inject_user_role():
    # Prefer server-side session first (most authoritative if present)
    sess_user = session.get("username")
    sess_role = session.get("role")
    sess_role_display = session.get("role_display")

    # prefer DB-loaded user (safer) then fall back to session -> request.args -> cookies
    db_user = getattr(g, "current_user", None)

    username = None
    if db_user and getattr(db_user, "username", None):
        username = db_user.username
    elif sess_user:
        username = sess_user
    else:
        username = request.args.get("user") or get_current_username() or None

    is_authenticated = bool(username)

    # Role resolution: DB-backed role if present -> session -> query args -> cookie
    if db_user and getattr(db_user, "role", None):
        role_raw = (db_user.role or "").strip()
    elif sess_role:
        role_raw = sess_role
    else:
        role_raw = (request.args.get("role") or get_current_role() or "").strip()

    role_norm = role_raw.lower()
    role_display = (request.args.get("role_display") or sess_role_display or get_role_display() or (role_raw.title() if role_raw else ""))

    selected_project = get_selected_project() or ""

    # Build auth_qs...
    auth_params = {}
    if username:
        auth_params["user"] = username
    if role_norm:
        auth_params["role"] = role_norm
    if role_display:
        auth_params["role_display"] = role_display
    auth_qs = ("?" + urlencode(auth_params)) if auth_params else ""
    auth_params_json = json.dumps(auth_params or {})

    return {
        "current_user": username,
        "is_authenticated": is_authenticated,
        "user_role": role_norm,
        "role_display": role_display,
        "is_superadmin": role_norm == "super admin",
        "selected_project": selected_project,
        "auth_qs": auth_qs,
        "auth_params": auth_params,
        "auth_params_json": auth_params_json,
    }




# Add Google OAuth config
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For HTTP (development only)
# existing imports include: from flask_dance.contrib.google import make_google_blueprint, google
google_bp = make_google_blueprint(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    # force the exact HTTPS redirect that you have added to Google Console
    redirect_url="https://myportal.magnasoft.com/login/google/authorized",
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

@app.route('/change_password', methods=['POST'])
def change_password():
    try:
        session_cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
        app.logger.info(
            "DBG CHANGE_PW: remote=%s, xff=%s, proto=%s, host=%s, scheme=%s, ua=%s, cookies=%s, session_cookie=%s",
            request.remote_addr,
            request.headers.get('X-Forwarded-For'),
            request.headers.get('X-Forwarded-Proto'),
            request.host,
            request.scheme,
            request.headers.get('User-Agent'),
            dict(request.cookies),
            request.cookies.get(session_cookie_name)
        )

        # Try multiple auth sources: session, flask-login current_user, then auth_user cookie
        username = session.get('username')

        # If you're using flask-login, prefer that as authoritative
        try:
            from flask_login import current_user, login_user
            if not username and getattr(current_user, "is_authenticated", False):
                # current_user may be an object with get_id or username attribute
                uid = getattr(current_user, "get_id", None)
                if callable(uid):
                    username = uid()
                else:
                    username = getattr(current_user, "username", username)
        except Exception:
            # flask-login not installed/used — ignore
            current_user = None
            login_user = None

        # Fallback to the auth_user cookie (useful when session was lost but cookie exists)
        if not username:
            cookie_user = request.cookies.get('auth_user')
            if cookie_user:
                # Attempt to find user in DB; if found, restore session and (optionally) login_user
                user = User.query.filter_by(username=cookie_user).first()
                if user:
                    username = user.username
                    # re-create server-side session entry so subsequent checks work
                    session['username'] = username
                    session.permanent = True
                    # If flask-login is available, re-login silently so current_user works
                    try:
                        if login_user:
                            login_user(user)
                    except Exception:
                        app.logger.debug("login_user() failed during session restore", exc_info=True)

        # If still no username, unauthenticated
        if not username:
            app.logger.info("CHANGE_PW: unauthenticated request; cookies=%s", dict(request.cookies))
            return jsonify({"success": False, "message": "Not authenticated"}), 401

        # --- proceed with password change logic ---
        data = request.get_json(silent=True) or {}
        new_password = (data.get('new_password') or "").strip()
        if not new_password or len(new_password) < 8:
            return jsonify({"success": False, "message": "Password must be at least 8 characters"}), 400

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        # set hashed password
        user.password = generate_password_hash(new_password)
        # optional: user.password_last_changed = datetime.utcnow()
        db.session.commit()
        app.logger.info("Password changed for user=%s (via change_password route)", username)

        return jsonify({"success": True, "message": "Password changed successfully"}), 200

    except Exception as e:
        # Log full stack trace to server logs
        app.logger.exception("Error changing password (full stack):")

        # Return the exception message in the JSON response for debugging (remove in production)
        return jsonify({"success": False, "message": "Server error: " + str(e)}), 500


# --- SQLAlchemy / MySQL ---
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


@app.route("/__debug_oauth")
def debug_oauth():
    return jsonify({
        "url_for_google_authorized": url_for("google.authorized", _external=True),
        "request_host": request.host,
        "headers": {
            "Host": request.headers.get("Host"),
            "X-Forwarded-Proto": request.headers.get("X-Forwarded-Proto"),
            "X-Forwarded-For": request.headers.get("X-Forwarded-For")
        }
    })

# add somewhere for debugging (temporary)
@app.route("/debug_cookies")
def debug_cookies():
    return jsonify({
      "cookie_sent_by_browser": {k: request.cookies.get(k) for k in ["auth_user","auth_role","auth_role_display","selected_project"]},
      "headers": { "X-Forwarded-Proto": request.headers.get("X-Forwarded-Proto"), "Host": request.headers.get("Host") }
    })

@app.route('/visitor', methods=['GET', 'POST'])
def visitor_qr():
    # if POST, you can reuse your existing add_visitor logic
    if request.method == 'POST':
        # quick reuse: delegate to same function that handles add_visitor
        return add_visitor()   # only if add_visitor() returns a response
    # GET: render the same template but hide navbar
    return render_template('visitor_form.html', visitor_only=True)


# --- Models ---
class Visitor(db.Model):
    __tablename__ = "visitors"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(200))
    company = db.Column(db.String(200))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(200))
    location = db.Column(db.String(100))
    badge_number = db.Column(db.String(50), nullable=True)
    idType = db.Column(db.String(100))
    idNumber = db.Column(db.String(200))
    purpose = db.Column(db.String(200))
    otherPurpose = db.Column(db.Text)
    contact_person = db.Column(db.String(200))
    contact_email = db.Column(db.String(200))
    notes = db.Column(db.Text)
    dept = db.Column(db.String(100), nullable=True)
    items = db.Column(db.Text)        # store as JSON string
    otherItems = db.Column(db.String(200))
    check_in = db.Column(db.DateTime, nullable=True)
    check_out = db.Column(db.DateTime, nullable=True)
    remarks = db.Column(db.Text)
    verified = db.Column(db.Boolean, default=False)
    approved = db.Column(db.Boolean, nullable=True)
    electronics_approved = db.Column(db.Boolean, nullable=True)
    created_at = db.Column(db.DateTime, default=func.now())
    photo_filename = db.Column(db.String(255), nullable=True)
    photo_mime = db.Column(db.String(100), nullable=True)
    photo_data = db.Column(db.LargeBinary, nullable=True)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)


# --- Utilities ---
def safe_colname(col: str) -> str:
    """
    Sanitize a column name for MySQL identifiers.
    Converts spaces/dashes to underscores and strips weird chars.
    """
    name = col.strip().replace(" ", "_").replace("-", "_")
    # optional: keep only alnum + underscore
    import re
    name = re.sub(r"[^0-9a-zA-Z_]", "", name)
    if not name:
        name = "col"
    # avoid starting with digit
    if name[0].isdigit():
        name = f"c_{name}"
    return name


def safe_table_name(name: str) -> str:
    """Sanitize project name for a MySQL table name."""
    import re
    tbl = name.strip().replace(" ", "_").replace("-", "_")
    tbl = re.sub(r"[^0-9a-zA-Z_]", "", tbl)
    if tbl and tbl[0].isdigit():
        tbl = f"t_{tbl}"
    return tbl.lower()


def ensure_columns_exist(new_columns):
    """
    ALTER TABLE excel_data ADD COLUMN `<col>` TEXT for any missing  columns.
    """
    inspector = inspect(db.engine)
    existing = {c["name"] for c in inspector.get_columns("excel_data")}
    for col in new_columns:
        c = safe_colname(col)
        if c not in existing and c not in {"id", "project_name", "uploaded_by", "upload_time", "file_name"}:
            db.session.execute(text(f"ALTER TABLE `excel_data` ADD COLUMN `{c}` TEXT"))
            db.session.commit()
            existing.add(c)


# --- NEW HELPER: verify_password (supports hashed OR plaintext stored passwords) ---
def verify_password(stored_password: str, provided_password: str) -> bool:
    """
    Return True if provided_password matches stored_password.
    Supports:
      1) werkzeug hashed passwords (check_password_hash)
      2) legacy plaintext passwords (direct equality) — fallback
    """
    if not stored_password:
        return False

    # 1) Try hashed comparison (works for pbkdf2/sha/etc.)
    try:
        if check_password_hash(stored_password, provided_password):
            return True
    except Exception:
        # If stored_password isn't a valid hash format, check_password_hash
        # may raise; ignore and try plaintext fallback below.
        pass

    # 2) Fallback to plaintext match (handles legacy DB rows)
    try:
        if stored_password == provided_password:
            return True
    except Exception:
        pass

    return False
# -------------------------------------------------------------------------------


# --- Authorization helpers (place near other utilities) ---
ELECTRONICS_KEYWORDS = {
    "laptop", "pendrive", "usb", "usb-drive", "usb drive",
    "ipad", "tablet", "mobile", "phone", "charger", "powerbank",
    "notebook", "macbook"
}

def visitor_has_electronics(visitor):
    """Return True if visitor.items (or otherItems) contains an electronics keyword."""
    try:
        items_src = getattr(visitor, "items", None) or ""
        other_text = getattr(visitor, "otherItems", "") or ""
        items_list = []

        # if stored as JSON string
        if isinstance(items_src, str):
            try:
                parsed = json.loads(items_src)
                if isinstance(parsed, (list, tuple, set)):
                    items_list = [str(x).strip() for x in parsed if x]
                else:
                    items_list = [str(parsed).strip()] if parsed else []
            except Exception:
                # fallback: comma-separated or bracketed string
                cleaned = items_src.strip().strip("[]").replace('"', "").replace("'", "")
                items_list = [s.strip() for s in cleaned.split(",") if s.strip()]
        elif isinstance(items_src, (list, tuple, set)):
            items_list = [str(x).strip() for x in items_src if x]

        if other_text:
            items_list.append(str(other_text).strip())

        items_lower = [it.lower() for it in items_list if it]
        for it in items_lower:
            for kw in ELECTRONICS_KEYWORDS:
                if kw in it:
                    return True
    except Exception:
        app.logger.exception("visitor_has_electronics() failed for id=%s", getattr(visitor, "id", None))
    return False


def visitor_allowed_to_checkin(visitor):
    """
    Return (allowed:bool, reason:str_or_None).
    Rules:
      - department approval (visitor.approved) must be True
      - if visitor carries electronics, visitor.electronics_approved must be True
    """
    if not visitor:
        return False, "Visitor not found"

    # department approval required
    if visitor.approved is not True:
        return False, "Awaiting department approval or approval denied"

    # electronics require IT approval
    if visitor_has_electronics(visitor) and visitor.electronics_approved is not True:
        return False, "Awaiting IT approval (electronics)"

    return True, None

@app.route("/")
def home():
    """
    Redirect anonymous users to login.
    Authenticated users see the landing page.
    """
    username = get_current_username()
    app.logger.info("✔ / route HIT — remote=%s, user=%s, args=%s",
                    request.remote_addr, username, request.args)

    if not username:
        return redirect(url_for("login"))

    # prevent caching so auth changes are reflected immediately in browser
    resp = make_response(render_template("landing.html", user=username))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/landing")
def landing_page():
    """
    Always render landing.html (no redirect). Add no-cache headers so browser shows
    what server returns and doesn't reuse any cached redirect.
    """
    username = get_current_username()  # may be None
    resp = make_response(render_template("landing.html", user=username))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/google")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))  # Redirect to Google OAuth

    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        user_info = resp.json()
        email = user_info["email"]

        # ✅ Check if user exists in DB, else create
        user = User.query.filter_by(username=email).first()
        if not user:
            user = User(username=email, password="", role="User")
            db.session.add(user)
            db.session.commit()

        # Use query param redirect (no cookie dependency)
        role_norm = (user.role or "").strip().lower()
        role_display = (user.role or "").strip()

        params = {"user": email, "role": role_norm, "role_display": role_display}
        return redirect(url_for("landing_page") + "?" + urlencode(params))

    return "Google login failed!", 400


# ---------- LOGIN (keep or replace existing login success path) ----------


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # authenticate user (your existing logic)
        user = User.query.filter_by(username=username).first() if username else None

        if user and verify_password(user.password, password):
            role_norm = (user.role or "").strip().lower()
            role_display = (user.role or "").strip()

            # session fallback
            session.permanent = True
            session["username"] = user.username
            session["role"] = role_norm
            session["role_display"] = role_display

            # prepare redirect and set cookies (assign returned response)
            params = {"user": user.username, "role": session["role"], "role_display": session["role_display"]}
            resp = redirect(url_for("landing_page") + "?" + urlencode(params))

            # ensure cookies are attached to the response object we return
            resp = set_auth_cookies(
                resp,
                username=user.username,
                role=role_norm,
                role_display=role_display,
                selected_project=""
            )

            return resp

        else:
            # failed login -> flash an error and redirect back to login page
            return redirect(url_for("login", error="❌ Invalid username or password!"))

    # GET -> render the login page (always returns a template response)
    return render_template("login.html")



# ---------- LOGOUT (partial logout) ----------
@app.route("/logout")
def logout():
    """
    Minimal / logout behavior: DO NOT delete any auth cookies.
    This keeps both auth_user and auth_role intact so the header continues
    to show the username and role until the user clicks Exit (which does a full sign-out).
    """
    
    return redirect(url_for("landing_page"))

@app.route("/exit")
def exit_app():
    session.clear()
    resp = redirect(url_for("login"))
    clear_auth_cookies(resp)
    return resp

@app.route('/vms_demo')
def vms_demo():
    return render_template('vms.html')


@app.route("/vms")
@login_required_strict
def vms():
    app.logger.info("✔ /vms route HIT — remote=%s, args=%s", request.remote_addr, request.args)
    return render_template('visitor_form.html', user=get_current_username())


@app.route("/add_visitor", methods=["POST"])
def add_visitor():
    form = request.form
    visitor_only = form.get("visitor_only")
    dept = form.get('dept')
    location = form.get('location')
    selected_contact_person = form.get('contact_person')

    # --- normalize items submitted from the form ---
    items_raw = request.form.getlist("items") or request.form.getlist("items[]") or []
    other_text = (form.get("otherItems") or "").strip()

    # Build normalized list: replace literal "Other" with typed text (if present)
    normalized_items = []
    for it in items_raw:
        if not it:
            continue
        if it == "Other":
            if other_text:
                normalized_items.append(other_text)
            # if no typed text, skip the literal "Other"
        else:
            normalized_items.append(it)

    # If user typed something in otherItems but did not check the 'Other' box,
    if other_text and other_text not in normalized_items:
        normalized_items.append(other_text)

    # ------------------ NEW: DEDUPE normalized_items (preserve order, case-insensitive) ------------------
    seen = set()
    normalized_items_unique = []
    for it in normalized_items:
        if not it:
            continue
        val = str(it).strip()
        key = val.lower()
        if key not in seen:
            normalized_items_unique.append(val)
            seen.add(key)
    # use the deduped list from here on
    normalized_items = normalized_items_unique
    # -----------------------------------------------------------------------------------------------------

    # Finally create visitor record (store items as JSON string; keep otherItems too)
    visitor = Visitor(
        name=form.get("name"),
        company=form.get("company"),
        phone=form.get("phone"),
        email=form.get("email"),
        location=form.get("location"),
        idType=form.get("idType"),
        idNumber=form.get("idNumber"),
        purpose=form.get("purpose"),
        otherPurpose=form.get("otherPurpose"),
        contact_person=form.get("contact_person"),
        contact_email=form.get("contact_email"),
        notes=form.get("notes"),
        dept = form.get("dept"),
        items=json.dumps(normalized_items),
        otherItems=other_text,
        check_in=None,
        check_out=None,
        remarks=None,
        verified=False,
        approved=None,
        electronics_approved=None   
    )

    # helper to decide JSON vs redirect response
    def respond_success(msg, visitor_id=None):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or "application/json" in request.headers.get("Accept", ""):
            payload = {"success": True, "message": msg}
            if visitor_id:
                payload["visitor_id"] = visitor_id
            return jsonify(payload), 200
        # non-AJAX: original behaviour
        if visitor_only:
            return redirect(url_for("visitor_qr", alert=msg, alert_cat="success"))
        return redirect(url_for("vms", alert=msg, alert_cat="success"))

    def respond_error(msg, status=500):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or "application/json" in request.headers.get("Accept", ""):
            return jsonify({"success": False, "message": msg}), status
        if visitor_only:
            return redirect(url_for("visitor_qr", alert=msg, alert_cat="danger"))
        return redirect(url_for("vms", alert=msg, alert_cat="danger"))

    # handle uploaded photo (optional)
    photo_file = request.files.get('photo')
    if photo_file and photo_file.filename:
        # sanitize filename
        safe_name = secure_filename(photo_file.filename)
        visitor.photo_filename = safe_name
        visitor.photo_mime = photo_file.mimetype or 'image/jpeg'
        # read bytes
        visitor.photo_data = photo_file.read()

    # --- save to MySQL using SQLAlchemy (safe commit with rollback) ---
    try:
        db.session.add(visitor)
        db.session.commit()
        new_id = visitor.id
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.exception("Failed to save visitor to DB")
        return respond_error(f"Failed saving visitor (DB error): {e.__class__.__name__}", 500)

    # if saved — attempt department emails but never rollback on email failure
    try:
        v = Visitor.query.get(new_id)  # fresh instance from DB

        if selected_contact_person:
            # single selected contact (assumes contact_person/contact_email already set on form)
            try:
                send_email_to_contact(v, visitor_id=new_id)
            except Exception:
                app.logger.exception("Failed to send contact-person email for visitor %s", new_id)
        else:
            # find all contacts for the requested dept/location and email them
            users = db.session.execute(
                text("SELECT username, email FROM contact_person WHERE dept = :dept AND location = :location"),
                {"dept": dept, "location": location}
            ).mappings().all()

            for user in users:
                # DO NOT persist these changes to DB; just set on the `v` object for email context
                orig_contact_person = v.contact_person
                orig_contact_email = v.contact_email
                try:
                    v.contact_person = user["username"]
                    v.contact_email = user["email"]
                    send_email_to_contact(v, visitor_id=new_id)
                except Exception:
                    app.logger.exception("Failed to send contact-person email to %s for visitor %s", user.get("email"), new_id)
                finally:
                    # restore original contact fields on `v` object (avoid accidental overwrites)
                    v.contact_person = orig_contact_person
                    v.contact_email = orig_contact_email

    except Exception as e:
        app.logger.exception("Email sending failed after saving visitor (department emails)")
        # still return success to user (visitor saved), but include warning in message
        return respond_success(f"Visitor saved but department email failed: {str(e)}", visitor_id=new_id)

    # --- send separate IT approval email if visitor carried electronics ---
    try:
        # electronics keywords (extend if needed)
        electronics_keywords = {
            "laptop", "pendrive", "usb", "usb-drive", "usb drive",
            "ipad", "tablet", "mobile", "phone", "charger", "powerbank", "notebook", "macbook"
        }

        # we already built normalized_items above; fall back to parsing DB value if not available
        items_to_check = normalized_items
        if not items_to_check:
            # robust fallback: try parse from DB row
            try:
                if isinstance(v.items, str):
                    items_to_check = json.loads(v.items)
                elif isinstance(v.items, (list, tuple, set)):
                    items_to_check = list(v.items)
            except Exception:
                s = (v.items or "")
                s = s.strip().strip("[]").replace('"', "").replace("'", "")
                items_to_check = [x.strip() for x in s.split(",") if x.strip()]

        items_lower = [str(it).strip().lower() for it in (items_to_check or []) if it and str(it).strip()]
        has_electronics = any(any(k in it for k in electronics_keywords) for it in items_lower)

        if has_electronics:
            # query IT contacts for the same location
            it_users = db.session.execute(
                text("SELECT username, email FROM contact_person WHERE dept = :dept AND location = :location"),
                {"dept": "IT", "location": location}
            ).mappings().all()

            # send IT email(s) — do not persist contact_person on v (we only set temporarily)
            for it_user in it_users:
                orig_contact_person = v.contact_person
                orig_contact_email = v.contact_email
                try:
                    v.contact_person = it_user["username"]
                    v.contact_email = it_user["email"]
                    send_email_to_it(v, it_user["username"], it_user["email"], visitor_id=new_id)
                except Exception:
                    app.logger.exception("Failed sending IT email for visitor %s to %s", new_id, it_user.get("email"))
                finally:
                    v.contact_person = orig_contact_person
                    v.contact_email = orig_contact_email

    except Exception:
        app.logger.exception("Error while processing IT approval flow")

    # all good
    return respond_success("Visitor saved and email(s) sent successfully!", visitor_id=new_id)


@app.route('/visitor_photo/<int:visitor_id>')
def visitor_photo(visitor_id):
    v = Visitor.query.get(visitor_id)
    if not v or not v.photo_data:
        return '', 404
    resp = make_response(v.photo_data)
    resp.headers.set('Content-Type', v.photo_mime or 'image/jpeg')
    # inline display
    resp.headers.set('Content-Disposition', 'inline', filename=v.photo_filename or f'photo_{visitor_id}.jpg')
    return resp


def send_email_to_it(visitor_obj_or_dict, contact_name, contact_email, visitor_id=None):
    """
    Send a separate approval email to IT contacts when visitor carries electronics.
    Adds only electronic item names into the email (other items are omitted).
    """
    import json
    import html
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    import smtplib

    # same visitor/dict handling like send_email_to_contact
    if hasattr(visitor_obj_or_dict, "__table__"):
        v = visitor_obj_or_dict
        vid = visitor_id or v.id
        name = getattr(v, "name", "") or ""
        company = getattr(v, "company", "") or ""
        phone = getattr(v, "phone", "") or ""
        purpose = getattr(v, "purpose") or ""
        location = getattr(v, "location") or ""
        items_field = getattr(v, "items_with_other", None) or getattr(v, "items", None)
        other_text_field = getattr(v, "otherItems", None)
    else:
        v = visitor_obj_or_dict
        vid = visitor_id or v.get("id")
        name = v.get("name") or ""
        company = v.get("company") or ""
        phone = v.get("phone") or ""
        purpose = v.get("purpose") or ""
        location = v.get("location") or ""
        items_field = v.get("items_with_other") or v.get("items")
        other_text_field = v.get("otherItems")

    # Build items list robustly (preserve order, dedupe case-insensitively)
    items_list = []

    def extend_from(src):
        if not src:
            return
        # list/tuple/set
        if isinstance(src, (list, tuple, set)):
            for x in src:
                if x is not None:
                    items_list.append(str(x).strip())
            return
        # try JSON parse if string
        if isinstance(src, str):
            s = src.strip()
            try:
                parsed = json.loads(s)
                if isinstance(parsed, (list, tuple, set)):
                    for x in parsed:
                        if x is not None:
                            items_list.append(str(x).strip())
                    return
            except Exception:
                # fallback: treat as comma-separated string
                cleaned = s.strip("[]").replace('"', "").replace("'", "")
                for part in (p.strip() for p in cleaned.split(",") if p.strip()):
                    items_list.append(part)
                return
        # otherwise coerce to string
        items_list.append(str(src).strip())

    # preferred: server-provided cleaned list, else raw items, then otherItems
    extend_from(items_field)
    if other_text_field:
        extend_from(other_text_field)

    # dedupe case-insensitively while preserving order
    seen = set()
    items_clean = []
    for it in items_list:
        if not it:
            continue
        key = it.lower()
        if key not in seen:
            items_clean.append(it)
            seen.add(key)

    # --- FILTER: keep only electronic items for IT email ---
    electronics_keywords = {
        "laptop", "pendrive", "usb", "usb-drive", "usb drive",
        "ipad", "tablet", "mobile", "phone", "charger", "powerbank",
        "notebook", "macbook"
    }
    items_electronic = [it for it in items_clean if any(k in it.lower() for k in electronics_keywords)]
    items_line = ", ".join(items_electronic) if items_electronic else "—"
    # ----------------------------------------------------------------

    # build approve/decline links
    try:
        base = VISITOR_BASE_URL or request.url_root.rstrip('/')
    except Exception:
        base = VISITOR_BASE_URL or "http://myportal.magnasoft.com"
    base = base.rstrip('/')

    approve_link = f"{base}/approve_electronics/{vid}"
    decline_link = f"{base}/decline_electronics/{vid}"

    dept = ""
    try:
        # if visitor is SQLAlchemy object
        dept = (getattr(v, "dept", None) or getattr(v, "department", None) or "") if hasattr(v, "__table__") else ""
    except Exception:
        dept = ""

    if not dept and isinstance(v, dict):
        dept = v.get("dept") or v.get("department") or ""

    dept = (dept or "").strip()

    dept_value = ""
    try:
        if hasattr(v, "__table__"):
            dept_value = (getattr(v, "dept", None) or "").strip()
        else:
            dept_value = (v.get("dept") or "").strip()
    except Exception:
        dept_value = ""

    # fallback: if still empty, try contact_person or contact_name
    if not dept_value:
        dept_value = (getattr(v, "contact_person", None) or v.get("contact_person") or "").strip() or ""

    # process list-style values and normalize display
    if dept_value:
        parts = [p.strip() for p in re.split(r'[;,|]', dept_value) if p.strip()]
        normalized = []
        for p in parts:
            normalized.append(p.upper() if len(p) <= 3 else p.title())
        dept_display = ", ".join(normalized)
    else:
          if dept_value:
    # ... existing normalization ...
            dept_display = ", ".join(normalized)
          else:
            dept_display = "IT" 

    # sanitize visitor name
    safe_name = " ".join((name or "Unknown").split())

    subject = f"IT Approval Required for {dept_display} — Visitor : {safe_name} carrying electronic item(s)"
# -------------------------------------------------------------------------------

    # ----- end replacement -----

    body = f"""
    <html><body>
      <p>Hello {html.escape(str(contact_name or ''))},</p>
      <p>A visitor has registered and marked that they are carrying electronic item(s):</p>

      <ul>
        <li><strong>Name:</strong> {html.escape(str(name))}</li>
        <li><strong>Company:</strong> {html.escape(str(company))}</li>
        <li><strong>Phone:</strong> {html.escape(str(phone))}</li>
        <li><strong>Purpose:</strong> {html.escape(str(purpose))}</li>
        <li><strong>Location:</strong> {html.escape(str(location))}</li>
      </ul>

      <p>Please approve/decline the electronics request:</p>
      <ul>
        <li><strong>Items:</strong> {html.escape(items_line)}</li>
      </ul> 
      <p>
        <a href="{approve_link}">✅ Approve </a>&nbsp;&nbsp;
        <a href="{decline_link}">❌ Decline</a>
      </p>
      <p>Regards,<br>VMS System</p>
    </body></html>
    """

    message = MIMEMultipart()
    message["From"] = formataddr((str(Header(SMTP_FROM_NAME, 'utf-8')), SMTP_MAIL))
    message["To"] = contact_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(message["From"], contact_email, message.as_string())
    except Exception:
        app.logger.exception("Failed to send IT approval email to %s for visitor %s", contact_email, vid)
        # keep behavior consistent: swallow exception (caller handles logging/flow)
        return False

    return True


def send_email_to_contact(visitor_obj_or_dict, visitor_id=None):
    # Accept either: SQLAlchemy Visitor instance OR dict (for compatibility)
    if hasattr(visitor_obj_or_dict, "__table__"):  # SQLAlchemy model
        v = visitor_obj_or_dict
        vid = visitor_id or v.id
        contact_email = v.contact_email
        contact_name = v.contact_person
        name = v.name
        company = v.company
        phone = v.phone
        purpose = v.purpose
    else:
        v = visitor_obj_or_dict
        vid = visitor_id or v.get("id") or v.get("_id")
        contact_email = v.get("contact_email")
        contact_name = v.get("contact_person")
        name = v.get("name")
        company = v.get("company")
        phone = v.get("phone")
        purpose = v.get("purpose")

    # decide base URL for links: prefer config, otherwise use current request host
    try:
        base = VISITOR_BASE_URL or request.url_root.rstrip('/')
    except Exception:
        # if called outside request context, fall back to localhost or config
        base = VISITOR_BASE_URL or "http://myportal.magnasoft.com"
    base = base.rstrip('/')

    approve_link = f"{base}/approve_visitor/{vid}"
    decline_link = f"{base}/decline_visitor/{vid}"

    # guard: if no email, nothing to send
    if not contact_email:
        return False

    subject = "New Visitor Approval Required"
    body = f"""
    <html><body>
      <p>Hello {contact_name},</p>
      <p>A new visitor has registered to meet you:</p>
      <ul>
        <li><strong>Name:</strong> {name}</li>
        <li><strong>Company:</strong> {company}</li>
        <li><strong>Phone:</strong> {phone}</li>
        <li><strong>Purpose:</strong> {purpose}</li>
      </ul>
      <p>Please choose an option below:</p>
      <p>
        <a href="{approve_link}">✅ Approve</a>&nbsp;&nbsp;
        <a href="{decline_link}">❌ Decline</a>
      </p>
      <p>Regards,<br>VMS System</p>
    </body></html>
    """

    message = MIMEMultipart()
    message["From"] = formataddr((str(Header(SMTP_FROM_NAME, 'utf-8')), SMTP_MAIL))
    message["To"] = contact_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "html"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(message["From"], contact_email, message.as_string())

    return True


@app.route("/approve_visitor/<int:visitor_id>")
def approve_visitor(visitor_id):
    v = Visitor.query.get(visitor_id)
    if not v:
        return "Visitor not found", 404
    v.approved = True
    db.session.commit()
    return "Visitor approved ✅."


@app.route("/decline_visitor/<int:visitor_id>")
def decline_visitor(visitor_id):
    v = Visitor.query.get(visitor_id)
    if not v:
        return "Visitor not found", 404
    v.approved = False
    db.session.commit()
    return "Visitor declined ❌."


@app.route("/approve_electronics/<int:visitor_id>")
def approve_electronics(visitor_id):
    v = Visitor.query.get(visitor_id)
    if not v:
        return "Visitor not found", 404
    v.electronics_approved = True
    db.session.commit()
    app.logger.info("Electronics approved via link for id=%s", visitor_id)
    return "<html><body>Electronics approved. You can close this window.</body></html>"


@app.route("/decline_electronics/<int:visitor_id>")
def decline_electronics(visitor_id):
    v = Visitor.query.get(visitor_id)
    if not v:
        return "Visitor not found", 404
    v.electronics_approved = False
    db.session.commit()
    app.logger.info("Electronics declined via link for id=%s", visitor_id)
    return "<html><body>Electronics declined. You can close this window.</body></html>"


@app.route("/get_users")
def get_users():
    dept = request.args.get("dept")
    location = request.args.get("location")

    if not dept or not location:
        return jsonify([])

    users = db.session.execute(
        text("SELECT username, email FROM contact_person WHERE dept = :dept AND location = :location"),
        {"dept": dept, "location": location}
    ).mappings().all()

    return jsonify([{"username": u["username"], "email": u["email"]} for u in users])


@app.route("/visitors")
@login_required_strict
def visitors_list():
    import json as _json
    all_visitors = Visitor.query.order_by(Visitor.created_at.desc()).all()

    # IMPORTANT: prefer query param role when present so the UI matches query-param-based logins
    user_role = get_current_role() or current_role_authoritative()

    out = []
    # keywords used server-side to detect electronics
    keywords = ['laptop','pendrive','usb','notebook','macbook','ipad','tablet','mobile','phone','charger','powerbank']

    for v in all_visitors:
        # --- normalize items (robust) ---
        items_value = getattr(v, "items", None)
        items_list = []
        try:
            if isinstance(items_value, str):
                # try JSON first (handles '['"Laptop","Pendrive"]')
                try:
                    parsed = _json.loads(items_value)
                    if isinstance(parsed, (list, tuple, set)):
                        items_list = [str(x).strip() for x in parsed if str(x).strip()]
                    else:
                        items_list = [str(parsed).strip()] if str(parsed).strip() else []
                except Exception:
                    # fallback: comma separated or bracketed string
                    cleaned = items_value.strip().strip("[]").replace('"', "").replace("'", "")
                    items_list = [s.strip() for s in cleaned.split(",") if s.strip()]
            elif isinstance(items_value, (list, tuple, set)):
                items_list = [str(x).strip() for x in items_value if str(x).strip()]
            elif items_value is None:
                items_list = []
            else:
                items_list = [str(items_value).strip()]
        except Exception:
            app.logger.exception("Failed to parse items for visitor id %s", getattr(v, "id", None))
            items_list = []

                # typed "Other" text (if any)
        other_text = getattr(v, "otherItems", "") or ""
        other_text = other_text.strip() if isinstance(other_text, str) else ""

        # canonical items_with_other: drop literal "Other" and append typed other text if any
        items_clean = [str(it).strip() for it in items_list if str(it).strip().lower() != "other"]

        # combine and dedupe case-insensitively while preserving original order
        combined = items_clean[:]  # copy
        if other_text:
            low_set = {x.lower() for x in combined}
            if other_text.strip().lower() not in low_set:
                combined.append(other_text.strip())

        seen = set()
        items_with_other_for_pass = []
        for it in combined:
            if not it:
                continue
            key = it.strip().lower()
            if key not in seen:
                items_with_other_for_pass.append(it.strip())
                seen.add(key)


        # --- compute has_electronics server-side (reliable) ---
        has_electronics_flag = False
        for itm in items_with_other_for_pass:
            itm_low = str(itm).strip().lower()
            for kw in keywords:
                if kw in itm_low:
                    has_electronics_flag = True
                    break
            if has_electronics_flag:
                break

        # visitor is allowed to be checked-in only if department approved AND
        # (no electronics OR electronics approved)
        dept_ok = bool(v.approved)   # True only if department approved (v.approved is True)
        it_ok = (v.electronics_approved is True) if has_electronics_flag else True
        allowed_to_checkin = dept_ok and it_ok

        # Prepare other fields expected by the template
        checked_items = getattr(v, "checked_items", []) or []
        badge_number = getattr(v, "badge_number", "") or ""
        idNumber = getattr(v, "idNumber", "") or ""
        photo_url = url_for('visitor_photo', visitor_id=v.id) if getattr(v, "photo_data", None) else None

        # helpful logging to debug what server passes to template
        app.logger.info(
            "VISITOR_OUT id=%s items=%s other=%s items_with_other=%s e_approved=%s has_elec=%s",
            v.id, items_list, other_text, items_with_other_for_pass, getattr(v, "electronics_approved", None), has_electronics_flag
        )

        out.append({
            "_id": v.id,
            "id": v.id,
            "name": v.name,
            "company": v.company,
            "phone": v.phone,
            "email": v.email,
            "location": v.location,
            "badge_number": badge_number,
            "idNumber": idNumber,
            "contact_person": v.contact_person,
            "contact_email": v.contact_email,
            "purpose": v.purpose,
            "items": items_list,                           # raw list
            "otherItems": other_text,                      # typed other text
            "items_with_other": items_with_other_for_pass, # canonical cleaned list for template
            "checked_items": checked_items,
            "check_in": v.check_in.strftime("%Y-%m-%d %H:%M:%S") if v.check_in else None,
            "check_out": v.check_out.strftime("%Y-%m-%d %H:%M:%S") if v.check_out else None,
            "verified": bool(v.verified),
            "dept": v.dept or "",  
            "approved": v.approved,
            "electronics_approved": getattr(v, "electronics_approved", None),
            "has_electronics": has_electronics_flag,       # <-- NEW boolean flag
             "allowed_to_checkin": allowed_to_checkin,
            "remarks": v.remarks or "",
            "photo_url": photo_url,
        })

    return render_template("visitors_list.html", visitors=out, user_role=user_role)


@app.route("/api/visitors")
def visitors_api():
    visitors = Visitor.query.order_by(Visitor.created_at.desc()).all()
    out = []
    for v in visitors:
        # normalize items to a Python list (same logic as visitors_list)
        items_list = []
        try:
            if isinstance(v.items, str):
                items_list = json.loads(v.items) if v.items else []
            elif isinstance(v.items, (list, tuple, set)):
                items_list = list(v.items)
            else:
                items_list = []
        except Exception:
            items_list = []

        out.append({
            "_id": v.id,
            "id": v.id,
            "name": v.name,
            "company": v.company,
            "phone": v.phone,
            "email": v.email,
            "location": v.location,
            "idNumber": v.idNumber,
            "contact_person": v.contact_person,
            "contact_email": v.contact_email,
            "purpose": v.purpose,
            "items": items_list,
            "check_in": v.check_in.strftime("%Y-%m-%d %H:%M:%S") if v.check_in else "",
            "check_out": v.check_out.strftime("%Y-%m-%d %H:%M:%S") if v.check_out else "",
            "verified": bool(v.verified),
            "approved": v.approved
        })
    return jsonify(out)


@app.route('/checkin/<int:visitor_id>', methods=['POST'])
def checkin(visitor_id):
    # read JSON early so we can accept role from the client payload (works when querystring lost)
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        data = {}

    # Extra logging to debug role visibility
    app.logger.info("CHECKIN REQUEST: visitor_id=%s, raw_payload=%s, query_args=%s", visitor_id, data, dict(request.args))

    # Authoritative server-side role check:
    # prefer role from POST body -> request.args -> DB/cookie fallback
    role_raw = (data.get('role') or request.args.get('role') or current_role_authoritative() or "")
    role = str(role_raw).strip().lower()
    app.logger.info("CHECKIN ROLE RESOLVED: payload_role=%s, query_role=%s, authoritative=%s", data.get('role'), request.args.get('role'), role)

    if role != "security":
        app.logger.warning("CHECKIN FORBIDDEN: resolved role=%s (not 'security')", role)
        return jsonify(success=False, message="Forbidden: insufficient permissions"), 403

    try:
        app.logger.info("CHECKIN: payload=%s", data)

        # --- normalize badge safely (accept strings or numbers) ---
        badge_raw = data.get('badge', "")
        badge = str(badge_raw).strip() if badge_raw is not None else ""

        # --- normalize override (accept bools or strings like "true"/"1"/"yes") ---
        ov_raw = data.get('override', "")
        if isinstance(ov_raw, bool):
            override = ov_raw
        else:
            override = str(ov_raw).strip().lower() in ("true", "1", "yes")

        if not badge:
            return jsonify(success=False, message="Missing badge"), 400

        # --- normalize verified: accept boolean True or text like "yes"/"true" ---
        verified_raw = data.get('verified', "")
        if isinstance(verified_raw, bool):
            verified_bool = verified_raw
            verified = "true" if verified_raw else ""
        else:
            verified = str(verified_raw or "").strip()
            verified_bool = bool(verified)

        if not verified_bool:
            return jsonify(success=False, message="ID verification missing"), 400

        v = Visitor.query.get(visitor_id)
        if not v:
            return jsonify(success=False, message="Visitor not found"), 404

        # prevent double check-in
        if v.check_in:
            return jsonify(success=False, message="Visitor already checked in"), 400

        # enforce approvals server-side, but allow explicit security override
        allowed, reason = visitor_allowed_to_checkin(v)
        # log the result so we can debug
        app.logger.info("visitor_allowed_to_checkin: allowed=%s reason=%s", allowed, reason)
        if not allowed and not override:
            return jsonify(success=False, message=f"Not allowed to check in: {reason}"), 403

        # all good — record badge and check-in time
        v.badge_number = badge

        # --- IMPORTANT: store boolean if your DB column is boolean ---
        # If your Visitor.verified column is Boolean, save the boolean:
        try:
            v.verified = verified_bool
        except Exception:
            # fallback: store the string representation (keeps old behaviour)
            app.logger.exception("Could not assign boolean to v.verified; falling back to string assignment")
            v.verified = verified

        v.check_in = datetime.utcnow()
        db.session.commit()

        return jsonify(success=True, message="Checked in", badge=badge, verified=verified , check_in=v.check_in.isoformat()), 200

    except Exception as e:
        # log full traceback for debugging
        tb = traceback.format_exc()
        app.logger.error("Checkin error: %s\n%s", str(e), tb)

        # In development you may want to return the traceback to the client (debug help).
        # Only include traceback in response if DEBUG enabled to avoid leaking internals in production.
        if app.config.get("DEBUG", False):
            return jsonify(success=False, message="Server error", error=str(e), traceback=tb), 500
        else:
            return jsonify(success=False, message="Server error"), 500

@app.route("/checkout/<int:visitor_id>", methods=["POST"])
def checkout(visitor_id):
    # read JSON early so we can accept role from the client payload
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        data = {}

    app.logger.info(
        "CHECKOUT REQUEST: visitor_id=%s, raw_payload=%s, query_args=%s",
        visitor_id, data, dict(request.args)
    )

    # prefer role from POST body -> request.args -> DB/cookie fallback
    role_raw = (data.get('role') or request.args.get('role') or current_role_authoritative() or "")
    role = str(role_raw).strip().lower()
    app.logger.info(
        "CHECKOUT ROLE RESOLVED: payload_role=%s, query_role=%s, authoritative=%s",
        data.get('role'), request.args.get('role'), role
    )

    if role != "security":
        app.logger.warning("CHECKOUT FORBIDDEN: resolved role=%s (not 'security')", role)
        return jsonify({"success": False, "message": "Forbidden: insufficient permissions"}), 403

    try:
        remarks = (data.get("remarks") or "").strip()

        # --- normalize override (security can force checkout if needed) ---
        ov_raw = data.get("override", "")
        if isinstance(ov_raw, bool):
            override = ov_raw
        else:
            override = str(ov_raw or "").strip().lower() in ("true", "1", "yes", "on")

        # small helper for common truthy checkbox/form values
        def is_truthy(val):
            if isinstance(val, bool):
                return val
            if val is None:
                return False
            if isinstance(val, (int, float)):
                return val != 0
            s = str(val).strip().lower()
            return s in ("true", "1", "yes", "on")

        # --- require all_returned (preferred) OR accept returned_items list where every entry is truthy ---
        all_returned = False
        if "all_returned" in data:
            all_returned = is_truthy(data.get("all_returned"))
        elif "returned_items" in data:
            ri = data.get("returned_items")
            if isinstance(ri, list):
                # treat each element as truthy if it's checkbox-like ("on") or boolean/dict with returned field
                def item_ok(it):
                    if isinstance(it, bool):
                        return it
                    if isinstance(it, dict):
                        # check common keys
                        return is_truthy(it.get("returned") or it.get("checked") or next(iter(it.values()), None))
                    return is_truthy(it)
                all_returned = (len(ri) == 0) or all(item_ok(x) for x in ri)
            elif isinstance(ri, dict):
                # dict of id -> bool-like
                all_returned = all(is_truthy(v) for v in ri.values())
            else:
                all_returned = is_truthy(ri)
        else:
            # no explicit info from client: treat as NOT all returned (force explicit client signal)
            all_returned = False

        app.logger.info("CHECKOUT: all_returned=%s override=%s payload=%s", all_returned, override, data)

        v = Visitor.query.get(visitor_id)
        if not v:
            return jsonify({"success": False, "message": "Visitor not found"}), 404

        # must be checked-in before checking out
        if not v.check_in:
            return jsonify({"success": False, "message": "Cannot checkout: visitor is not checked in"}), 400

        # prevent double checkout
        if v.check_out:
            return jsonify({"success": False, "message": "Visitor already checked out"}), 400

        # enforce 'all_returned' unless override provided
        if not all_returned and not override:
            return jsonify({"success": False, "message": "Please mark all return items as returned before checkout."}), 400

        # record check-out time and append optional remarks
        v.check_out = datetime.utcnow()
        if remarks:
            v.remarks = (v.remarks or "") + ("\n" + remarks if v.remarks else remarks)

        db.session.commit()
        return jsonify({"success": True, "message": "Visitor checked out successfully", "check_out": v.check_out.isoformat()}), 200

    except Exception:
        app.logger.exception("Checkout error")
        return jsonify({"success": False, "message": "Server error"}), 500


# --- Ensure a default admin user exists (run once on startup) ---
def ensure_default_admin():
    """
    Creates a default admin user (username=admin, password=admin) if missing.
    Only for development. Remove or change password in production.
    """
    try:
        # create tables if they don't exist (no-op if already created)
        db.create_all()

        if not User.query.filter_by(username="admin").first():
            hashed = generate_password_hash("admin")
            admin_user = User(username="admin", password=hashed, role="Super Admin")
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("✅ Created default admin user: admin / admin (development only)")
    except Exception:
        app.logger.exception("Failed to ensure default admin user")

# call it under app context so SQLAlchemy works
with app.app_context():
    ensure_default_admin()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
