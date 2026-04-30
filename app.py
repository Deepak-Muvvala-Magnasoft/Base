import os
import pandas as pd
import json
import smtplib
import traceback 
import re
import csv

from flask import g
from urllib.parse import urlencode
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, jsonify,
    make_response, session,  redirect, url_for, render_template
)
from urllib.parse import urlencode
from flask_sqlalchemy import SQLAlchemy
from io import StringIO
from flask import Response, g, request
from datetime import datetime
from zoneinfo import ZoneInfo
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
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import pytz
import secrets

IST = ZoneInfo("Asia/Kolkata")

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


# ─────────────────────────────────────────────────────────────────────────────
# CENTRAL APP PERMISSION MAP
# To grant a new role access: just add it to the relevant list below.
# To add a future new app: add a new key with its allowed roles.
# ─────────────────────────────────────────────────────────────────────────────
APP_ROLE_PERMISSIONS = {
    "vms":      {"admin", "security", "superadmin", "super admin"},
    "gatepass": {"admin", "security", "it", "finance", "superadmin", "super admin"},
    # Add future apps here

}

def get_allowed_roles(app_name: str) -> set:
    """Return allowed roles for a given app. Superadmin always has access."""
    return APP_ROLE_PERMISSIONS.get(app_name, set()) | {"superadmin", "super admin"}

# Backward-compatible alias (used by decorator below)
GATEPASS_ALLOWED_ROLES = get_allowed_roles("gatepass")

def gatepass_access_required(f):
    """
    Decorator: allow only roles listed in GATEPASS_ALLOWED_ROLES.
    Returns JSON 401/403 for AJAX calls, redirects browser requests.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1. Must be logged in
        if not _is_strictly_authenticated():
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "message": "Unauthorized"}), 401
            flash("Please login to access that page.", "warning")
            return redirect(url_for("login", next=request.path))

        # 2. Resolve role: DB user -> session -> cookie
        db_user = getattr(g, "current_user", None)
        if db_user and getattr(db_user, "role", None):
            user_role = (db_user.role or "").strip().lower()
        elif session.get("role"):
            user_role = (session.get("role") or "").strip().lower()
        else:
            user_role = (request.cookies.get("auth_role") or "").strip().lower()

        # 3. Check against allowed roles
        if user_role not in get_allowed_roles("gatepass"):
            app.logger.warning(
                "GatePass access denied: user=%s role=%s path=%s",
                get_current_username(), user_role, request.path
            )
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "message": "Access denied: GatePass module not available for your role."}), 403
            flash("You don\'t have access to the GatePass module.", "danger")
            return redirect(url_for("landing_page"))

        return f(*args, **kwargs)
    return decorated


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
        "today": datetime.now(IST).replace(tzinfo=None).date(),
        # App-level access flags — used in landing.html to show/hide tiles
        "can_access_vms":      role_norm in get_allowed_roles("vms"),
        "can_access_gatepass": role_norm in get_allowed_roles("gatepass"),
        # Add future apps here, e.g.:
        # "can_access_newapp": role_norm in get_allowed_roles("newapp"),
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
        # optional: user.password_last_changed = datetime.now(IST).replace(tzinfo=None)
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

# Jinja2 filter to parse JSON strings in templates
@app.template_filter('from_json')
def from_json_filter(value):
    if not value:
        return []
    try:
        result = json.loads(value)
        return result if isinstance(result, list) else []
    except Exception:
        return []

def validate_db_schema():
    """
    Fail fast if connected to a wrong / empty database.
    READ-ONLY check. No schema or data modification.
    """
    required_tables = {"visitors", "users"}

    try:
        result = db.session.execute(text("SHOW TABLES")).fetchall()
        existing_tables = {row[0] for row in result}

        missing = required_tables - existing_tables
        if missing:
            raise RuntimeError(
                f"FATAL: Invalid database schema. Missing tables: {missing}"
            )

        app.logger.info("✅ Database schema validation passed")

    except Exception as e:
        app.logger.critical("❌ Database schema validation failed: %s", e)
        raise

# 🔒 IMPORTANT: call it ONCE at startup
# with app.app_context():
#     validate_db_schema()


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
    check_in = db.Column(db.DateTime(timezone=True), nullable=True)
    check_out = db.Column(db.DateTime(timezone=True), nullable=True)
    remarks = db.Column(db.Text)
    verified = db.Column(db.Boolean, default=False)
    approved = db.Column(db.Boolean, nullable=True)
    electronics_approved = db.Column(db.Boolean, nullable=True)
    created_at = db.Column(db.DateTime, default=func.now())
    photo_filename = db.Column(db.String(255), nullable=True)
    photo_mime = db.Column(db.String(100), nullable=True)
    photo_data = db.Column(db.LargeBinary, nullable=True)
    asset_number = db.Column(db.String(100), nullable=True)

    # ── Approval tracking ────────────────────────────────────────────────
    # These columns must already exist in MySQL (added via earlier migration).
    approved_at             = db.Column(db.DateTime,    nullable=True)
    approved_by             = db.Column(db.String(150), nullable=True)
    declined_at             = db.Column(db.DateTime,    nullable=True)
    declined_by             = db.Column(db.String(150), nullable=True)
    electronics_approved_at = db.Column(db.DateTime,    nullable=True)
    electronics_approved_by = db.Column(db.String(150), nullable=True)
    electronics_declined_at = db.Column(db.DateTime,    nullable=True)
    electronics_declined_by = db.Column(db.String(150), nullable=True)


class User(db.Model):
    __tablename__ = "users"
    # DB MIGRATION: run once
    # ALTER TABLE users ADD COLUMN name       VARCHAR(150) NULL;
    # ALTER TABLE users ADD COLUMN department VARCHAR(100) NULL;
    id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username   = db.Column(db.String(100), unique=True, nullable=False)
    password   = db.Column(db.String(255), nullable=False)
    role       = db.Column(db.String(20),  nullable=False)
    name       = db.Column(db.String(150), nullable=True)   # display name
    department = db.Column(db.String(100), nullable=True)   # IT / Admin / Finance etc.

class GatePass(db.Model):
    __tablename__ = "gatepass_requests"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    pass_no = db.Column(db.String(50), unique=True)
    pass_type = db.Column(db.String(20), nullable=False)  

    created_at = db.Column(db.DateTime, default=func.now())

    requester       = db.Column(db.String(200))
    raised_by_email = db.Column(db.String(200), nullable=True)  
    raised_by_role  = db.Column(db.String(50),  nullable=True)  
    location = db.Column(db.String(100)) 
    sender_vendor = db.Column(db.String(200))
    item_description = db.Column(db.Text)
    invoice_no = db.Column(db.String(100))
    purpose = db.Column(db.String(200))
    destination = db.Column(db.String(200))
    returnable = db.Column(db.String(10), default="no")  
    expected_return_date = db.Column(db.Date)
    status = db.Column(db.String(20), default="submitted")
    needs_it_approval    = db.Column(db.Boolean, default=False)  
    needs_admin_approval = db.Column(db.Boolean, default=False)  
    it_approved_at    = db.Column(db.DateTime, nullable=True)
    it_declined_at    = db.Column(db.DateTime, nullable=True)
    it_approved_by    = db.Column(db.String(150), nullable=True)   
    it_declined_by    = db.Column(db.String(150), nullable=True)   
    admin_approved_at = db.Column(db.DateTime, nullable=True)
    admin_declined_at = db.Column(db.DateTime, nullable=True)
    admin_approved_by = db.Column(db.String(150), nullable=True)   
    admin_declined_by = db.Column(db.String(150), nullable=True)   
    security_status = db.Column(db.String(20), default="Pending")  
    security_remarks = db.Column(db.Text, nullable=True)  
    security_checked_at = db.Column(db.DateTime, nullable=True)
    security_name = db.Column(db.String(150), nullable=True)   

    # Return tracking 

    returned_at   = db.Column(db.DateTime, nullable=True) 
    returned_by   = db.Column(db.String(150), nullable=True) 

    # Partial return tracking 

    return_status_overall = db.Column(db.String(20), nullable=True)
    last_return_at        = db.Column(db.DateTime, nullable=True)
    fully_returned_at     = db.Column(db.DateTime, nullable=True)
    returns_history       = db.Column(db.Text, nullable=True)   

    # Feedback changes 

    contact_details   = db.Column(db.String(200), nullable=True)   
    receiver_email    = db.Column(db.String(200), nullable=True)   
    handover_email    = db.Column(db.String(200), nullable=True)   
    ack_token         = db.Column(db.String(100), nullable=True)  
    ack_token_sent_at = db.Column(db.DateTime,    nullable=True)
    acknowledged_at   = db.Column(db.DateTime,    nullable=True)
    acknowledged_by   = db.Column(db.String(200), nullable=True)
    ack_company       = db.Column(db.String(200), nullable=True)

    @property
    def return_status(self):
        """
        Computed return status for a returnable gate pass.
        Returns one of: 'returned_ontime', 'returned_late', 'overdue', 'pending', 'na'
        """
        if self.returnable != "yes":
            return "na"
        if self.returned_at:
            if self.expected_return_date and self.returned_at.date() <= self.expected_return_date:
                return "returned_ontime"
            return "returned_late"
        from datetime import date as _d
        if self.expected_return_date and _d.today() > self.expected_return_date:
            return "overdue"
        return "pending"


class GatepassContactPerson(db.Model):
    __tablename__ = "gatepass_contact_persons"

    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    person_name = db.Column(db.String(150))
    email = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=func.now())

class GatePassItem(db.Model):
    __tablename__ = "gatepass_items"

    id = db.Column(db.Integer, primary_key=True)
    gatepass_id = db.Column(db.Integer, db.ForeignKey("gatepass_requests.id"))
    department = db.Column(db.String(100))
    item_name = db.Column(db.String(200))
    qty = db.Column(db.String(50))
    serial_no = db.Column(db.String(200))

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

# --- Authorization helpers (place near other utilities) ---
ELECTRONICS_KEYWORDS = {
    "laptop", "pendrive", "usb", "usb-drive", "usb drive",
    "ipad", "tablet", "macbook"
}

# Robust whole-word matcher helper (precompile once)
_ELECTRONICS_REGEX = [re.compile(r"\b" + re.escape(k) + r"\b", re.IGNORECASE) for k in ELECTRONICS_KEYWORDS]

def matches_electronics(text: str) -> bool:
    """
    Return True only when any ELECTRONICS_KEYWORD appears as a whole word
    inside `text`. This avoids accidental substring matches (e.g. 'lap' in
    some unrelated word).
    """
    if not text:
        return False
    s = str(text)
    for rx in _ELECTRONICS_REGEX:
        if rx.search(s):
            return True
    return False

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


# ---------- LOGIN (keep or replace existing login success path) ---------
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
        else:
            normalized_items.append(it)

    # If user typed something in otherItems but did not check the 'Other' box,
    if other_text and other_text not in normalized_items:
        normalized_items.append(other_text)

    # DEDUPE normalized_items (preserve order, case-insensitive) ------------------
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

    #  POST-DEDUPE VALIDATION (INSERT HERE) 
    if not normalized_items:
        # No items selected (or user checked "Other" but didn't type anything)
        return respond_error("Please select at least one item carried.", status=400)

    # defensive: if the form contained the literal "Other" but user didn't type text
    if ("Other" in items_raw) and (not other_text):
        return respond_error('You checked "Others" — please describe the other items in the text box.', status=400)

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
        asset_number=(form.get("asset_number") or "").strip(),
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
        electronics_keywords = ELECTRONICS_KEYWORDS

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

        has_electronics = any(matches_electronics(it) for it in (items_to_check or []))

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
    items_electronic = [it for it in items_clean if matches_electronics(it)]
    items_line = ", ".join(items_electronic) if items_electronic else "—"
    # ----------------------------------------------------------------

    # build approve/decline links
    try:
        base = VISITOR_BASE_URL or request.url_root.rstrip('/')
    except Exception:
        base = VISITOR_BASE_URL or "http://myportal.magnasoft.com"
    base = base.rstrip('/')

    # Pass the IT contact's email as ?actor= so the approve route can resolve
    # the real person name from the contact_person table.
    from urllib.parse import quote as _quote
    _actor_q = _quote(contact_email or "", safe="")
    approve_link = f"{base}/approve_electronics/{vid}?actor={_actor_q}"
    decline_link = f"{base}/decline_electronics/{vid}?actor={_actor_q}"

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
        location = getattr(v, "location", None) if hasattr(v, "__table__") else v.get("location")

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

    # Pass the contact's email as ?actor=... so the approve/decline route can
    # resolve the real person name from the contact_person table.
    from urllib.parse import quote as _quote
    _actor_q = _quote(contact_email or "", safe="")
    approve_link = f"{base}/approve_visitor/{vid}?actor={_actor_q}"
    decline_link = f"{base}/decline_visitor/{vid}?actor={_actor_q}"

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
        <li><strong>Location:</strong> {location or 'N/A'}</li>
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


def _already_taken_page(visitor_name, action_word, action_by, action_time):
    """Reusable 'already actioned' HTML response."""
    time_str = action_time.strftime("%d-%m-%Y %H:%M") if action_time else "—"
    return (
        "<html><body style='font-family:Arial,sans-serif;padding:40px;max-width:520px;margin:auto;'>"
        "<div style='border:1px solid #e2e8f0;border-radius:10px;padding:32px;text-align:center;'>"
        "<div style='font-size:40px;margin-bottom:12px;'>ℹ️</div>"
        "<h2 style='color:#1e3a5f;margin-bottom:8px;'>Action Already Taken</h2>"
        f"<p style='color:#475569;font-size:15px;'>Visitor <strong>{visitor_name}</strong> "
        f"has already been <strong>{action_word}</strong> by "
        f"<strong>{action_by}</strong> on {time_str}.</p>"
        "<p style='color:#94a3b8;font-size:13px;margin-top:16px;'>"
        "No further action is needed. You may close this window.</p>"
        "</div></body></html>"
    )

def _success_page(emoji, color, title, visitor_name, action_word, actor):
    by_str = f" by <strong>{actor}</strong>" if actor else ""
    return (
        "<html><body style='font-family:Arial,sans-serif;padding:40px;max-width:520px;margin:auto;'>"
        "<div style='border:1px solid #e2e8f0;border-radius:10px;padding:32px;text-align:center;'>"
        f"<div style='font-size:40px;margin-bottom:12px;'>{emoji}</div>"
        f"<h2 style='color:{color};margin-bottom:8px;'>{title}</h2>"
        f"<p style='color:#475569;font-size:15px;'>Visitor <strong>{visitor_name}</strong> "
        f"has been <strong>{action_word}</strong>{by_str}.</p>"
        "<p style='color:#94a3b8;font-size:13px;margin-top:16px;'>You may close this window.</p>"
        "</div></body></html>"
    )


def _resolve_actor_name(actor_param: str, fallback_email: str = None, default: str = "") -> str:
    """
    Given the ?actor= query param (which we now pass as an email), look up the
    real person name from the contact_person table. Falls back gracefully so we
    always return *something* sensible to store in approved_by / declined_by.

    Resolution order:
      1. If ?actor= looks like an email → look up `username` (display name) by that email.
      2. If ?actor= is non-empty and not an email → trust it as the name itself.
      3. Otherwise try fallback_email (e.g., visitor.contact_email) → look up name.
      4. Finally fall back to the email's local-part (before @) titled, or `default`.
    """
    actor_param = (actor_param or "").strip()
    fallback_email = (fallback_email or "").strip()

    def _lookup_by_email(em):
        if not em:
            return None
        try:
            row = db.session.execute(
                text("SELECT username FROM contact_person WHERE email = :em LIMIT 1"),
                {"em": em}
            ).mappings().first()
            if row and row.get("username"):
                return row["username"].strip()
        except Exception:
            app.logger.exception("contact_person lookup failed for email=%s", em)
        # nice-looking fallback from the email
        local = em.split("@", 1)[0]
        return local.replace(".", " ").replace("_", " ").title() if local else None

    # 1. actor looks like an email → resolve
    if "@" in actor_param:
        name = _lookup_by_email(actor_param)
        if name:
            return name

    # 2. actor is some plain text (already a name) → trust it, but reject obvious dept labels
    dept_words = {"support", "admin", "it", "finance", "hr", "security"}
    if actor_param and actor_param.lower() not in dept_words:
        return actor_param

    # 3. try fallback email
    if fallback_email:
        name = _lookup_by_email(fallback_email)
        if name:
            return name

    return default or None


@app.route("/approve_visitor/<int:visitor_id>")
def approve_visitor(visitor_id):
    v = Visitor.query.get(visitor_id)
    if not v:
        return "Visitor not found", 404
    visitor_name = v.name or f"#{visitor_id}"

    # Person 2 clicked Approve, but someone already approved → show "already approved"
    if v.approved is True and v.approved_at:
        return _already_taken_page(visitor_name, "approved", v.approved_by or "another approver", v.approved_at)
    # Person 2 clicked Approve, but someone already declined → show "already declined"
    if v.approved is False and v.declined_at:
        return _already_taken_page(visitor_name, "declined", v.declined_by or "another approver", v.declined_at)

    # First action — record it
    v.approved = True
    v.approved_at = datetime.now(IST).replace(tzinfo=None)
    v.approved_by = _resolve_actor_name(
        request.args.get("actor"),
        fallback_email=v.contact_email,
        default=None,
    )
    v.declined_at = None
    v.declined_by = None
    db.session.commit()
    return _success_page("✅", "#166534", "Approved Successfully", visitor_name, "approved", v.approved_by)


@app.route("/decline_visitor/<int:visitor_id>")
def decline_visitor(visitor_id):
    v = Visitor.query.get(visitor_id)
    if not v:
        return "Visitor not found", 404
    visitor_name = v.name or f"#{visitor_id}"

    if v.approved is False and v.declined_at:
        return _already_taken_page(visitor_name, "declined", v.declined_by or "another approver", v.declined_at)
    if v.approved is True and v.approved_at:
        return _already_taken_page(visitor_name, "approved", v.approved_by or "another approver", v.approved_at)

    v.approved = False
    v.declined_at = datetime.now(IST).replace(tzinfo=None)
    v.declined_by = _resolve_actor_name(
        request.args.get("actor"),
        fallback_email=v.contact_email,
        default=None,
    )
    v.approved_at = None
    v.approved_by = None
    db.session.commit()
    return _success_page("❌", "#991b1b", "Declined", visitor_name, "declined", v.declined_by)


@app.route("/approve_electronics/<int:visitor_id>")
def approve_electronics(visitor_id):
    v = Visitor.query.get(visitor_id)
    if not v:
        return "Visitor not found", 404
    visitor_name = v.name or f"#{visitor_id}"

    if v.electronics_approved is True and v.electronics_approved_at:
        return _already_taken_page(
            visitor_name, "approved (electronics)",
            v.electronics_approved_by or "another approver",
            v.electronics_approved_at,
        )
    if v.electronics_approved is False and v.electronics_declined_at:
        return _already_taken_page(
            visitor_name, "declined (electronics)",
            v.electronics_declined_by or "another approver",
            v.electronics_declined_at,
        )

    v.electronics_approved = True
    v.electronics_approved_at = datetime.now(IST).replace(tzinfo=None)
    v.electronics_approved_by = _resolve_actor_name(
        request.args.get("actor"),
        fallback_email=v.contact_email,
        default="IT",
    )
    v.electronics_declined_at = None
    v.electronics_declined_by = None
    db.session.commit()
    app.logger.info("Electronics approved via link for id=%s by=%s", visitor_id, v.electronics_approved_by)
    return _success_page("✅", "#166534", "Electronics Approved", visitor_name, "approved (electronics)", v.electronics_approved_by)


@app.route("/decline_electronics/<int:visitor_id>")
def decline_electronics(visitor_id):
    v = Visitor.query.get(visitor_id)
    if not v:
        return "Visitor not found", 404
    visitor_name = v.name or f"#{visitor_id}"

    if v.electronics_approved is False and v.electronics_declined_at:
        return _already_taken_page(
            visitor_name, "declined (electronics)",
            v.electronics_declined_by or "another approver",
            v.electronics_declined_at,
        )
    if v.electronics_approved is True and v.electronics_approved_at:
        return _already_taken_page(
            visitor_name, "approved (electronics)",
            v.electronics_approved_by or "another approver",
            v.electronics_approved_at,
        )

    v.electronics_approved = False
    v.electronics_declined_at = datetime.now(IST).replace(tzinfo=None)
    v.electronics_declined_by = _resolve_actor_name(
        request.args.get("actor"),
        fallback_email=v.contact_email,
        default="IT",
    )
    v.electronics_approved_at = None
    v.electronics_approved_by = None
    db.session.commit()
    app.logger.info("Electronics declined via link for id=%s by=%s", visitor_id, v.electronics_declined_by)
    return _success_page("❌", "#991b1b", "Electronics Declined", visitor_name, "declined (electronics)", v.electronics_declined_by)


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
    # determine user role (prefer query param / UI-driven role if present)
    user_role = (get_current_role() or current_role_authoritative() or "").strip()
    user_role_lc = user_role.lower()

    # default: no role-location restriction, allow download
    role_location = None
    can_download = True

    # If role is a restricted admin (admin-blr/admin-hyd/admin-hsn), enforce server-side location filter
    if user_role_lc.startswith("admin-") and user_role_lc not in ("admin", "superadmin"):
        parts = user_role_lc.split("-", 1)
        if len(parts) == 2 and parts[1]:
            role_location = parts[1].upper()
            can_download = False

    # Build base query, apply role_location filter early to avoid loading all rows
    q = Visitor.query
    if role_location:
        q = q.filter(Visitor.location == role_location)

    all_visitors = q.order_by(Visitor.created_at.desc()).all()

    out = []

    for v in all_visitors:
        # --- normalize items (robust) ---
        items_value = getattr(v, "items", None)
        items_list = []
        try:
            if isinstance(items_value, str):
                # try JSON first (handles '["Laptop","Pendrive"]')
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

        # centralized whole-word check
        has_electronics_flag = any(matches_electronics(itm) for itm in items_with_other_for_pass)

        # visitor is allowed to be checked-in only if department approved AND
        dept_ok = bool(v.approved)   # True only if department approved (v.approved is True)
        it_ok = (v.electronics_approved is True) if has_electronics_flag else True
        allowed_to_checkin = dept_ok and it_ok

        # Prepare other fields expected by the template
        checked_items = getattr(v, "checked_items", []) or []
        badge_number = getattr(v, "badge_number", "") or ""
        asset_number = getattr(v, "asset_number", "") or ""
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
            "items": items_list,
            "asset_number": asset_number,
            "otherItems": other_text,                      # typed other text
            "items_with_other": items_with_other_for_pass, # canonical cleaned list for template
            "checked_items": checked_items,
            "check_in": v.check_in.strftime("%Y-%m-%d %H:%M:%S") if v.check_in else None,
            "check_out": v.check_out.strftime("%Y-%m-%d %H:%M:%S") if v.check_out else None,
            "verified": bool(v.verified),
            "dept": v.dept or "",
            "approved": v.approved,
            "electronics_approved": getattr(v, "electronics_approved", None),
            "has_electronics": has_electronics_flag,
            "allowed_to_checkin": allowed_to_checkin,
            "remarks": v.remarks or "",
            "photo_url": photo_url,
            # ── approval tracking ──────────────────────────────────────────
            "approved_at":             getattr(v, "approved_at",             None),
            "approved_by":             getattr(v, "approved_by",             None),
            "declined_at":             getattr(v, "declined_at",             None),
            "declined_by":             getattr(v, "declined_by",             None),
            "electronics_approved_at": getattr(v, "electronics_approved_at", None),
            "electronics_approved_by": getattr(v, "electronics_approved_by", None),
            "electronics_declined_at": getattr(v, "electronics_declined_at", None),
            "electronics_declined_by": getattr(v, "electronics_declined_by", None),
        })

    # Pass role_location and can_download to template so client can enforce UI changes too
    return render_template(
        "visitors_list.html",
        visitors=out,
        user_role=user_role,
        role_location=(role_location or None),
        can_download=bool(can_download)
        )


@app.route('/download_visitors_csv')
def download_visitors_csv():
    # role check
    user_role = (g.user_role or "").lower()
    requested_loc = request.args.get('location', 'ALL').upper()

    # restricted admins cannot download
    if user_role in ('admin-blr', 'admin-hyd', 'admin-hsn'):
        return ("Not allowed", 403)

    # Build query (same filtering logic you used in visitors_list)
    q = Visitor.query
    if requested_loc and requested_loc != 'ALL':
        q = q.filter(Visitor.location == requested_loc)

    rows = q.order_by(Visitor.created_at.desc()).all()

    # Build CSV in memory
    sio = StringIO()
    writer = csv.writer(sio)
    headers = ['Name', 'Company', 'Location', 'Badge ID', 'ID Proof', 'Items', 'Check-in', 'Check-out', 'Department']
    writer.writerow(headers)

    for v in rows:
        # use same normalization / fields as your visitors_list output (keep minimal)
        badge = getattr(v, "badge_number", "") or ""
        idnum = getattr(v, "idNumber", "") or ""
        # items: if stored as JSON or string, you can reuse existing parsing helper.
        items_val = getattr(v, "items", "") or ""
        # simple fallback: if list -> join else string
        if isinstance(items_val, (list, tuple, set)):
            items_str = ", ".join(str(x) for x in items_val)
        else:
            items_str = str(items_val)
        checkin = v.check_in.strftime("%Y-%m-%d %H:%M:%S") if v.check_in else ""
        checkout = v.check_out.strftime("%Y-%m-%d %H:%M:%S") if v.check_out else ""
        dept = v.dept or ""
        writer.writerow([v.name or "", v.company or "", v.location or "", badge, idnum, items_str, checkin, checkout, dept])

    csv_body = sio.getvalue()
    sio.close()

    # Response with proper headers so browser downloads file
    filename = f"visitors_{requested_loc}_{datetime.now(IST).replace(tzinfo=None).strftime('%Y-%m-%d')}.csv"
    resp = Response(csv_body, mimetype='text/csv; charset=utf-8')
    resp.headers.set("Content-Disposition", "attachment", filename=filename)
    return resp

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

        # --- normalize explicit handed_over flag (accept bools or strings) ---
        ho_raw = data.get('handed_over', None)
        if isinstance(ho_raw, bool):
            handed_over = ho_raw
        elif ho_raw is None:
            # fallback to override if explicit handed_over not provided
            handed_over = override
        else:
            handed_over = str(ho_raw).strip().lower() in ("true", "1", "yes")

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

        # If security indicated a handover (or override used as fallback), append an audit remark
        try:
            if handed_over:
                # try to determine actor (session username or auth cookie)
                actor = session.get("username") or request.cookies.get("auth_user") or "security"
                # use IST for human-readable remark timestamp
                ts = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S %Z")
                note = f"Handed over electronics to security (checked-in by {actor}) at {ts}."
                v.remarks = (v.remarks or "") + ("\n" + note if v.remarks else note)
                app.logger.info("CHECKIN: recorded handed_over remark for visitor_id=%s by=%s", visitor_id, actor)
        except Exception:
            app.logger.exception("Failed to append handed_over remark for visitor id=%s", visitor_id)

        # store UTC-aware datetime in DB
        v.check_in = datetime.now(ZoneInfo("Asia/Kolkata")).replace(tzinfo=None)
        db.session.commit()

        return jsonify(success=True, message="Checked in", badge=badge, verified=verified,
               check_in=v.check_in.isoformat()), 200

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
                def item_ok(it):
                    if isinstance(it, bool):
                        return it
                    if isinstance(it, dict):
                        return is_truthy(it.get("returned") or it.get("checked") or next(iter(it.values()), None))
                    return is_truthy(it)
                all_returned = (len(ri) == 0) or all(item_ok(x) for x in ri)
            elif isinstance(ri, dict):
                all_returned = all(is_truthy(vv) for vv in ri.values())
            else:
                all_returned = is_truthy(ri)
        else:
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

        # --- ASSET VERIFICATION (do NOT treat IT approval as blocker) ---
        asset_verified_raw = data.get("asset_verified", False)
        asset_verified = is_truthy(asset_verified_raw)
        asset_number = (data.get("asset_number") or "").strip()
        stored_asset = (getattr(v, "asset_number", None) or "").strip()

        # If a stored asset exists, require verification (match) unless security used override.
        if stored_asset:
            if not (asset_verified or override):
                return jsonify({"success": False, "message": "Please verify asset number before completing checkout (or use override)."}), 400

            if asset_verified and asset_number and asset_number.lower() != stored_asset.lower() and not override:
                return jsonify({"success": False, "message": "Asset number mismatch. Checkout aborted."}), 400

        # record UTC-aware check_out
        v.check_out = datetime.now(ZoneInfo("Asia/Kolkata")).replace(tzinfo=None)
        if remarks:
            v.remarks = (v.remarks or "") + ("\n" + remarks if v.remarks else remarks)

        # append asset audit note if provided / verified / or override used (use IST timestamps in notes)
        try:
            actor = session.get("username") or request.cookies.get("auth_user") or "security"
            ts = datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S %Z")
            if stored_asset and asset_verified and asset_number:
                note = f"Asset {asset_number} returned to visitor (verified by {actor}) at {ts}."
                v.remarks = (v.remarks or "") + ("\n" + note if v.remarks else note)
            elif stored_asset and override:
                note = f"Asset return override used by {actor} at {ts} (expected asset: {stored_asset}, provided: {asset_number or '—'})."
                v.remarks = (v.remarks or "") + ("\n" + note if v.remarks else note)
            elif (not stored_asset) and asset_number:
                note = f"Asset {asset_number} recorded at checkout by {actor} at {ts}."
                v.remarks = (v.remarks or "") + ("\n" + note if v.remarks else note)
        except Exception:
            app.logger.exception("Failed to append asset_verified remark for visitor id=%s", visitor_id)

        db.session.commit()
      
        return jsonify({"success": True, "message": "Visitor checked out successfully",
                "check_out": v.check_out.isoformat()}), 200

    except Exception:
        app.logger.exception("Checkout error")
        return jsonify({"success": False, "message": "Server error"}), 500

# --- Ensure a default admin user exists (run once on startup) ---
def ensure_default_admin():
    """
    DEV ONLY.
    Do NOT auto-create tables in production.
    """
    try:
        if not User.query.filter_by(username="admin").first():
            hashed = generate_password_hash("admin")
            admin_user = User(username="admin", password=hashed, role="Super Admin")
            db.session.add(admin_user)
            db.session.commit()
            app.logger.info("✅ Created default admin user (DEV only)")
    except Exception:
        app.logger.exception("Failed to ensure default admin user")

# ⚠️ IMPORTANT: only run in development
if app.config.get("ENV") == "development":
    with app.app_context():
        ensure_default_admin()

@app.route('/gatepass')
@login_required_strict
@gatepass_access_required
def gatepass_home():
    return render_template('gatepass/gatepass_home.html')

def generate_gatepass_no(pass_type="returnable"):
    prefix = "GP-R" if pass_type == "returnable" else "GP-NR"
    last = db.session.query(GatePass.pass_no)\
        .filter(GatePass.pass_no.like(f"{prefix}-%")).all()
    max_seq = 0
    for (pno,) in last:
        try:
            seq = int(pno.replace(prefix + "-", ""))
            if seq > max_seq:
                max_seq = seq
        except Exception:
            pass
    seq_str = str(max_seq + 1).zfill(2)
    return f"{prefix}-{seq_str}"


# ════════════════════════════════════════════════════════════════════════
# PARTIAL / FULL RETURN HELPERS
# Items are stored as JSON inside gatepass_requests.item_description.
# Each item dict gets a new key "qty_returned" (int, default 0).
# Returns history is stored as JSON array in gatepass_requests.returns_history.
# ════════════════════════════════════════════════════════════════════════

def _safe_int(val, default=0):
    """Parse a value (str/int/None) into int. Returns `default` if unparseable."""
    try:
        return int(str(val).strip())
    except (ValueError, AttributeError, TypeError):
        return default


def _item_effective_qty(item: dict) -> int:
    """
    Effective outgoing quantity for an item.
    If 'qty' is empty or non-numeric (e.g. '1 set', '', '—'),
    treat the item as 1 unit so it can still be returned.
    """
    raw = item.get("qty")
    n = _safe_int(raw, 0)
    if n > 0:
        return n
    # Fallback: any non-empty value (including non-numeric like "1 set") = 1 unit
    if raw not in (None, "", 0, "0"):
        return 1
    # Truly empty qty — still treat as 1 unit so the row is returnable
    return 1


def _item_outstanding(item: dict) -> int:
    """How many units of this item are still out."""
    qty_out = _item_effective_qty(item)
    qty_ret = _safe_int(item.get("qty_returned"), 0)
    return max(0, qty_out - qty_ret)


def _item_return_status(item: dict) -> str:
    """'pending' | 'partial' | 'returned' for a single item dict."""
    qty_out = _item_effective_qty(item)
    qty_ret = _safe_int(item.get("qty_returned"), 0)
    if qty_ret <= 0:
        return "pending"
    if qty_ret >= qty_out:
        return "returned"
    return "partial"


def recompute_gatepass_return_status(gp) -> str:
    """
    Recompute gp.return_status_overall from its items JSON.
    Mutates gp in place. Caller is responsible for commit.

    Returns:
      None         → non-returnable
      'pending'    → no items returned yet
      'partial'    → some items back, some outstanding
      'completed'  → all items fully returned
    """
    is_returnable = (gp.returnable == "yes") or (gp.pass_type == "returnable")
    if not is_returnable:
        gp.return_status_overall = None
        return None

    try:
        items = json.loads(gp.item_description or "[]")
    except Exception:
        items = []

    if not items:
        gp.return_status_overall = "pending"
        return "pending"

    statuses = [_item_return_status(it) for it in items]
    if all(s == "returned" for s in statuses):
        new_status = "completed"
    elif all(s == "pending" for s in statuses):
        new_status = "pending"
    else:
        new_status = "partial"

    gp.return_status_overall = new_status

    # Keep legacy fields in sync so old UI + emails don't break
    if new_status == "completed" and not gp.fully_returned_at:
        gp.fully_returned_at = datetime.now(IST).replace(tzinfo=None)
        if not gp.returned_at:
            gp.returned_at = gp.fully_returned_at
    return new_status


@app.route("/gatepass/create", methods=["POST"])
@login_required_strict
@gatepass_access_required
def gatepass_create():
    try:
        pass_type = (request.form.get("pass_type") or "").strip().lower()

        # Fetch requester name from users table (not from form text which can be wrong)
        _creator_login = get_current_username() or ""
        _creator_user  = User.query.filter_by(username=_creator_login).first() if _creator_login else None
        if _creator_user and (_creator_user.name or "").strip():
            requester = _creator_user.name.strip()
        elif _creator_login:
            # Fallback: derive name from email prefix
            requester = _creator_login.split("@")[0].replace(".", " ").title()
        else:
            requester = (request.form.get("requester") or "").strip()
        # 'location' is posted by the hidden field (always present).
        # 'nonret_location' is a fallback for older form submissions.
        location = (
            request.form.get("location") or
            request.form.get("nonret_location") or
            ""
        ).strip()

        # ---- NEW: read item rows (arrays) ----
        item_depts   = request.form.getlist("department[]")
        item_names   = request.form.getlist("item_name[]")
        qty_list     = request.form.getlist("qty[]")
        value_list   = request.form.getlist("value[]")    # Model Name
        fams_id_list = request.form.getlist("fams_id[]")  # FAMS ID

        items = []
        max_len = max(len(item_names), len(item_depts), len(qty_list), len(value_list), len(fams_id_list))

        for i in range(max_len):
            dept      = (item_depts[i]   if i < len(item_depts)   else "").strip()
            name      = (item_names[i]   if i < len(item_names)   else "").strip()
            qty       = (qty_list[i]     if i < len(qty_list)     else "").strip()
            serial_no = (value_list[i]   if i < len(value_list)   else "").strip()
            fams_id   = (fams_id_list[i] if i < len(fams_id_list) else "").strip()

            # skip completely empty rows
            if not (dept or name or qty or serial_no or fams_id):
                continue

            items.append({
                "department": dept,
                "item_name":  name,
                "qty":        qty,
                "serial_no":  serial_no,
                "fams_id":    fams_id
            })

        # basic validation
        if not pass_type:
            return "Pass type missing", 400
        if not requester:
            return "Requester missing", 400
        if not location:
            return "Location missing", 400
        if not items:
            return "Please add at least 1 item row", 400

        # save items JSON into item_description (your DB column is item_description)
        items_json = json.dumps(items, ensure_ascii=False)

        # Always require both IT and Admin approval
        needs_it    = True
        needs_admin = True

        submitted_pass_no = generate_gatepass_no(pass_type)
        # Capture creator email and role at submission time
        _creator_email = get_current_username() or ""
        _creator_role  = ""
        _db_user = getattr(g, "current_user", None)
        if _db_user and getattr(_db_user, "role", None):
            _creator_role = (_db_user.role or "").strip().lower()
        elif session.get("role"):
            _creator_role = (session.get("role") or "").strip().lower()
        else:
            _creator_role = (request.cookies.get("auth_role") or "").strip().lower()

        gp = GatePass(
            pass_no=submitted_pass_no,
            pass_type=pass_type,
            requester=requester,
            raised_by_email=_creator_email,
            raised_by_role=_creator_role,
            location=location,
            sender_vendor=(request.form.get("sender_vendor") or "").strip(),
            contact_details=(request.form.get("contact_details") or "").strip(),
            receiver_email=(request.form.get("receiver_email") or "").strip(),
            invoice_no=(request.form.get("invoice_no") or "").strip(),
            item_description=items_json,
            purpose=(request.form.get("purpose") or "").strip(),
            destination=(request.form.get("destination") or "").strip(),
            returnable=(request.form.get("returnable") or ("yes" if pass_type == "returnable" else "no")).strip().lower(),
            expected_return_date=request.form.get("expected_return_date") or None,
            needs_it_approval=needs_it,
            needs_admin_approval=needs_admin,
        )

        # Initialize return status for returnable passes
        if (gp.returnable == "yes") or (gp.pass_type == "returnable"):
            gp.return_status_overall = "pending"

        db.session.add(gp)
        db.session.commit()

        # ---- Step 5 will be called here (next section) ----
        send_gatepass_approvals(gp, items)

        return redirect("/gatepass/list")

    except Exception as e:
        db.session.rollback()
        return f"GatePass create failed: {e}", 500

def get_gatepass_contacts(location: str, department: str):
    q = GatepassContactPerson.query.filter(
        GatepassContactPerson.location == location,
        GatepassContactPerson.department == department,
        GatepassContactPerson.is_active == 1        
    )
    return q.all()

def send_gatepass_approvals(gp, items: list[dict]):
    location = (gp.location or "").strip()
    if not location:
        app.logger.warning("GatePass %s has no location, skipping email", gp.pass_no)
        return

    def _unique_by_email(contacts):
        """Deduplicate contacts — one email per person, first occurrence wins."""
        seen = set()
        result = []
        for c in contacts:
            email = (c.email or "").strip().lower()
            if email and email not in seen:
                seen.add(email)
                result.append(c)
            elif not email:
                app.logger.warning("Contact id=%s has no email, skipping", c.id)
        return result

    # ── IT: location-specific (same location as gate pass) ──
    it_contacts = _unique_by_email(
        GatepassContactPerson.query.filter(
            func.lower(GatepassContactPerson.department) == "it",
            func.lower(GatepassContactPerson.location)   == location.lower(),
            GatepassContactPerson.is_active == 1
        ).all()
    )
    # Fallback: if no IT contact at this location, use all active IT contacts
    if not it_contacts:
        it_contacts = _unique_by_email(
            GatepassContactPerson.query.filter(
                func.lower(GatepassContactPerson.department) == "it",
                GatepassContactPerson.is_active == 1
            ).all()
        )
        app.logger.warning("GatePass %s — no IT contacts for location=%s, falling back to all IT", gp.pass_no, location)
    for c in it_contacts:
        sent = send_gatepass_approval_email(gp=gp, to_email=c.email,
                   to_name=c.person_name or "IT", approval_department="IT")
        app.logger.info("IT Email to %s (location=%s): %s", c.email, location, "sent" if sent else "FAILED")

    # ── Admin: location-specific ──
    admin_contacts = _unique_by_email(
        GatepassContactPerson.query.filter(
            func.lower(GatepassContactPerson.department) == "admin",
            func.lower(GatepassContactPerson.location)   == location.lower(),
            GatepassContactPerson.is_active == 1
        ).all()
    )
    if not admin_contacts:
        app.logger.warning("GatePass %s — no Admin contacts for location=%s", gp.pass_no, location)
    for c in admin_contacts:
        sent = send_gatepass_approval_email(gp=gp, to_email=c.email,
                   to_name=c.person_name or "Admin", approval_department="Admin")
        app.logger.info("Admin Email to %s (location=%s): %s", c.email, location, "sent" if sent else "FAILED")

def send_gatepass_approval_email(gp, to_email: str, to_name: str, approval_department: str):
    if not to_email:
        return False

    try:
        base = VISITOR_BASE_URL or request.url_root.rstrip('/')
    except Exception:
        base = VISITOR_BASE_URL or "http://myportal.magnasoft.com"
    base = base.rstrip('/')

    from urllib.parse import quote as _quote
    actor_param = _quote(to_name or "")
    dept_lower  = approval_department.lower()
    approve_link = f"{base}/gatepass/approve/{gp.id}?dept={dept_lower}&actor={actor_param}"
    decline_link = f"{base}/gatepass/decline/{gp.id}?dept={dept_lower}&actor={actor_param}"
    subject = f"Action Required: GatePass Approval ({approval_department}) — {gp.pass_no}"

    try:
        items = json.loads(gp.item_description or "[]")
    except Exception:
        items = []

    pass_type_raw = (gp.pass_type or "").lower()
    if pass_type_raw == "returnable":
        pass_type_display = "Returnable"
    elif pass_type_raw in ("nonreturnable", "non-returnable"):
        pass_type_display = "Non-Returnable"
    else:
        pass_type_display = gp.pass_type or "—"

    # Outlook-safe item rows
    rows_html = ""
    for i, x in enumerate(items):
        row_bg = "#f8f9fc" if i % 2 else "#ffffff"
        fams_id = x.get("fams_id") or "—"
        rows_html += (
            f'<tr style="background-color:{row_bg};">'
            f'<td style="padding:9px 14px;color:#1e293b;font-size:13px;font-family:Arial,sans-serif;'
            f'border-bottom:1px solid #e2e8f0;">{x.get("item_name") or "&mdash;"}</td>'
            f'<td style="padding:9px 10px;color:#1e293b;font-size:13px;font-family:Arial,sans-serif;'
            f'text-align:center;border-bottom:1px solid #e2e8f0;">{x.get("qty") or "&mdash;"}</td>'
            f'<td style="padding:9px 14px;color:#475569;font-size:12px;font-family:Courier New,monospace;'
            f'border-bottom:1px solid #e2e8f0;">{x.get("serial_no") or "&mdash;"}</td>'
            f'<td style="padding:9px 14px;color:#475569;font-size:12px;font-family:Courier New,monospace;'
            f'border-bottom:1px solid #e2e8f0;">{fams_id}</td>'
            f'</tr>'
        )
    if not rows_html:
        rows_html = ('<tr><td colspan="4" style="padding:14px;color:#94a3b8;font-size:13px;'
                     'font-family:Arial,sans-serif;text-align:center;">No items added.</td></tr>')

    # Optional detail rows
    purpose_row     = ""
    destination_row = ""
    vendor_row      = ""
    invoice_row     = ""
    ret_row         = ""

    def _detail_row(label, value, bg="#ffffff"):
        return (f'<tr style="background-color:{bg};">'
                f'<td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;'
                f'color:#64748b;border-bottom:1px solid #f1f5f9;">{label}</td>'
                f'<td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;'
                f'color:#1e293b;border-bottom:1px solid #f1f5f9;">{value}</td></tr>')

    if gp.purpose:      purpose_row     = _detail_row("Purpose",         gp.purpose,         "#f8faff")
    if gp.destination:  destination_row = _detail_row("Destination",     gp.destination)
    if gp.sender_vendor: vendor_row     = _detail_row("Sender / Vendor", gp.sender_vendor,   "#f8faff")
    if gp.invoice_no:   invoice_row     = _detail_row("Emp / Vendor ID",  gp.invoice_no)
    if pass_type_raw == "returnable" and gp.expected_return_date:
        ret_row = _detail_row("Expected Return",
                              gp.expected_return_date.strftime("%d-%m-%Y"), "#f8faff")

    body = f"""<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="x-apple-disable-message-reformatting">
<title>GatePass Approval Required</title>
<!--[if mso]>
<noscript><xml><o:OfficeDocumentSettings>
<o:PixelsPerInch>96</o:PixelsPerInch>
</o:OfficeDocumentSettings></xml></noscript>
<![endif]-->
<style type="text/css">
  body, table, td {{ margin:0; padding:0; }}
  table {{ border-collapse:collapse !important; }}
  body {{ height:100% !important; margin:0 !important; padding:0 !important; width:100% !important;
          background-color:#f1f5f9; font-family:Arial,sans-serif; }}
</style>
</head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:Arial,sans-serif;">

<table border="0" cellpadding="0" cellspacing="0" width="100%"
       style="background-color:#f1f5f9;padding:32px 0;">
  <tr>
    <td align="center" valign="top">
      <!--[if mso]>
      <table border="0" cellspacing="0" cellpadding="0" width="640"><tr><td>
      <![endif]-->
      <table border="0" cellpadding="0" cellspacing="0" width="640"
             style="max-width:640px;background-color:#ffffff;border:1px solid #cbd5e1;">

        <!-- HEADER -->
        <tr>
          <td style="background-color:#1e3a5f;padding:28px 36px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td width="46" valign="middle"
                    style="width:46px;background-color:#2d5282;border:2px solid #4a7fb5;
                           padding:10px;text-align:center;">
                  <span style="font-size:20px;color:#ffffff;">&#128203;</span>
                </td>
                <td style="padding-left:16px;" valign="middle">
                  <div style="color:#93c5fd;font-size:10px;font-family:Arial,sans-serif;
                              letter-spacing:2px;font-weight:700;text-transform:uppercase;
                              mso-line-height-rule:exactly;line-height:16px;">
                    GatePass Management System
                  </div>
                  <div style="color:#ffffff;font-size:20px;font-family:Arial,sans-serif;
                              font-weight:700;mso-line-height-rule:exactly;line-height:28px;
                              margin-top:4px;">
                    Approval Required
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- STATUS BAR -->
        <tr>
          <td style="background-color:#f8faff;border-bottom:1px solid #e2e8f0;padding:10px 36px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="font-size:12px;font-family:Arial,sans-serif;color:#475569;letter-spacing:0.5px;">
                  <span style="display:inline-block;width:8px;height:8px;
                               background-color:#f59e0b;margin-right:8px;"></span>
                  PENDING APPROVAL &nbsp;&bull;&nbsp;
                  <strong style="color:#1e3a5f;">{approval_department.upper()}</strong>
                </td>
                <td align="right" style="font-size:13px;font-family:Arial,sans-serif;
                                          font-weight:700;color:#1e3a5f;">{gp.pass_no}</td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- BODY -->
        <tr>
          <td style="padding:28px 36px 10px;">
            <p style="margin:0 0 6px;font-size:15px;font-family:Arial,sans-serif;color:#374151;">
              Dear <strong style="color:#1e293b;">{to_name}</strong>,
            </p>
            <p style="margin:0 0 26px;font-size:14px;font-family:Arial,sans-serif;
                      color:#64748b;line-height:1.7;">
              Your <strong>{approval_department}</strong> approval is required for the
              gate pass below. Please review the details and take action.
            </p>

            <!-- Pass Details -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%"
                   style="border:1px solid #e2e8f0;margin-bottom:20px;">
              <tr>
                <td colspan="2"
                    style="background-color:#f0f4f9;padding:10px 16px;border-bottom:1px solid #e2e8f0;">
                  <span style="font-size:10px;font-family:Arial,sans-serif;font-weight:700;
                               letter-spacing:1.5px;color:#475569;text-transform:uppercase;">
                    Pass Details
                  </span>
                </td>
              </tr>
              {_detail_row("Pass Number", f"<strong>{gp.pass_no}</strong>")}
              {_detail_row("Pass Type", pass_type_display, "#f8faff")}
              {_detail_row("Requester", gp.requester or "&mdash;")}
              {_detail_row("Location", gp.location or "&mdash;", "#f8faff")}
              {purpose_row}{destination_row}{vendor_row}{invoice_row}{ret_row}
            </table>

            <!-- Item Details -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%"
                   style="border:1px solid #e2e8f0;margin-bottom:26px;">
              <tr>
                <td colspan="4"
                    style="background-color:#f0f4f9;padding:10px 16px;border-bottom:1px solid #e2e8f0;">
                  <span style="font-size:10px;font-family:Arial,sans-serif;font-weight:700;
                               letter-spacing:1.5px;color:#475569;text-transform:uppercase;">
                    Item Details
                  </span>
                </td>
              </tr>
              <tr style="background-color:#1e3a5f;">
                <th align="left" style="padding:9px 14px;color:#ffffff;font-size:12px;
                    font-family:Arial,sans-serif;font-weight:600;">Item Name</th>
                <th align="center" style="padding:9px 10px;color:#ffffff;font-size:12px;
                    font-family:Arial,sans-serif;font-weight:600;">Qty</th>
                <th align="left" style="padding:9px 14px;color:#ffffff;font-size:12px;
                    font-family:Arial,sans-serif;font-weight:600;">Model Name</th>
                <th align="left" style="padding:9px 14px;color:#ffffff;font-size:12px;
                    font-family:Arial,sans-serif;font-weight:600;">FAMS ID</th>
              </tr>
              {rows_html}
            </table>

            <!-- CTA Buttons — solid blocks, Outlook-safe -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%"
                   style="margin-bottom:30px;">
              <tr>
                <td width="50%" style="padding-right:6px;">
                  <!--[if mso]>
                  <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml"
                               xmlns:w="urn:schemas-microsoft-com:office:word"
                               href="{approve_link}"
                               style="height:46px;v-text-anchor:middle;width:280px;"
                               arcsize="4%" stroke="f" fillcolor="#166534">
                    <w:anchorlock/>
                    <center style="color:#ffffff;font-family:Arial,sans-serif;
                                   font-size:14px;font-weight:700;">
                      Approve Gate Pass
                    </center>
                  </v:roundrect>
                  <![endif]-->
                  <!--[if !mso]><!-->
                  <a href="{approve_link}"
                     style="background-color:#166534;color:#ffffff;display:block;
                            font-family:Arial,sans-serif;font-size:14px;font-weight:700;
                            padding:13px;text-decoration:none;text-align:center;
                            letter-spacing:0.3px;">
                    &#10003;&nbsp; Approve Gate Pass
                  </a>
                  <!--<![endif]-->
                </td>
                <td width="50%" style="padding-left:6px;">
                  <!--[if mso]>
                  <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml"
                               xmlns:w="urn:schemas-microsoft-com:office:word"
                               href="{decline_link}"
                               style="height:46px;v-text-anchor:middle;width:280px;"
                               arcsize="4%" stroke="t" strokecolor="#fca5a5" fillcolor="#ffffff">
                    <w:anchorlock/>
                    <center style="color:#991b1b;font-family:Arial,sans-serif;
                                   font-size:14px;font-weight:700;">
                      Decline
                    </center>
                  </v:roundrect>
                  <![endif]-->
                  <!--[if !mso]><!-->
                  <a href="{decline_link}"
                     style="background-color:#ffffff;color:#991b1b;display:block;
                            font-family:Arial,sans-serif;font-size:14px;font-weight:700;
                            padding:12px;text-decoration:none;text-align:center;
                            letter-spacing:0.3px;border:2px solid #fca5a5;">
                    &#10005;&nbsp; Decline
                  </a>
                  <!--<![endif]-->
                </td>
              </tr>
            </table>

          </td>
        </tr>

        <!-- FOOTER -->
        <tr>
          <td style="background-color:#f8faff;border-top:1px solid #e2e8f0;padding:16px 36px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="font-size:11px;font-family:Arial,sans-serif;color:#94a3b8;">
                  This is an automated notification. Please do not reply to this email.
                </td>
                <td align="right" style="font-size:12px;font-family:Arial,sans-serif;
                                          font-weight:700;color:#1e3a5f;">
                  GatePass &middot; Magnasoft
                </td>
              </tr>
            </table>
          </td>
        </tr>

      </table>
      <!--[if mso]></td></tr></table><![endif]-->
    </td>
  </tr>
</table>
</body></html>"""

    message = MIMEMultipart("alternative")
    message["From"] = formataddr((str(Header(SMTP_FROM_NAME, "utf-8")), SMTP_MAIL))
    message["To"] = to_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "html", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(message["From"], to_email, message.as_string())
        return True
    except Exception:
        app.logger.exception("GatePass email failed to %s (pass_no=%s)", to_email, gp.pass_no)
        return False
    


def send_gatepass_security_notification(gp):
    """
    Send a "GatePass Fully Approved — Please Verify & Allow" email to the
    Security contact(s) at the same location as the gate pass.
    Triggered once BOTH IT and Admin have approved.

    Security contacts are stored in gatepass_contact_persons with
    department = 'Security' and the matching location.
    e.g.
      Bangalore → security.desk@magnasoft.com
      Hassan    → security.hassan@magnasoft.com
      Hyderabad → security.hyderabad@magnasoft.com
    """
    location = (gp.location or "").strip()
    if not location:
        app.logger.warning(
            "Security notify: GatePass %s has no location — skipping", gp.pass_no
        )
        return

    # ── Resolve Security contacts for this location ───────────────────────────
    security_contacts = GatepassContactPerson.query.filter(
        func.lower(GatepassContactPerson.department) == "security",
        func.lower(GatepassContactPerson.location)   == location.lower(),
        GatepassContactPerson.is_active == 1
    ).all()

    if not security_contacts:
        app.logger.warning(
            "Security notify: no Security contacts for location='%s' (pass_no=%s) — skipping",
            location, gp.pass_no
        )
        return

    # Deduplicate by email
    seen, recipients = set(), []
    for c in security_contacts:
        email = (c.email or "").strip().lower()
        if email and email not in seen:
            seen.add(email)
            recipients.append(c)

    try:
        base = VISITOR_BASE_URL or "http://myportal.magnasoft.com"
    except Exception:
        base = "http://myportal.magnasoft.com"
    base = base.rstrip("/")

    try:
        items = json.loads(gp.item_description or "[]")
    except Exception:
        items = []

    pass_type_raw = (gp.pass_type or "").lower()
    if pass_type_raw == "returnable":
        pass_type_display = "Returnable"
    elif pass_type_raw in ("nonreturnable", "non-returnable"):
        pass_type_display = "Non-Returnable"
    else:
        pass_type_display = gp.pass_type or "—"

    returnable_display = "Yes" if gp.returnable == "yes" else "No"
    exp_date_display   = gp.expected_return_date.strftime("%d-%m-%Y") if gp.expected_return_date else "—"

    it_by    = gp.it_approved_by    or "IT Team"
    admin_by = gp.admin_approved_by or "Admin Team"
    it_time    = gp.it_approved_at.strftime("%d-%m-%Y %H:%M")    if gp.it_approved_at    else "—"
    admin_time = gp.admin_approved_at.strftime("%d-%m-%Y %H:%M") if gp.admin_approved_at else "—"

    # ── Item rows ─────────────────────────────────────────────────────────────
    rows_html = ""
    for i, x in enumerate(items):
        row_bg = "#f8f9fc" if i % 2 else "#ffffff"
        rows_html += (
            f'<tr style="background-color:{row_bg};">' 
            f'<td style="padding:9px 14px;color:#1e293b;font-size:13px;font-family:Arial,sans-serif;' 
            f'border-bottom:1px solid #e2e8f0;">{x.get("item_name") or "&mdash;"}</td>' 
            f'<td style="padding:9px 10px;color:#1e293b;font-size:13px;font-family:Arial,sans-serif;' 
            f'text-align:center;border-bottom:1px solid #e2e8f0;">{x.get("qty") or "&mdash;"}</td>' 
            f'<td style="padding:9px 14px;color:#475569;font-size:12px;font-family:Courier New,monospace;' 
            f'border-bottom:1px solid #e2e8f0;">{x.get("serial_no") or "&mdash;"}</td>' 
            f'<td style="padding:9px 14px;color:#475569;font-size:12px;font-family:Arial,sans-serif;' 
            f'border-bottom:1px solid #e2e8f0;">{x.get("department") or "&mdash;"}</td>' 
            f'</tr>'
        )
    if not rows_html:
        rows_html = ('<tr><td colspan="4" style="padding:14px;color:#94a3b8;font-size:13px;' 
                     'font-family:Arial,sans-serif;text-align:center;">No items recorded.</td></tr>')

    def _detail_row(label, value, bg="#ffffff"):
        return (f'<tr style="background-color:{bg};">' 
                f'<td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;' 
                f'color:#64748b;border-bottom:1px solid #f1f5f9;">{label}</td>' 
                f'<td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;' 
                f'color:#1e293b;border-bottom:1px solid #f1f5f9;">{value}</td></tr>')

    purpose_row      = _detail_row("Purpose",          gp.purpose,         "#f8faff") if gp.purpose      else ""
    destination_row  = _detail_row("Destination",      gp.destination)                if gp.destination  else ""
    vendor_row       = _detail_row("Sender / Vendor",  gp.sender_vendor,   "#f8faff") if gp.sender_vendor else ""
    vehicle_row      = _detail_row("Contact Details",  gp.contact_details)            if gp.contact_details else ""
    invoice_row      = _detail_row("Emp / Vendor ID",  gp.invoice_no,      "#f8faff") if gp.invoice_no   else ""
    ret_row          = (_detail_row("Expected Return",  exp_date_display)
                        if gp.returnable == "yes" and gp.expected_return_date else "")

    def _build_security_email(to_name):
        return f"""<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="x-apple-disable-message-reformatting">
<title>GatePass Approved — Security Action Required</title>
<!--[if mso]>
<noscript><xml><o:OfficeDocumentSettings>
<o:PixelsPerInch>96</o:PixelsPerInch>
</o:OfficeDocumentSettings></xml></noscript>
<![endif]-->
<style type="text/css">
  body, table, td {{ margin:0; padding:0; }}
  table {{ border-collapse:collapse !important; }}
  body {{ height:100% !important; margin:0 !important; padding:0 !important; width:100% !important;
          background-color:#f1f5f9; font-family:Arial,sans-serif; }}
  a {{ color:#1a56db; }}
</style>
</head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:Arial,sans-serif;">

<table border="0" cellpadding="0" cellspacing="0" width="100%"
       style="background-color:#f1f5f9;padding:32px 0;">
  <tr>
    <td align="center" valign="top">
      <!--[if mso]>
      <table border="0" cellspacing="0" cellpadding="0" width="640"><tr><td>
      <![endif]-->
      <table border="0" cellpadding="0" cellspacing="0" width="640"
             style="max-width:640px;background-color:#ffffff;border:1px solid #cbd5e1;">

        <!-- HEADER -->
        <tr>
          <td style="background-color:#1e3a5f;padding:28px 36px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td width="46" valign="middle"
                    style="width:46px;background-color:#2d5282;border:2px solid #4a7fb5;
                           padding:10px;text-align:center;">
                  <span style="font-size:20px;color:#ffffff;">&#9989;</span>
                </td>
                <td style="padding-left:16px;" valign="middle">
                  <div style="color:#93c5fd;font-size:10px;font-family:Arial,sans-serif;
                              letter-spacing:2px;font-weight:700;text-transform:uppercase;
                              mso-line-height-rule:exactly;line-height:16px;">
                    GatePass Management System
                  </div>
                  <div style="color:#ffffff;font-size:20px;font-family:Arial,sans-serif;
                              font-weight:700;mso-line-height-rule:exactly;line-height:28px;
                              margin-top:4px;">
                    GatePass Approved — Kindly Verify &amp; Allow
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- STATUS BAR -->
        <tr>
          <td style="background-color:#f0fdf4;border-bottom:1px solid #bbf7d0;padding:10px 36px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="font-size:12px;font-family:Arial,sans-serif;color:#166534;letter-spacing:0.5px;">
                  <span style="display:inline-block;width:8px;height:8px;
                               background-color:#22c55e;margin-right:8px;"></span>
                  FULLY APPROVED &nbsp;&bull;&nbsp;
                  <strong style="color:#14532d;">SECURITY ACTION REQUIRED</strong>
                </td>
                <td align="right" style="font-size:13px;font-family:Arial,sans-serif;
                                          font-weight:700;color:#1e3a5f;">{gp.pass_no}</td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- BODY -->
        <tr>
          <td style="padding:28px 36px 10px;">

            <p style="margin:0 0 6px;font-size:15px;font-family:Arial,sans-serif;color:#374151;">
              Dear <strong style="color:#1e293b;">{to_name}</strong>,
            </p>
            <p style="margin:0 0 26px;font-size:14px;font-family:Arial,sans-serif;
                      color:#64748b;line-height:1.7;">
              The gate pass below has been <strong style="color:#166534;">fully approved</strong>
              by both IT and Admin departments. Please verify the items at the gate and
              <strong>allow the pass</strong> accordingly.
            </p>

            <!-- Approval Summary -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%"
                   style="border:1px solid #bbf7d0;background-color:#f0fdf4;
                          margin-bottom:20px;">
              <tr>
                <td style="padding:10px 16px;border-bottom:1px solid #bbf7d0;">
                  <span style="font-size:10px;font-family:Arial,sans-serif;font-weight:700;
                               letter-spacing:1.5px;color:#166534;text-transform:uppercase;">
                    Approval Summary
                  </span>
                </td>
              </tr>
              <tr>
                <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                           color:#1e293b;border-bottom:1px solid #dcfce7;">
                  <span style="color:#16a34a;font-weight:700;">&#10003; IT Approved</span>
                  &nbsp;&nbsp;by <strong>{it_by}</strong>
                  <span style="color:#6b7280;font-size:12px;">&nbsp;&nbsp;{it_time}</span>
                </td>
              </tr>
              <tr>
                <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                           color:#1e293b;">
                  <span style="color:#16a34a;font-weight:700;">&#10003; Admin Approved</span>
                  &nbsp;&nbsp;by <strong>{admin_by}</strong>
                  <span style="color:#6b7280;font-size:12px;">&nbsp;&nbsp;{admin_time}</span>
                </td>
              </tr>
            </table>

            <!-- Pass Details -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%"
                   style="border:1px solid #e2e8f0;margin-bottom:20px;">
              <tr>
                <td colspan="2"
                    style="background-color:#f0f4f9;padding:10px 16px;border-bottom:1px solid #e2e8f0;">
                  <span style="font-size:10px;font-family:Arial,sans-serif;font-weight:700;
                               letter-spacing:1.5px;color:#475569;text-transform:uppercase;">
                    Pass Details
                  </span>
                </td>
              </tr>
              {_detail_row("Pass Number",    f"<strong>{gp.pass_no}</strong>")}
              {_detail_row("Pass Type",      pass_type_display,    "#f8faff")}
              {_detail_row("Requester",      gp.requester or "&mdash;")}
              {_detail_row("Location",       gp.location  or "&mdash;", "#f8faff")}
              {_detail_row("Returnable",     returnable_display)}
              {purpose_row}{destination_row}{vendor_row}{vehicle_row}{invoice_row}{ret_row}
            </table>

            <!-- Item Details -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%"
                   style="border:1px solid #e2e8f0;margin-bottom:26px;">
              <tr>
                <td colspan="4"
                    style="background-color:#f0f4f9;padding:10px 16px;border-bottom:1px solid #e2e8f0;">
                  <span style="font-size:10px;font-family:Arial,sans-serif;font-weight:700;
                               letter-spacing:1.5px;color:#475569;text-transform:uppercase;">
                    Item Details
                  </span>
                </td>
              </tr>
              <tr style="background-color:#1e3a5f;">
                <th align="left"   style="padding:9px 14px;color:#ffffff;font-size:12px;font-family:Arial,sans-serif;font-weight:600;">Item Name</th>
                <th align="center" style="padding:9px 10px;color:#ffffff;font-size:12px;font-family:Arial,sans-serif;font-weight:600;">Qty</th>
                <th align="left"   style="padding:9px 14px;color:#ffffff;font-size:12px;font-family:Arial,sans-serif;font-weight:600;">Model Name</th>
                <th align="left"   style="padding:9px 14px;color:#ffffff;font-size:12px;font-family:Arial,sans-serif;font-weight:600;">Department</th>
              </tr>
              {rows_html}
            </table>

            <!-- Note box -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%"
                   style="margin-bottom:28px;border:1px solid #fed7aa;background-color:#fff7ed;">
              <tr>
                <td style="padding:14px 18px;font-size:13px;font-family:Arial,sans-serif;color:#9a3412;line-height:1.6;">
                  <strong>&#9888;&nbsp; Security Note:</strong> Please physically verify the items
                  against the details listed above before allowing the gate pass.
                  Mark your action (Approve / Decline) in the system once done.
                </td>
              </tr>
            </table>

          </td>
        </tr>

        <!-- FOOTER -->
        <tr>
          <td style="background-color:#f8faff;border-top:1px solid #e2e8f0;padding:16px 36px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="font-size:11px;font-family:Arial,sans-serif;color:#94a3b8;">
                  This is an automated notification. Please do not reply to this email.
                </td>
                <td align="right" style="font-size:12px;font-family:Arial,sans-serif;
                                          font-weight:700;color:#1e3a5f;">
                  GatePass &middot; Magnasoft
                </td>
              </tr>
            </table>
          </td>
        </tr>

      </table>
      <!--[if mso]></td></tr></table><![endif]-->
    </td>
  </tr>
</table>
</body>
</html>"""

    subject = f"GatePass Approved — Action Required at Gate: {gp.pass_no} ({gp.location})"

    def _send_security(to_email, to_name):
        if not to_email:
            return False
        body = _build_security_email(to_name)
        message = MIMEMultipart("alternative")
        message["From"]    = formataddr((str(Header(SMTP_FROM_NAME, "utf-8")), SMTP_MAIL))
        message["To"]      = to_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "html", "utf-8"))
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(message["From"], to_email, message.as_string())
            return True
        except Exception:
            app.logger.exception(
                "Security notify email failed to %s (pass_no=%s)", to_email, gp.pass_no
            )
            return False

    app.logger.info(
        "Security notify: %s — sending to %d contact(s) at location='%s': %s",
        gp.pass_no, len(recipients), location, [c.email for c in recipients]
    )
    for c in recipients:
        sent = _send_security(c.email, c.person_name or "Security Team")
        app.logger.info(
            "Security Email → %s (location=%s): %s",
            c.email, location, "sent" if sent else "FAILED"
        )

def send_gatepass_overdue_notification(gp):
    """
    Send overdue notification to:
      - IT:    contacts at the same location as the gate pass (fallback: all IT)
      - Admin: contacts at the same location as the gate pass
    Triggered the DAY AFTER the expected_return_date passes.
    """
    location = (gp.location or "").strip()
    if not location:
        app.logger.warning("Overdue GatePass %s has no location, skipping notification", gp.pass_no)
        return

    try:
        base = VISITOR_BASE_URL or "http://myportal.magnasoft.com"
    except Exception:
        base = "http://myportal.magnasoft.com"
    base = base.rstrip('/')
    list_link = f"{base}/gatepass/list"

    try:
        items = json.loads(gp.item_description or "[]")
    except Exception:
        items = []

    from datetime import date as _date
    today = _date.today()
    days_overdue = (today - gp.expected_return_date).days if gp.expected_return_date else 0
    exp_str = gp.expected_return_date.strftime('%d-%m-%Y') if gp.expected_return_date else "—"

    # ── Helper: case-insensitive location match ───────────────────────────────
    def _contacts_for(dept, loc=None):
        q = GatepassContactPerson.query.filter(
            func.lower(GatepassContactPerson.department) == dept.lower(),
            GatepassContactPerson.is_active == 1
        )
        if loc:
            q = q.filter(func.lower(GatepassContactPerson.location) == loc.lower())
        # Deduplicate by email — one email gets exactly one notification
        seen = set()
        result = []
        for c in q.all():
            email = (c.email or "").strip().lower()
            if email and email not in seen:
                seen.add(email)
                result.append(c)
        return result

    # Build item rows — Outlook-safe: no shorthand CSS, explicit borders, table layout
    rows_html = ""
    for i, x in enumerate(items):
        row_bg = "#f8f9fc" if i % 2 else "#ffffff"
        rows_html += (
            f'<tr style="background-color:{row_bg};">'
            f'<td style="padding:9px 14px;color:#1e293b;font-size:13px;font-family:Arial,sans-serif;'
            f'border-bottom:1px solid #e2e8f0;">{x.get("item_name") or "&mdash;"}</td>'
            f'<td style="padding:9px 10px;color:#1e293b;font-size:13px;font-family:Arial,sans-serif;'
            f'text-align:center;border-bottom:1px solid #e2e8f0;">{x.get("qty") or "&mdash;"}</td>'
            f'<td style="padding:9px 14px;color:#475569;font-size:12px;font-family:Courier New,monospace;'
            f'border-bottom:1px solid #e2e8f0;">{x.get("serial_no") or "&mdash;"}</td>'
            f'</tr>'
        )
    if not rows_html:
        rows_html = ('<tr><td colspan="3" style="padding:14px;color:#94a3b8;font-size:13px;'
                     'font-family:Arial,sans-serif;text-align:center;">No items recorded.</td></tr>')

    def _build_overdue_email(to_name):
        # Outlook-safe: table-based layout, no CSS gradients on key elements,
        # no border-radius on td, inline everything, MSO conditional for width
        return f"""<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="x-apple-disable-message-reformatting">
<title>GatePass Overdue Notice</title>
<!--[if mso]>
<noscript><xml><o:OfficeDocumentSettings>
<o:PixelsPerInch>96</o:PixelsPerInch>
</o:OfficeDocumentSettings></xml></noscript>
<![endif]-->
<style type="text/css">
  body, table, td {{ margin:0; padding:0; }}
  img {{ border:0; line-height:100%; outline:none; text-decoration:none; }}
  table {{ border-collapse:collapse !important; }}
  body {{ height:100% !important; margin:0 !important; padding:0 !important; width:100% !important;
          background-color:#f1f5f9; font-family:Arial,sans-serif; }}
  a {{ color:#1a56db; }}
</style>
</head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:Arial,sans-serif;">

<!-- Outer wrapper -->
<table border="0" cellpadding="0" cellspacing="0" width="100%"
       style="background-color:#f1f5f9;padding:32px 0;">
  <tr>
    <td align="center" valign="top">

      <!--[if mso]>
      <table border="0" cellspacing="0" cellpadding="0" width="640"><tr><td>
      <![endif]-->

      <!-- Main card -->
      <table border="0" cellpadding="0" cellspacing="0" width="640"
             style="max-width:640px;background-color:#ffffff;border:1px solid #cbd5e1;">

        <!-- ── HEADER BAND ── -->
        <tr>
          <td style="background-color:#1e3a5f;padding:28px 36px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td width="46" valign="middle"
                    style="width:46px;background-color:#2d5282;border:2px solid #4a7fb5;
                           padding:10px;text-align:center;">
                  <span style="font-size:20px;color:#ffffff;">&#9888;</span>
                </td>
                <td style="padding-left:16px;" valign="middle">
                  <div style="color:#93c5fd;font-size:10px;font-family:Arial,sans-serif;
                              letter-spacing:2px;font-weight:700;text-transform:uppercase;
                              mso-line-height-rule:exactly;line-height:16px;">
                    GatePass Management System
                  </div>
                  <div style="color:#ffffff;font-size:20px;font-family:Arial,sans-serif;
                              font-weight:700;mso-line-height-rule:exactly;line-height:28px;
                              margin-top:4px;">
                    Return Overdue Notice
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── STATUS BAR ── -->
        <tr>
          <td style="background-color:#f8faff;border-bottom:1px solid #e2e8f0;
                     padding:10px 36px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="font-size:12px;font-family:Arial,sans-serif;
                           color:#475569;letter-spacing:0.5px;">
                  <span style="display:inline-block;width:8px;height:8px;
                               background-color:#f59e0b;margin-right:8px;"></span>
                  PENDING RETURN &nbsp;&bull;&nbsp;
                  <strong style="color:#1e3a5f;">
                    {days_overdue} DAY{'S' if days_overdue != 1 else ''} OVERDUE
                  </strong>
                </td>
                <td align="right" style="font-size:13px;font-family:Arial,sans-serif;
                                         font-weight:700;color:#1e3a5f;">
                  {gp.pass_no}
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- ── BODY ── -->
        <tr>
          <td style="padding:28px 36px 10px;">

            <p style="margin:0 0 6px;font-size:15px;font-family:Arial,sans-serif;color:#374151;">
              Dear <strong style="color:#1e293b;">{to_name}</strong>,
            </p>
            <p style="margin:0 0 24px;font-size:14px;font-family:Arial,sans-serif;
                      color:#64748b;line-height:1.7;">
              This is an automated notice that the returnable gate pass listed below
              has <strong style="color:#1e3a5f;">not been returned</strong> as of its
              expected return date. The item is now
              <strong style="color:#b45309;">{days_overdue} day{'s' if days_overdue != 1 else ''} overdue</strong>.
              Please follow up with the requester and update the return date using the
              GatePass portal.
            </p>

            <!-- Pass Details table -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%"
                   style="border:1px solid #e2e8f0;margin-bottom:20px;">
              <tr>
                <td colspan="2"
                    style="background-color:#f0f4f9;padding:10px 16px;
                           border-bottom:1px solid #e2e8f0;">
                  <span style="font-size:10px;font-family:Arial,sans-serif;font-weight:700;
                               letter-spacing:1.5px;color:#475569;text-transform:uppercase;">
                    Pass Details
                  </span>
                </td>
              </tr>
              <tr style="background-color:#ffffff;">
                <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                    color:#64748b;border-bottom:1px solid #f1f5f9;">Pass Number</td>
                <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                    color:#1e293b;font-weight:700;border-bottom:1px solid #f1f5f9;">{gp.pass_no}</td>
              </tr>
              <tr style="background-color:#f8faff;">
                <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                    color:#64748b;border-bottom:1px solid #f1f5f9;">Requester</td>
                <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                    color:#1e293b;border-bottom:1px solid #f1f5f9;">{gp.requester or '&mdash;'}</td>
              </tr>
              <tr style="background-color:#ffffff;">
                <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                    color:#64748b;border-bottom:1px solid #f1f5f9;">Location</td>
                <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                    color:#1e293b;border-bottom:1px solid #f1f5f9;">{gp.location or '&mdash;'}</td>
              </tr>
              <tr style="background-color:#f8faff;">
                <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                    color:#64748b;border-bottom:1px solid #f1f5f9;">Expected Return Date</td>
                <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                    color:#92400e;font-weight:700;border-bottom:1px solid #f1f5f9;">{exp_str}</td>
              </tr>
              <tr style="background-color:#ffffff;">
                <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                    color:#64748b;">Days Overdue</td>
                <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;
                    color:#92400e;font-weight:700;">
                  {days_overdue} day{'s' if days_overdue != 1 else ''}
                </td>
              </tr>
            </table>

            <!-- Items table -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%"
                   style="border:1px solid #e2e8f0;margin-bottom:26px;">
              <tr>
                <td colspan="3"
                    style="background-color:#f0f4f9;padding:10px 16px;
                           border-bottom:1px solid #e2e8f0;">
                  <span style="font-size:10px;font-family:Arial,sans-serif;font-weight:700;
                               letter-spacing:1.5px;color:#475569;text-transform:uppercase;">
                    Item Details
                  </span>
                </td>
              </tr>
              <tr style="background-color:#1e3a5f;">
                <th align="left" style="padding:9px 14px;color:#ffffff;font-size:12px;
                    font-family:Arial,sans-serif;font-weight:600;">Item Name</th>
                <th align="center" style="padding:9px 10px;color:#ffffff;font-size:12px;
                    font-family:Arial,sans-serif;font-weight:600;">Qty</th>
                <th align="left" style="padding:9px 14px;color:#ffffff;font-size:12px;
                    font-family:Arial,sans-serif;font-weight:600;">Model Name</th>
              </tr>
              {rows_html}
            </table>

            <!-- CTA Button — solid color block, no gradient (Outlook-safe) -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%"
                   style="margin-bottom:28px;">
              <tr>
                <td align="center" style="padding:0;">
                  <!--[if mso]>
                  <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml"
                               xmlns:w="urn:schemas-microsoft-com:office:word"
                               href="{list_link}"
                               style="height:46px;v-text-anchor:middle;width:320px;"
                               arcsize="6%" stroke="f" fillcolor="#1e3a5f">
                    <w:anchorlock/>
                    <center style="color:#ffffff;font-family:Arial,sans-serif;
                                   font-size:14px;font-weight:700;">
                      Open GatePass List &rarr; Extend Date
                    </center>
                  </v:roundrect>
                  <![endif]-->
                  <!--[if !mso]><!-->
                  <a href="{list_link}"
                     style="background-color:#1e3a5f;color:#ffffff;display:inline-block;
                            font-family:Arial,sans-serif;font-size:14px;font-weight:700;
                            padding:13px 32px;text-decoration:none;letter-spacing:0.3px;">
                    Open GatePass List &rarr; Extend Date
                  </a>
                  <!--<![endif]-->
                </td>
              </tr>
            </table>

          </td>
        </tr>

        <!-- ── FOOTER ── -->
        <tr>
          <td style="background-color:#f8faff;border-top:1px solid #e2e8f0;padding:16px 36px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td style="font-size:11px;font-family:Arial,sans-serif;color:#94a3b8;">
                  This is an automated notification. Please do not reply to this email.
                </td>
                <td align="right" style="font-size:12px;font-family:Arial,sans-serif;
                                          font-weight:700;color:#1e3a5f;">
                  GatePass &middot; Magnasoft
                </td>
              </tr>
            </table>
          </td>
        </tr>

      </table>
      <!--[if mso]></td></tr></table><![endif]-->

    </td>
  </tr>
</table>

</body>
</html>"""

    subject = f"GatePass Return Overdue — {gp.pass_no} ({days_overdue} day{'s' if days_overdue != 1 else ''} overdue)"

    def _send(to_email, to_name):
        if not to_email:
            return False
        body = _build_overdue_email(to_name)
        message = MIMEMultipart("alternative")
        message["From"] = formataddr((str(Header(SMTP_FROM_NAME, "utf-8")), SMTP_MAIL))
        message["To"] = to_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "html", "utf-8"))
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(message["From"], to_email, message.as_string())
            return True
        except Exception:
            app.logger.exception("Overdue email failed to %s (pass_no=%s)", to_email, gp.pass_no)
            return False

    # Send overdue email only to:
    # 1. The person who raised the gatepass (raised_by_email)
    # 2. The receiver/vendor (receiver_email)
    # IT/Admin contact persons do NOT get overdue emails.
    creator_email = (gp.raised_by_email or "").strip().lower()
    if not creator_email:
        app.logger.warning(
            "Overdue notify: no creator email on pass_no=%s (raised_by_email is empty)",
            gp.pass_no
        )
        return

    creator_name = creator_email.split("@")[0].replace(".", " ").title()
    sent = _send(creator_email, creator_name)
    app.logger.info(
        "Overdue Email to creator %s (pass_no=%s): %s",
        creator_email, gp.pass_no, "sent" if sent else "FAILED"
    )

    # Also send to receiver_email if present
    receiver_email = (getattr(gp, 'receiver_email', None) or "").strip().lower()
    if receiver_email and receiver_email != creator_email:
        receiver_name = receiver_email.split("@")[0].replace(".", " ").title()
        sent_r = _send(receiver_email, receiver_name)
        app.logger.info(
            "Overdue Email to receiver %s (pass_no=%s): %s",
            receiver_email, gp.pass_no, "sent" if sent_r else "FAILED"
        )

@app.route("/gatepass/approve/<int:gp_id>")
def gatepass_approve(gp_id):
    dept  = (request.args.get("dept") or "").strip().lower()
    actor = (request.args.get("actor") or "").strip()   # name of the person who clicked
    gp = GatePass.query.get(gp_id)
    if not gp:
        return "<html><body><h3>GatePass not found.</h3></body></html>", 404

    now = datetime.now(IST)

    # ── Guard: check if action was already taken for this dept ──────────────
    if dept == "it":
        if gp.it_approved_at or gp.it_declined_at:
            action_word = "approved" if gp.it_approved_at else "declined"
            action_by   = gp.it_approved_by or gp.it_declined_by or "another approver"
            action_time = (gp.it_approved_at or gp.it_declined_at).strftime("%d-%m-%Y %H:%M")
            return (
                f"<html><body style='font-family:Arial,sans-serif;padding:40px;max-width:520px;margin:auto;'>"
                f"<div style='border:1px solid #e2e8f0;border-radius:10px;padding:32px;text-align:center;'>"
                f"<div style='font-size:40px;margin-bottom:12px;'>ℹ️</div>"
                f"<h2 style='color:#1e3a5f;margin-bottom:8px;'>Action Already Taken</h2>"
                f"<p style='color:#475569;font-size:15px;'>This gate pass (<strong>{gp.pass_no}</strong>) "
                f"has already been <strong>{action_word}</strong> by <strong>{action_by}</strong> on {action_time}.</p>"
                f"<p style='color:#94a3b8;font-size:13px;margin-top:16px;'>No further action is needed from you. You may close this window.</p>"
                f"</div></body></html>"
            )
        gp.it_approved_at = now
        gp.it_declined_at = None
        gp.it_approved_by = actor or None
        gp.it_declined_by = None

    elif dept == "admin":
        if gp.admin_approved_at or gp.admin_declined_at:
            action_word = "approved" if gp.admin_approved_at else "declined"
            action_by   = gp.admin_approved_by or gp.admin_declined_by or "another approver"
            action_time = (gp.admin_approved_at or gp.admin_declined_at).strftime("%d-%m-%Y %H:%M")
            return (
                f"<html><body style='font-family:Arial,sans-serif;padding:40px;max-width:520px;margin:auto;'>"
                f"<div style='border:1px solid #e2e8f0;border-radius:10px;padding:32px;text-align:center;'>"
                f"<div style='font-size:40px;margin-bottom:12px;'>ℹ️</div>"
                f"<h2 style='color:#1e3a5f;margin-bottom:8px;'>Action Already Taken</h2>"
                f"<p style='color:#475569;font-size:15px;'>This gate pass (<strong>{gp.pass_no}</strong>) "
                f"has already been <strong>{action_word}</strong> by <strong>{action_by}</strong> on {action_time}.</p>"
                f"<p style='color:#94a3b8;font-size:13px;margin-top:16px;'>No further action is needed from you. You may close this window.</p>"
                f"</div></body></html>"
            )
        gp.admin_approved_at = now
        gp.admin_declined_at = None
        gp.admin_approved_by = actor or None
        gp.admin_declined_by = None

    it_done    = (not gp.needs_it_approval)    or (gp.it_approved_at is not None)
    admin_done = (not gp.needs_admin_approval) or (gp.admin_approved_at is not None)
    it_dec     = gp.it_declined_at is not None
    admin_dec  = gp.admin_declined_at is not None

    if it_dec or admin_dec:
        gp.status = "declined"
    elif it_done and admin_done:
        gp.status = "approved"
    else:
        gp.status = "pending"

    db.session.commit()

    # ── Notify Security once BOTH IT and Admin have approved ──────────────────
    if it_done and admin_done and not it_dec and not admin_dec:
        try:
            send_gatepass_security_notification(gp)
        except Exception:
            app.logger.exception(
                "Failed to send security notification for gatepass id=%s", gp.id
            )

    return (
        "<html><body style='font-family:Arial,sans-serif;padding:40px;max-width:520px;margin:auto;'>"
        "<div style='border:1px solid #e2e8f0;border-radius:10px;padding:32px;text-align:center;'>"
        "<div style='font-size:40px;margin-bottom:12px;'>✅</div>"
        "<h2 style='color:#166534;margin-bottom:8px;'>Approved Successfully</h2>"
        f"<p style='color:#475569;font-size:15px;'>Gate pass <strong>{gp.pass_no}</strong> has been approved.</p>"
        "<p style='color:#94a3b8;font-size:13px;margin-top:16px;'>You may close this window.</p>"
        "</div></body></html>"
    )

@app.route("/gatepass/decline/<int:gp_id>")
def gatepass_decline(gp_id):
    dept  = (request.args.get("dept") or "").strip().lower()
    actor = (request.args.get("actor") or "").strip()
    gp = GatePass.query.get(gp_id)
    if not gp:
        return "<html><body><h3>GatePass not found.</h3></body></html>", 404

    now = datetime.now(IST)

    # ── Guard: check if action was already taken for this dept ──────────────
    if dept == "it":
        if gp.it_approved_at or gp.it_declined_at:
            action_word = "approved" if gp.it_approved_at else "declined"
            action_by   = gp.it_approved_by or gp.it_declined_by or "another approver"
            action_time = (gp.it_approved_at or gp.it_declined_at).strftime("%d-%m-%Y %H:%M")
            return (
                f"<html><body style='font-family:Arial,sans-serif;padding:40px;max-width:520px;margin:auto;'>"
                f"<div style='border:1px solid #e2e8f0;border-radius:10px;padding:32px;text-align:center;'>"
                f"<div style='font-size:40px;margin-bottom:12px;'>ℹ️</div>"
                f"<h2 style='color:#1e3a5f;margin-bottom:8px;'>Action Already Taken</h2>"
                f"<p style='color:#475569;font-size:15px;'>This gate pass (<strong>{gp.pass_no}</strong>) "
                f"has already been <strong>{action_word}</strong> by <strong>{action_by}</strong> on {action_time}.</p>"
                f"<p style='color:#94a3b8;font-size:13px;margin-top:16px;'>No further action is needed from you. You may close this window.</p>"
                f"</div></body></html>"
            )
        gp.it_declined_at  = now
        gp.it_approved_at  = None
        gp.it_declined_by  = actor or None
        gp.it_approved_by  = None

    elif dept == "admin":
        if gp.admin_approved_at or gp.admin_declined_at:
            action_word = "approved" if gp.admin_approved_at else "declined"
            action_by   = gp.admin_approved_by or gp.admin_declined_by or "another approver"
            action_time = (gp.admin_approved_at or gp.admin_declined_at).strftime("%d-%m-%Y %H:%M")
            return (
                f"<html><body style='font-family:Arial,sans-serif;padding:40px;max-width:520px;margin:auto;'>"
                f"<div style='border:1px solid #e2e8f0;border-radius:10px;padding:32px;text-align:center;'>"
                f"<div style='font-size:40px;margin-bottom:12px;'>ℹ️</div>"
                f"<h2 style='color:#1e3a5f;margin-bottom:8px;'>Action Already Taken</h2>"
                f"<p style='color:#475569;font-size:15px;'>This gate pass (<strong>{gp.pass_no}</strong>) "
                f"has already been <strong>{action_word}</strong> by <strong>{action_by}</strong> on {action_time}.</p>"
                f"<p style='color:#94a3b8;font-size:13px;margin-top:16px;'>No further action is needed from you. You may close this window.</p>"
                f"</div></body></html>"
            )
        gp.admin_declined_at = now
        gp.admin_approved_at = None
        gp.admin_declined_by = actor or None
        gp.admin_approved_by = None

    gp.status = "declined"
    db.session.commit()
    return (
        "<html><body style='font-family:Arial,sans-serif;padding:40px;max-width:520px;margin:auto;'>"
        "<div style='border:1px solid #e2e8f0;border-radius:10px;padding:32px;text-align:center;'>"
        "<div style='font-size:40px;margin-bottom:12px;'>❌</div>"
        "<h2 style='color:#991b1b;margin-bottom:8px;'>Declined</h2>"
        f"<p style='color:#475569;font-size:15px;'>Gate pass <strong>{gp.pass_no}</strong> has been declined.</p>"
        "<p style='color:#94a3b8;font-size:13px;margin-top:16px;'>You may close this window.</p>"
        "</div></body></html>"
    )
        

@app.route("/gatepass/send-ack/<int:gp_id>", methods=["POST"])
@login_required_strict
@gatepass_access_required
def gatepass_send_ack(gp_id):
    """Send acknowledgement link to collector. Called before security approval."""
    gp = GatePass.query.get(gp_id)
    if not gp:
        return jsonify({"success": False, "message": "GatePass not found"}), 404
    data           = request.get_json(silent=True) or {}
    handover_email = (data.get("handover_email") or "").strip()
    security_name  = (data.get("security_name") or "").strip()
    if not handover_email:
        return jsonify({"success": False, "message": "Handover email is required"}), 400
    gp.handover_email    = handover_email
    gp.security_name     = security_name
    token                = secrets.token_urlsafe(32)
    gp.ack_token         = token
    gp.ack_token_sent_at = datetime.now(IST).replace(tzinfo=None)
    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"success": False, "message": "Database error"}), 500
    try:
        _send_ack_email(gp, handover_email, token)
    except Exception:
        app.logger.exception("Failed to send ack email for gatepass id=%s", gp_id)
        return jsonify({"success": False, "message": "Failed to send email. Check SMTP settings."}), 500
    return jsonify({"success": True})


@app.route("/gatepass/resend-ack/<int:gp_id>", methods=["POST"])
@login_required_strict
@gatepass_access_required
def gatepass_resend_ack(gp_id):
    """
    Security edits the collector email and resends the acknowledgement link.
    Kills the old token so the wrong recipient can't acknowledge anymore.

    Only allowed when:
      - Logged-in role is 'security'
      - A previous ack was already sent (ack_token_sent_at is set)
      - Pass is NOT yet acknowledged (acknowledged_at is NULL)
      - New email is different from the current one and has valid format

    Request JSON:
      { "new_email": "correct@client.com", "reason": "typo" }
    """
    # ── Role guard: Security only (matches dialog visibility) ────────────
    role = (get_current_role() or "").lower().replace(" ", "")
    if role not in ("security", "superadmin"):
        return jsonify({
            "success": False,
            "message": "Only Security can resend acknowledgement links."
        }), 403

    gp = GatePass.query.get(gp_id)
    if not gp:
        return jsonify({"success": False, "message": "GatePass not found"}), 404

    # State checks
    if not gp.ack_token_sent_at:
        return jsonify({
            "success": False,
            "message": "No original acknowledgement to resend. Send it first."
        }), 400
    if gp.acknowledged_at:
        return jsonify({
            "success": False,
            "message": "Pass is already acknowledged — cannot resend."
        }), 400

    data       = request.get_json(silent=True) or {}
    new_email  = (data.get("new_email") or "").strip()
    reason     = (data.get("reason") or "").strip()

    if not new_email:
        return jsonify({"success": False, "message": "New collector email is required."}), 400

    # Basic email format check
    import re as _re
    if not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", new_email):
        return jsonify({"success": False, "message": "Invalid email format."}), 400

    old_email = (gp.handover_email or "").strip()
    if new_email.lower() == old_email.lower():
        return jsonify({
            "success": False,
            "message": "New email is the same as the current one. Enter a different email."
        }), 400

    try:
        now_ist   = datetime.now(IST).replace(tzinfo=None)
        new_token = secrets.token_urlsafe(32)

        # Kill old token by overwriting, update email, reset sent timestamp
        gp.handover_email    = new_email
        gp.ack_token         = new_token
        gp.ack_token_sent_at = now_ist

        # Audit trail appended to security_remarks (no schema change)
        guard_name = (gp.security_name or "Security").strip()
        actor      = get_current_username() or ""
        note = (
            f"[Ack email resent on {now_ist.strftime('%d-%m-%Y %H:%M')} IST] "
            f"Changed from: {old_email or '—'} -> {new_email}."
        )
        if reason:
            note += f" Reason: {reason}."
        note += f" By: {guard_name}"
        if actor:
            note += f" ({actor})"
        note += "."

        existing = gp.security_remarks or ""
        gp.security_remarks = (existing + ("\n" if existing else "") + note).strip()

        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("resend-ack DB commit failed for gp_id=%s", gp_id)
        return jsonify({"success": False, "message": "Database error"}), 500

    # Send the new email AFTER commit so DB is the source of truth
    try:
        _send_ack_email(gp, new_email, new_token)
    except Exception:
        app.logger.exception("Failed to re-send ack email for gatepass id=%s", gp_id)
        # DB already updated; user can click resend again if needed.
        return jsonify({
            "success": False,
            "message": "Email send failed, but the link has been regenerated. Try resend again."
        }), 500

    app.logger.info(
        "GatePass %s: ack resent by=%s from=%s -> to=%s",
        gp.pass_no, guard_name, old_email, new_email
    )
    return jsonify({
        "success": True,
        "new_email": new_email,
        "sent_at": now_ist.strftime("%d-%m-%Y %H:%M"),
    })


@app.route("/gatepass/security-action/<int:gp_id>", methods=["POST"])
@login_required_strict
@gatepass_access_required
def gatepass_security_action(gp_id):
    gp = GatePass.query.get(gp_id)
    if not gp:
        return jsonify({"success": False, "message": "GatePass not found"}), 404
    try:
        data          = request.get_json(silent=True) or {}
        status        = (data.get("status") or "").strip()
        remarks       = (data.get("remarks") or "").strip()
        security_name = (data.get("security_name") or "").strip()

        if status not in ("Approved", "Declined"):
            return jsonify({"success": False, "message": "Invalid status"}), 400
        if not security_name:
            return jsonify({"success": False, "message": "Security officer name is required"}), 400

        # Block approval if collector has not acknowledged yet
        if status == "Approved" and not gp.acknowledged_at:
            return jsonify({"success": False, "message": "Collector has not acknowledged yet. Please wait for acknowledgement before approving."}), 400

        gp.security_status     = status
        gp.security_remarks    = remarks or None
        gp.security_name       = security_name
        gp.security_checked_at = datetime.now(IST).replace(tzinfo=None)

        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


def _send_ack_email(gp, to_email, token):
    """Send acknowledgement link to handover person."""
    import html as _html
    try:
        base = VISITOR_BASE_URL or "http://myportal.magnasoft.com"
    except Exception:
        base = "http://myportal.magnasoft.com"
    ack_link = f"{base.rstrip('/')}/gatepass/acknowledge/{token}"

    try:
        items = json.loads(gp.item_description or "[]")
    except Exception:
        items = []

    items_rows = ""
    for i, x in enumerate(items):
        bg = "#f8f9fc" if i % 2 else "#ffffff"
        items_rows += (
            f'<tr style="background:{bg};">'
            f'<td style="padding:8px 14px;font-size:13px;font-family:Arial,sans-serif;border-bottom:1px solid #e2e8f0;">{_html.escape(str(x.get("item_name") or "—"))}</td>'
            f'<td style="padding:8px 10px;font-size:13px;font-family:Arial,sans-serif;text-align:center;border-bottom:1px solid #e2e8f0;">{_html.escape(str(x.get("qty") or "—"))}</td>'
            f'<td style="padding:8px 14px;font-size:12px;font-family:Arial,sans-serif;border-bottom:1px solid #e2e8f0;">{_html.escape(str(x.get("serial_no") or "—"))}</td>'
            f'</tr>'
        )

    subject = f"Please Acknowledge Receipt — GatePass {gp.pass_no}"
    body = f"""<html><body style="font-family:Arial,sans-serif;background:#f1f5f9;padding:32px 0;margin:0;">
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background:#f1f5f9;">
<tr><td align="center">
<table border="0" cellpadding="0" cellspacing="0" width="620" style="background:#ffffff;border:1px solid #cbd5e1;max-width:620px;">
  <tr><td style="background:#1e3a5f;padding:24px 32px;">
    <div style="color:#93c5fd;font-size:10px;letter-spacing:2px;font-weight:700;text-transform:uppercase;">GatePass Management — Magnasoft</div>
    <div style="color:#ffffff;font-size:20px;font-weight:700;margin-top:4px;">Acknowledgement Required</div>
  </td></tr>
  <tr><td style="padding:28px 32px;">
    <p style="font-size:14px;color:#374151;margin:0 0 16px;">You are listed as the collector for the following items from <strong>Magnasoft Consulting pvt ltd</strong>.</p>
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border:1px solid #e2e8f0;margin-bottom:20px;">
      <tr style="background:#f4f6fb;">
        <td style="padding:8px 14px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#64748b;border-bottom:1px solid #e2e8f0;">Pass No</td>
        <td style="padding:8px 14px;font-size:13px;font-weight:700;color:#1e3a5f;border-bottom:1px solid #e2e8f0;">{_html.escape(gp.pass_no or '')}</td>
      </tr>
      <tr>
        <td style="padding:8px 14px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#64748b;border-bottom:1px solid #e2e8f0;">Location</td>
        <td style="padding:8px 14px;font-size:13px;color:#374151;border-bottom:1px solid #e2e8f0;">{_html.escape(gp.location or '—')}</td>
      </tr>
      <tr style="background:#f4f6fb;">
        <td style="padding:8px 14px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#64748b;">Date</td>
        <td style="padding:8px 14px;font-size:13px;color:#374151;">{(gp.ack_token_sent_at or gp.security_checked_at or gp.created_at).strftime('%d-%m-%Y') if (gp.ack_token_sent_at or gp.security_checked_at or gp.created_at) else '—'}</td>
      </tr>
    </table>
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;color:#64748b;margin-bottom:8px;">Items Being Collected</div>
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border:1px solid #e2e8f0;margin-bottom:24px;">
      <tr style="background:#f4f6fb;">
        <th style="padding:8px 14px;font-size:11px;font-weight:700;text-transform:uppercase;color:#64748b;text-align:left;border-bottom:1px solid #e2e8f0;">Item</th>
        <th style="padding:8px 10px;font-size:11px;font-weight:700;text-transform:uppercase;color:#64748b;text-align:center;border-bottom:1px solid #e2e8f0;">Qty</th>
        <th style="padding:8px 14px;font-size:11px;font-weight:700;text-transform:uppercase;color:#64748b;text-align:left;border-bottom:1px solid #e2e8f0;">Model / Serial</th>
      </tr>
      {items_rows}
    </table>
    <div style="text-align:center;margin-bottom:20px;">
      <a href="{ack_link}" style="display:inline-block;background:#1a56db;color:#ffffff;text-decoration:none;padding:13px 32px;font-size:15px;font-weight:700;font-family:Arial,sans-serif;">
        ✓ Acknowledge Receipt
      </a>
    </div>
    <p style="font-size:12px;color:#94a3b8;text-align:center;margin:0;">This link is valid for 7 days. If you did not collect these items, please ignore this email.</p>
  </td></tr>
  <tr><td style="background:#f8faff;border-top:1px solid #e2e8f0;padding:14px 32px;font-size:11px;color:#94a3b8;">
    This is an automated notification from Magnasoft GatePass Management System.
  </td></tr>
</table>
</td></tr></table>
</body></html>"""

    message = MIMEMultipart("alternative")
    message["From"]    = formataddr((str(Header(SMTP_FROM_NAME, "utf-8")), SMTP_MAIL))
    message["To"]      = to_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "html", "utf-8"))
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(message["From"], to_email, message.as_string())


@app.route("/gatepass/extend-return/<int:gp_id>", methods=["POST"])
@login_required_strict
@gatepass_access_required
def gatepass_extend_return(gp_id):
    gp = GatePass.query.get(gp_id)
    if not gp:
        return jsonify({"success": False, "message": "GatePass not found"}), 404
    try:
        data             = request.get_json(silent=True) or {}
        new_date         = (data.get("new_date") or "").strip()
        reason           = (data.get("reason") or "").strip()
        internal_remarks = (data.get("internal_remarks") or "").strip()
        if not new_date or not reason:
            return jsonify({"success": False, "message": "Date and reason are required"}), 400
        from datetime import datetime as _dt
        gp.expected_return_date = _dt.strptime(new_date, "%Y-%m-%d").date()
        # Append requester reason + internal remarks as separate notes
        existing = gp.security_remarks or ""
        note  = f"[Extended to {new_date}] Requester reason: {reason}"
        if internal_remarks:
            note += f" | Internal: {internal_remarks}"
        gp.security_remarks = (existing + ("\n" if existing else "") + note).strip()
        db.session.commit()

        # Send overdue notification to IT (all locations) + Admin (location-specific)
        try:
            send_gatepass_overdue_notification(gp)
        except Exception:
            app.logger.exception("Failed to send overdue notification for gatepass id=%s", gp_id)

        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


def send_gatepass_returned_notification(gp, returned_by: str, remarks: str, return_label: str):
    """
    Send "Material Returned" email to IT (location-specific) + Admin (location-specific)
    when security marks a gate pass as physically returned.
    Includes full pass details, item list, return status, and received remarks.
    """
    location = (gp.location or "").strip()
    if not location:
        app.logger.warning("Returned GatePass %s has no location, skipping notification", gp.pass_no)
        return

    try:
        base = VISITOR_BASE_URL or "http://myportal.magnasoft.com"
    except Exception:
        base = "http://myportal.magnasoft.com"
    base = base.rstrip('/')
    list_link = f"{base}/gatepass/list"

    try:
        items = json.loads(gp.item_description or "[]")
    except Exception:
        items = []

    # Return status badge colour
    if "on-time" in return_label:
        status_color = "#166534"
        status_bg    = "#dcfce7"
        status_label = "✓ Returned On Time"
    elif "late" in return_label:
        status_color = "#b45309"
        status_bg    = "#fef3c7"
        status_label = f"⚠ Returned Late ({return_label})"
    else:
        status_color = "#475569"
        status_bg    = "#f1f5f9"
        status_label = "Returned"

    exp_str      = gp.expected_return_date.strftime('%d-%m-%Y') if gp.expected_return_date else "—"
    returned_str = gp.returned_at.strftime('%d-%m-%Y %H:%M') + " IST" if gp.returned_at else "—"

    # Build item rows
    rows_html = ""
    for i, x in enumerate(items):
        row_bg = "#f8f9fc" if i % 2 else "#ffffff"
        rows_html += (
            f'<tr style="background-color:{row_bg};">'
            f'<td style="padding:9px 14px;color:#1e293b;font-size:13px;font-family:Arial,sans-serif;'
            f'border-bottom:1px solid #e2e8f0;">{x.get("item_name") or "&mdash;"}</td>'
            f'<td style="padding:9px 10px;color:#1e293b;font-size:13px;font-family:Arial,sans-serif;'
            f'text-align:center;border-bottom:1px solid #e2e8f0;">{x.get("qty") or "&mdash;"}</td>'
            f'<td style="padding:9px 14px;color:#475569;font-size:12px;font-family:Courier New,monospace;'
            f'border-bottom:1px solid #e2e8f0;">{x.get("serial_no") or "&mdash;"}</td>'
            f'<td style="padding:9px 14px;color:#475569;font-size:12px;font-family:Courier New,monospace;'
            f'border-bottom:1px solid #e2e8f0;">{x.get("fams_id") or "&mdash;"}</td>'
            f'</tr>'
        )
    if not rows_html:
        rows_html = ('<tr><td colspan="4" style="padding:14px;color:#94a3b8;font-size:13px;'
                     'font-family:Arial,sans-serif;text-align:center;">No items recorded.</td></tr>')

    remarks_display = remarks if remarks else "<em style='color:#9ca3af;'>No remarks</em>"
    remarks_html = (
        '<tr style="background-color:#f0fdf4;">'
        '<td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;'
        'color:#64748b;border-bottom:1px solid #f1f5f9;">Received Remarks</td>'
        '<td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;'
        'color:#166534;font-weight:600;border-bottom:1px solid #f1f5f9;">'
        f'{remarks_display}</td></tr>'
    )

    def _build_body(to_name):
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Material Returned — {gp.pass_no}</title>
<style>
  body,table,td{{margin:0;padding:0;}}
  table{{border-collapse:collapse !important;}}
  body{{background-color:#f1f5f9;font-family:Arial,sans-serif;}}
</style>
</head>
<body style="margin:0;padding:0;background-color:#f1f5f9;font-family:Arial,sans-serif;">
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color:#f1f5f9;padding:32px 0;">
  <tr><td align="center" valign="top">
    <table border="0" cellpadding="0" cellspacing="0" width="640"
           style="max-width:640px;background-color:#ffffff;border:1px solid #cbd5e1;">

      <!-- HEADER -->
      <tr>
        <td style="background-color:#166534;padding:28px 36px;">
          <table border="0" cellpadding="0" cellspacing="0" width="100%">
            <tr>
              <td width="46" valign="middle"
                  style="width:46px;background-color:#15803d;border:2px solid #22c55e;
                         padding:10px;text-align:center;">
                <span style="font-size:20px;color:#ffffff;">&#10003;</span>
              </td>
              <td style="padding-left:16px;" valign="middle">
                <div style="color:#bbf7d0;font-size:10px;font-family:Arial,sans-serif;
                            letter-spacing:2px;font-weight:700;text-transform:uppercase;">
                  GatePass Management System
                </div>
                <div style="color:#ffffff;font-size:20px;font-family:Arial,sans-serif;
                            font-weight:700;margin-top:4px;">
                  Material Returned
                </div>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- STATUS BAR -->
      <tr>
        <td style="background-color:#f8faff;border-bottom:1px solid #e2e8f0;padding:10px 36px;">
          <table border="0" cellpadding="0" cellspacing="0" width="100%">
            <tr>
              <td style="font-size:12px;font-family:Arial,sans-serif;color:#475569;">
                <span style="display:inline-block;background-color:{status_bg};
                             color:{status_color};font-weight:700;font-size:12px;
                             padding:4px 12px;border-radius:20px;">
                  {status_label}
                </span>
              </td>
              <td align="right" style="font-size:13px;font-family:Arial,sans-serif;
                                       font-weight:700;color:#1e3a5f;">{gp.pass_no}</td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- BODY -->
      <tr>
        <td style="padding:28px 36px 10px;">
          <p style="margin:0 0 6px;font-size:15px;font-family:Arial,sans-serif;color:#374151;">
            Dear <strong style="color:#1e293b;">{to_name}</strong>,
          </p>
          <p style="margin:0 0 24px;font-size:14px;font-family:Arial,sans-serif;
                    color:#64748b;line-height:1.7;">
            The returnable gate pass listed below has been
            <strong style="color:#166534;">physically returned</strong>
            and received by security. Please find the complete details below.
          </p>

          <!-- Pass Details -->
          <table border="0" cellpadding="0" cellspacing="0" width="100%"
                 style="border:1px solid #e2e8f0;margin-bottom:20px;">
            <tr>
              <td colspan="2" style="background-color:#f0f4f9;padding:10px 16px;
                                     border-bottom:1px solid #e2e8f0;">
                <span style="font-size:10px;font-family:Arial,sans-serif;font-weight:700;
                             letter-spacing:1.5px;color:#475569;text-transform:uppercase;">
                  Pass Details
                </span>
              </td>
            </tr>
            <tr style="background-color:#ffffff;">
              <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#64748b;border-bottom:1px solid #f1f5f9;">Pass Number</td>
              <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#1e293b;font-weight:700;border-bottom:1px solid #f1f5f9;">{gp.pass_no}</td>
            </tr>
            <tr style="background-color:#f8faff;">
              <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#64748b;border-bottom:1px solid #f1f5f9;">Requester</td>
              <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#1e293b;border-bottom:1px solid #f1f5f9;">{gp.requester or "&mdash;"}</td>
            </tr>
            <tr style="background-color:#ffffff;">
              <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#64748b;border-bottom:1px solid #f1f5f9;">Location</td>
              <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#1e293b;border-bottom:1px solid #f1f5f9;">{gp.location or "&mdash;"}</td>
            </tr>
            <tr style="background-color:#f8faff;">
              <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#64748b;border-bottom:1px solid #f1f5f9;">Sender / Vendor</td>
              <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#1e293b;border-bottom:1px solid #f1f5f9;">{gp.sender_vendor or "&mdash;"}</td>
            </tr>
            <tr style="background-color:#ffffff;">
              <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#64748b;border-bottom:1px solid #f1f5f9;">Emp / Vendor ID</td>
              <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#1e293b;border-bottom:1px solid #f1f5f9;">{gp.invoice_no or "&mdash;"}</td>
            </tr>
            <tr style="background-color:#f8faff;">
              <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#64748b;border-bottom:1px solid #f1f5f9;">Expected Return</td>
              <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#1e293b;border-bottom:1px solid #f1f5f9;">{exp_str}</td>
            </tr>
            <tr style="background-color:#ffffff;">
              <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#64748b;border-bottom:1px solid #f1f5f9;">Actual Return</td>
              <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:{status_color};font-weight:700;border-bottom:1px solid #f1f5f9;">{returned_str}</td>
            </tr>
            <tr style="background-color:#f8faff;">
              <td width="38%" style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#64748b;border-bottom:1px solid #f1f5f9;">Received By</td>
              <td style="padding:10px 16px;font-size:13px;font-family:Arial,sans-serif;color:#1e293b;font-weight:600;border-bottom:1px solid #f1f5f9;">{returned_by}</td>
            </tr>
            {remarks_html}
          </table>

          <!-- Item Details -->
          <table border="0" cellpadding="0" cellspacing="0" width="100%"
                 style="border:1px solid #e2e8f0;margin-bottom:26px;">
            <tr>
              <td colspan="4" style="background-color:#f0f4f9;padding:10px 16px;border-bottom:1px solid #e2e8f0;">
                <span style="font-size:10px;font-family:Arial,sans-serif;font-weight:700;
                             letter-spacing:1.5px;color:#475569;text-transform:uppercase;">
                  Item Details
                </span>
              </td>
            </tr>
            <tr style="background-color:#166534;">
              <th align="left" style="padding:9px 14px;color:#ffffff;font-size:12px;font-family:Arial,sans-serif;font-weight:600;">Item Name</th>
              <th align="center" style="padding:9px 10px;color:#ffffff;font-size:12px;font-family:Arial,sans-serif;font-weight:600;">Qty</th>
              <th align="left" style="padding:9px 14px;color:#ffffff;font-size:12px;font-family:Arial,sans-serif;font-weight:600;">Model Name</th>
              <th align="left" style="padding:9px 14px;color:#ffffff;font-size:12px;font-family:Arial,sans-serif;font-weight:600;">FAMS ID</th>
            </tr>
            {rows_html}
          </table>

          <!-- CTA -->
          <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
            <tr>
              <td align="center">
                <a href="{list_link}"
                   style="background-color:#166534;color:#ffffff;display:inline-block;
                          font-family:Arial,sans-serif;font-size:14px;font-weight:700;
                          padding:13px 32px;text-decoration:none;">
                  View GatePass List &rarr;
                </a>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- FOOTER -->
      <tr>
        <td style="background-color:#f8faff;border-top:1px solid #e2e8f0;padding:16px 36px;">
          <table border="0" cellpadding="0" cellspacing="0" width="100%">
            <tr>
              <td style="font-size:11px;font-family:Arial,sans-serif;color:#94a3b8;">
                This is an automated notification. Please do not reply to this email.
              </td>
              <td align="right" style="font-size:12px;font-family:Arial,sans-serif;font-weight:700;color:#1e3a5f;">
                GatePass &middot; Magnasoft
              </td>
            </tr>
          </table>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
</body></html>"""

    subject = f"Material Returned — {gp.pass_no} ({status_label})"

    def _send(to_email, to_name):
        if not to_email:
            return False
        body = _build_body(to_name)
        msg = MIMEMultipart("alternative")
        msg["From"]    = formataddr((str(Header(SMTP_FROM_NAME, "utf-8")), SMTP_MAIL))
        msg["To"]      = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "html", "utf-8"))
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(msg["From"], to_email, msg.as_string())
            return True
        except Exception:
            app.logger.exception("Returned email failed to %s (pass_no=%s)", to_email, gp.pass_no)
            return False

    def _dedup(contacts):
        """Return unique contacts by email address."""
        seen, result = set(), []
        for c in contacts:
            email = (c.email or "").strip().lower()
            if email and email not in seen:
                seen.add(email); result.append(c)
        return result

    # ── Notify only the department that raised this gatepass ─────────────────
    # Look up the requester's email in gatepass_contact_persons to find their dept.
    requester_email = (gp.raised_by_email or gp.requester or "").strip().lower()
    raising_role    = (gp.raised_by_role or "").strip().lower()

    # Returned email always goes directly to the person who raised the pass.
    creator_email = (gp.raised_by_email or "").strip().lower()
    if not creator_email:
        app.logger.warning(
            "Returned notify: no creator email on pass_no=%s (raised_by_email is empty)",
            gp.pass_no
        )
        return

    creator_name = creator_email.split("@")[0].replace(".", " ").title()
    sent = _send(creator_email, creator_name)
    app.logger.info(
        "Returned Email to creator %s (pass_no=%s): %s",
        creator_email, gp.pass_no, "sent" if sent else "FAILED"
    )


@app.route("/gatepass/mark-returned/<int:gp_id>", methods=["POST"])
@login_required_strict
@gatepass_access_required
def gatepass_mark_returned(gp_id):
    """
    Security marks a returnable gate pass as physically returned.
    Sets returned_at = now() and returned_by = guard name.
    
    Return status is then computed as:
      - returned_at.date() <= expected_return_date  → Returned On Time ✅
      - returned_at.date() >  expected_return_date  → Returned Late    ⚠️
    """
    gp = GatePass.query.get(gp_id)
    if not gp:
        return jsonify({"success": False, "message": "GatePass not found"}), 404
    if gp.returnable != "yes" and gp.pass_type != "returnable":
        return jsonify({"success": False, "message": "This gate pass is not returnable"}), 400
    if gp.returned_at:
        return jsonify({"success": False, "message": "Already marked as returned"}), 400
    try:
        data          = request.get_json(silent=True) or {}
        returned_by   = (data.get("returned_by") or "").strip()
        remarks       = (data.get("remarks") or "").strip()
        if not returned_by:
            return jsonify({"success": False, "message": "Guard / received-by name is required"}), 400

        now_ist = datetime.now(IST).replace(tzinfo=None)
        gp.returned_at = now_ist
        gp.returned_by = returned_by

        # Append return note to security_remarks using IST time
        note = f"[Returned on {now_ist.strftime('%d-%m-%Y %H:%M')} IST] Received by: {returned_by}"
        if remarks:
            note += f" | Remarks: {remarks}"
        existing = gp.security_remarks or ""
        gp.security_remarks = (existing + ("\n" if existing else "") + note).strip()

        # Compute on-time / late for logging
        if gp.expected_return_date:
            if gp.returned_at.date() <= gp.expected_return_date:
                return_label = "on-time"
            else:
                days_late = (gp.returned_at.date() - gp.expected_return_date).days
                return_label = f"late by {days_late} day(s)"
        else:
            return_label = "no expected date set"

        db.session.commit()
        app.logger.info(
            "GatePass %s marked returned by=%s status=%s", gp.pass_no, returned_by, return_label
        )

        # Send "Material Returned" email to IT + Admin
        try:
            send_gatepass_returned_notification(gp, returned_by, remarks, return_label)
        except Exception:
            app.logger.exception(
                "Failed to send returned notification for gatepass id=%s", gp_id
            )

        return jsonify({
            "success": True,
            "return_status": gp.return_status,
            "return_label": return_label
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


# ════════════════════════════════════════════════════════════════════════
# PARTIAL / FULL RETURN ROUTES
# ════════════════════════════════════════════════════════════════════════
@app.route("/gatepass/record-item-return/<int:gp_id>", methods=["POST"])
@login_required_strict
@gatepass_access_required
def gatepass_record_item_return(gp_id):
    """
    Security records return of one or more items on a returnable pass.
    Handles both partial and full returns transparently.

    Request JSON:
    {
      "received_by": "Guard Name",          # required
      "remarks":     "optional notes",
      "items": [                             # 1+ entries
        { "index": 0, "qty": 1 },
        { "index": 1, "qty": 2 }
      ]
    }
    'index' = position of the item in gp.item_description JSON array.

    Response:
    { "success": true, "return_status_overall": "partial" | "completed", ... }
    """
    # ── Role guard: only security (and superadmin) can record returns ────
    role = (get_current_role() or "").lower().replace(" ", "")
    if role not in ("security", "superadmin"):
        return jsonify({
            "success": False,
            "message": "Only Security can record item returns."
        }), 403

    gp = GatePass.query.get(gp_id)
    if not gp:
        return jsonify({"success": False, "message": "GatePass not found"}), 404

    if gp.returnable != "yes" and gp.pass_type != "returnable":
        return jsonify({"success": False, "message": "This pass is not returnable."}), 400

    if gp.security_status != "Approved":
        return jsonify({
            "success": False,
            "message": "Pass must be security-approved before returns can be recorded."
        }), 400

    if gp.return_status_overall == "completed":
        return jsonify({"success": False, "message": "All items already returned."}), 400

    data          = request.get_json(silent=True) or {}
    received_by   = (data.get("received_by") or "").strip()
    remarks       = (data.get("remarks") or "").strip()
    items_payload = data.get("items") or []

    if not received_by:
        return jsonify({"success": False, "message": "Received-by (guard name) is required."}), 400
    if not isinstance(items_payload, list) or not items_payload:
        return jsonify({"success": False, "message": "At least one item must be selected."}), 400

    try:
        items = json.loads(gp.item_description or "[]")
    except Exception:
        items = []
    if not items:
        return jsonify({"success": False, "message": "No items recorded on this pass."}), 400

    try:
        now_ist       = datetime.now(IST).replace(tzinfo=None)
        actor_email   = get_current_username() or ""
        event_entries = []   # rows for returns_history

        # ── Validate + apply each entry ──────────────────────────────────
        for entry in items_payload:
            try:
                idx     = int(entry.get("index"))
                qty_ret = int(entry.get("qty") or 0)
            except (TypeError, ValueError):
                return jsonify({
                    "success": False,
                    "message": "Invalid item index or qty in payload."
                }), 400

            if qty_ret <= 0:
                continue
            if idx < 0 or idx >= len(items):
                return jsonify({
                    "success": False,
                    "message": f"Item index {idx} is out of range."
                }), 400

            item        = items[idx]
            outstanding = _item_outstanding(item)
            if outstanding <= 0:
                return jsonify({
                    "success": False,
                    "message": f"Item '{item.get('item_name') or idx}' is already fully returned."
                }), 400
            if qty_ret > outstanding:
                return jsonify({
                    "success": False,
                    "message": (
                        f"Cannot return {qty_ret} of "
                        f"'{item.get('item_name') or idx}' — "
                        f"only {outstanding} outstanding."
                    )
                }), 400

            # Apply
            existing = _safe_int(item.get("qty_returned"), 0)
            item["qty_returned"] = existing + qty_ret
            items[idx] = item

            event_entries.append({
                "item_index":   idx,
                "item_name":    item.get("item_name") or "",
                "serial_no":    item.get("serial_no") or "",
                "qty_returned": qty_ret,
                "received_by":  received_by,
                "remarks":      remarks,
                "returned_at":  now_ist.strftime("%Y-%m-%d %H:%M:%S"),
                "actor_email":  actor_email,
            })

        if not event_entries:
            return jsonify({
                "success": False,
                "message": "No valid items. Enter a quantity greater than zero."
            }), 400

        # ── Persist item JSON ────────────────────────────────────────────
        gp.item_description = json.dumps(items, ensure_ascii=False)

        # ── Append to returns_history JSON ───────────────────────────────
        try:
            history = json.loads(gp.returns_history or "[]")
            if not isinstance(history, list):
                history = []
        except Exception:
            history = []
        history.extend(event_entries)
        gp.returns_history = json.dumps(history, ensure_ascii=False)

        # ── Recompute status ─────────────────────────────────────────────
        gp.last_return_at = now_ist
        new_status = recompute_gatepass_return_status(gp)

        # Mirror to legacy field
        if new_status == "completed":
            gp.returned_by = received_by

        # Append a short note to security_remarks (same style as mark-returned)
        note_lines = [
            f"[Item return on {now_ist.strftime('%d-%m-%Y %H:%M')} IST] "
            f"Received by: {received_by}"
        ]
        for ev in event_entries:
            note_lines.append(
                f"   • {ev['item_name']} × {ev['qty_returned']}"
                + (f" (SN: {ev['serial_no']})" if ev['serial_no'] else "")
            )
        if remarks:
            note_lines.append(f"   Remarks: {remarks}")
        note = "\n".join(note_lines)
        existing = gp.security_remarks or ""
        gp.security_remarks = (existing + ("\n" if existing else "") + note).strip()

        db.session.commit()

        app.logger.info(
            "GatePass %s: %d item-return event(s) by=%s -> status=%s",
            gp.pass_no, len(event_entries), received_by, new_status
        )

        # Fire legacy notification email only on full completion
        if new_status == "completed":
            try:
                send_gatepass_returned_notification(gp, received_by, remarks, "completed")
            except Exception:
                app.logger.exception(
                    "Failed to send returned notification for gatepass id=%s", gp_id
                )

        return jsonify({
            "success": True,
            "return_status_overall": new_status,
            "events_recorded": len(event_entries),
        })

    except Exception as e:
        db.session.rollback()
        app.logger.exception("record-item-return failed for gp_id=%s", gp_id)
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/gatepass/return-info/<int:gp_id>")
@login_required_strict
@gatepass_access_required
def gatepass_return_info(gp_id):
    """
    Returns JSON used by the 'Record Return' modal and the return-history
    panel. No role restriction — view only.
    """
    gp = GatePass.query.get(gp_id)
    if not gp:
        return jsonify({"success": False, "message": "Not found"}), 404

    try:
        items = json.loads(gp.item_description or "[]")
    except Exception:
        items = []
    try:
        history = json.loads(gp.returns_history or "[]")
        if not isinstance(history, list):
            history = []
    except Exception:
        history = []

    items_out = []
    for idx, it in enumerate(items):
        qty_int = _safe_int(it.get("qty"), 0)
        qty_ret = _safe_int(it.get("qty_returned"), 0)
        items_out.append({
            "index":        idx,
            "item_name":    it.get("item_name") or "",
            "serial_no":    it.get("serial_no") or "",
            "fams_id":      it.get("fams_id")   or "",
            "qty":          qty_int if qty_int > 0 else it.get("qty") or "",
            "qty_numeric":  qty_int,
            "qty_returned": qty_ret,
            "outstanding":  _item_outstanding(it),
            "status":       _item_return_status(it),
        })

    # Newest first for display
    history_sorted = sorted(history, key=lambda h: h.get("returned_at", ""), reverse=True)

    return jsonify({
        "success": True,
        "pass_no":               gp.pass_no,
        "return_status_overall": gp.return_status_overall,
        "last_return_at":        gp.last_return_at.strftime("%d-%m-%Y %H:%M")     if gp.last_return_at     else None,
        "fully_returned_at":     gp.fully_returned_at.strftime("%d-%m-%Y %H:%M") if gp.fully_returned_at else None,
        "items":   items_out,
        "history": history_sorted,
    })


@app.route("/gatepass/list")
@login_required_strict
@gatepass_access_required
def gatepass_list():
    rows = GatePass.query.order_by(GatePass.created_at.desc()).all()
    # Build a {id: items_json_string} map to pass safely to template
    items_map = {}
    for r in rows:
        if r.item_description:
            items_map[r.id] = r.item_description
    items_map_json = json.dumps(items_map)
    # Resolve role for role-based UI (DB > session > cookie)
    db_user = getattr(g, "current_user", None)
    if db_user and getattr(db_user, "role", None):
        page_role = (db_user.role or "").strip().lower()
    elif session.get("role"):
        page_role = (session.get("role") or "").strip().lower()
    else:
        page_role = (request.cookies.get("auth_role") or "").strip().lower()
    # Normalize both "super admin" and "superadmin" → "superadmin" for JS
    if page_role in ("super admin", "superadmin"):
        page_role = "superadmin"
    return render_template("gatepass/gatepass_list.html", rows=rows,
                           items_map_json=items_map_json, page_role=page_role)

@app.route('/gatepass/download_overdue_csv')
@login_required_strict
@gatepass_access_required
def gatepass_download_overdue_csv():
    import csv
    from io import StringIO
    from datetime import timedelta

    today      = datetime.now(IST).replace(tzinfo=None).date()
    pass_type  = request.args.get('type', 'all').lower()
    range_type = request.args.get('range', 'custom').lower()

    # Date range applies to created_at (when the gate pass was created)
    if range_type == 'weekly':
        start_date = today - timedelta(days=today.weekday())
        end_date   = start_date + timedelta(days=6)
    elif range_type == 'monthly':
        start_date = today.replace(day=1)
        if today.month == 12:
            end_date = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            end_date = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
    else:  # custom
        try:
            start_date = datetime.strptime(request.args.get('from', ''), '%Y-%m-%d').date()
            end_date   = datetime.strptime(request.args.get('to',   ''), '%Y-%m-%d').date()
        except ValueError:
            return "Invalid or missing date parameters.", 400

    start_dt = datetime.combine(start_date, datetime.min.time())
    end_dt   = datetime.combine(end_date,   datetime.max.time())

    q = GatePass.query.filter(
        GatePass.returnable == 'yes',
        GatePass.expected_return_date != None,
        GatePass.expected_return_date < today,
        GatePass.created_at >= start_dt,
        GatePass.created_at <= end_dt
    )
    if pass_type in ('inward', 'outward'):
        q = q.filter(GatePass.pass_type == pass_type)

    rows = q.order_by(GatePass.expected_return_date.asc()).all()

    sio    = StringIO()
    writer = csv.writer(sio)
    writer.writerow([
        'Pass No', 'Type', 'Requester', 'Location',
        'Expected Return Date', 'Days Overdue',
        'IT Status', 'IT Action At',
        'Admin Status', 'Admin Action At',
        'Created At', 'Items (JSON)'
    ])

    for r in rows:
        days_overdue = str((today - r.expected_return_date).days) + " days"
        it_status    = "Approved" if r.it_approved_at else ("Declined" if r.it_declined_at else "Pending")
        it_at        = r.it_approved_at or r.it_declined_at
        admin_status = "Approved" if r.admin_approved_at else ("Declined" if r.admin_declined_at else "Pending")
        admin_at     = r.admin_approved_at or r.admin_declined_at

        writer.writerow([
            r.pass_no or '',
            r.pass_type or '',
            r.requester or '',
            r.location or '',
            r.expected_return_date.strftime('%d-%m-%Y'),
            days_overdue,
            it_status,
            it_at.strftime('%d-%m-%Y %H:%M') if it_at else '',
            admin_status,
            admin_at.strftime('%d-%m-%Y %H:%M') if admin_at else '',
            r.created_at.strftime('%d-%m-%Y %H:%M') if r.created_at else '',
            r.item_description or '',
        ])

    csv_body = sio.getvalue()
    sio.close()

    filename = f"gatepass_overdue_{today.strftime('%d-%m-%Y')}.csv"
    resp = Response(csv_body, mimetype='text/csv; charset=utf-8')
    resp.headers.set("Content-Disposition", "attachment", filename=filename)
    return resp

@app.route('/gatepass/download_csv')
@login_required_strict
@gatepass_access_required
def gatepass_download_csv():
    """
    Query params:
      range  = custom | weekly | monthly          (default: custom)
      from   = YYYY-MM-DD                         (required for custom)
      to     = YYYY-MM-DD                         (required for custom)
      type   = all | inward | outward             (default: all)
    """
    import csv
    from io import StringIO
    from datetime import datetime, timedelta

    range_type = request.args.get('range', 'custom').lower()
    pass_type  = request.args.get('type', 'all').lower()
    today      = datetime.now(IST).replace(tzinfo=None).date()

    # ── Date range resolution ────────────────────────────────────────────
    if range_type == 'weekly':
        # Mon–Sun of the current week
        start_date = today - timedelta(days=today.weekday())
        end_date   = start_date + timedelta(days=6)

    elif range_type == 'monthly':
        # 1st → last day of current month
        start_date = today.replace(day=1)
        # last day: go to 1st of next month, subtract 1 day
        if today.month == 12:
            end_date = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            end_date = today.replace(month=today.month + 1, day=1) - timedelta(days=1)

    else:  # custom
        try:
            start_date = datetime.strptime(request.args.get('from', ''), '%Y-%m-%d').date()
            end_date   = datetime.strptime(request.args.get('to',   ''), '%Y-%m-%d').date()
        except ValueError:
            return "Invalid or missing date parameters. Use ?from=YYYY-MM-DD&to=YYYY-MM-DD", 400

    if start_date > end_date:
        return "from date must be before to date", 400

    # ── Query ────────────────────────────────────────────────────────────
    # Include all records created on end_date (up to 23:59:59)
    end_dt = datetime.combine(end_date, datetime.max.time())
    start_dt = datetime.combine(start_date, datetime.min.time())

    q = GatePass.query.filter(
        GatePass.created_at >= start_dt,
        GatePass.created_at <= end_dt
    )

    if pass_type in ('inward', 'outward'):
        q = q.filter(GatePass.pass_type == pass_type)

    rows = q.order_by(GatePass.created_at.desc()).all()

    # ── Build CSV ────────────────────────────────────────────────────────
    sio = StringIO()
    writer = csv.writer(sio)

    writer.writerow([
        'Pass No', 'Type', 'Requester', 'Location',
        'Sender / Vendor', 'Vehicle Details', 'Invoice No',
        'Purpose', 'Destination',
        'Returnable', 'Expected Return Date',
        'Status', 'IT Approved At', 'Admin Approved At',
        'Created At', 'Items (JSON)'
    ])

    for r in rows:
        writer.writerow([
            r.pass_no or '',
            r.pass_type or '',
            r.requester or '',
            r.location or '',
            r.sender_vendor or '',
            r.contact_details or '',
            r.invoice_no or '',
            r.purpose or '',
            r.destination or '',
            r.returnable or '',
            r.expected_return_date.strftime('%d-%m-%Y') if r.expected_return_date else '',
            r.status or '',
            r.it_approved_at.strftime('%d-%m-%Y %H:%M')    if r.it_approved_at    else '',
            r.admin_approved_at.strftime('%d-%m-%Y %H:%M') if r.admin_approved_at else '',
            r.created_at.strftime('%d-%m-%Y %H:%M')        if r.created_at        else '',
            r.item_description or '',
        ])

    csv_body = sio.getvalue()
    sio.close()

    # ── Filename ─────────────────────────────────────────────────────────
    label = range_type if range_type in ('weekly', 'monthly') else f"{start_date}_to_{end_date}"
    filename = f"gatepass_{pass_type}_{label}.csv"

    resp = Response(csv_body, mimetype='text/csv; charset=utf-8')
    resp.headers.set("Content-Disposition", "attachment", filename=filename)
    return resp

@app.route('/api/contact_person')
@login_required_strict
@gatepass_access_required
def contact_person():
    location = request.args.get('location')
    record = db.session.query(GatepassContactPerson)\
        .filter_by(location=location, is_active=1).first()
    if record:
        return jsonify({'person_name': record.person_name, 'department': record.department})
    return jsonify({}), 404

@app.route('/api/next_record_no')
@login_required_strict
@gatepass_access_required
def next_record_no():
    type_  = request.args.get('type')   # 'ret' or 'nonret'
    prefix = "GP-R" if type_ == 'ret' else "GP-NR"

    # Get the highest existing number for this prefix safely
    last = db.session.query(GatePass.pass_no)\
        .filter(GatePass.pass_no.like(f"{prefix}-%")).all()

    max_seq = 0
    for (pno,) in last:
        try:
            seq = int(pno.replace(prefix + "-", ""))
            if seq > max_seq:
                max_seq = seq
        except Exception:
            pass

    return jsonify({'next_no': max_seq + 1})

@app.route("/get_contact_person_by_email")
@login_required_strict
@gatepass_access_required
def get_contact_person_by_email():
    email = get_current_username()  # logged-in user email

    if not email:
        return jsonify({"success": False, "message": "User not found"})

    # Fetch name and department from the users table directly
    user = User.query.filter_by(username=email).first()

    if user:
        # Use user.name if set, otherwise derive from email prefix
        display_name = (user.name or "").strip()
        if not display_name:
            display_name = email.split("@")[0].replace(".", " ").title()
        return jsonify({
            "success": True,
            "person_name": display_name,
            "department": (user.department or user.role or "").strip(),
            "location": ""   # location is selected manually on the form
        })
    else:
        return jsonify({"success": False, "message": "No match found"})

# ── Daily overdue notification job ──────────────────────────────────────────
@app.route("/internal/send-overdue-notifications", methods=["POST"])
def send_overdue_notifications_job():
    """
    Internal endpoint for scheduled daily overdue notifications.
    Finds all returnable gate passes where expected_return_date < today
    (i.e. strictly yesterday or earlier) and sends one notification per pass.
    Protect with a secret token in production.
    """
    secret = request.headers.get("X-Internal-Token", "")
    expected = os.environ.get("INTERNAL_JOB_TOKEN", "")
    if expected and secret != expected:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    from datetime import date as _date
    today = _date.today()

    # Only passes where:
    #   - returnable = yes
    #   - expected_return_date is strictly BEFORE today (next day or later)
    #   - NOT yet returned (returned_at is NULL)
    overdue_passes = GatePass.query.filter(
        GatePass.returnable == "yes",
        GatePass.expected_return_date != None,
        GatePass.expected_return_date < today,   # < today = yesterday or earlier
        GatePass.returned_at == None             # skip already-returned items
    ).all()

    sent_count = 0
    failed_count = 0
    for gp in overdue_passes:
        try:
            send_gatepass_overdue_notification(gp)
            sent_count += 1
        except Exception:
            app.logger.exception("Overdue job: failed to notify for gatepass id=%s", gp.id)
            failed_count += 1

    app.logger.info("Overdue job: processed=%d sent=%d failed=%d date=%s",
                    len(overdue_passes), sent_count, failed_count, today)
    return jsonify({
        "success": True,
        "date": str(today),
        "overdue_count": len(overdue_passes),
        "sent": sent_count,
        "failed": failed_count
    })



@app.route("/internal/test-overdue-email/<int:gp_id>", methods=["GET"])
@login_required_strict
def test_overdue_email(gp_id):
    """
    DEV/TEST ONLY — manually trigger overdue email for a single gate pass by ID.
    Visit in browser: /internal/test-overdue-email/5
    Shows which contacts were found and whether email sent.
    Remove or restrict this route in production.
    """
    from datetime import date as _date
    gp = GatePass.query.get(gp_id)
    if not gp:
        return jsonify({"error": f"GatePass id={gp_id} not found"}), 404

    location = (gp.location or "").strip()
    today    = _date.today()

    # Diagnose contacts
    it_contacts = GatepassContactPerson.query.filter(
        func.lower(GatepassContactPerson.department) == "it",
        GatepassContactPerson.is_active == 1
    ).all()
    it_loc_contacts = [c for c in it_contacts
                       if c.location and c.location.lower() == location.lower()]

    admin_contacts = GatepassContactPerson.query.filter(
        func.lower(GatepassContactPerson.department) == "admin",
        GatepassContactPerson.is_active == 1
    ).all()
    admin_loc_contacts = [c for c in admin_contacts
                          if c.location and c.location.lower() == location.lower()]

    diag = {
        "pass_no":              gp.pass_no,
        "location_on_pass":     location,
        "returnable":           gp.returnable,
        "expected_return_date": str(gp.expected_return_date),
        "today":                str(today),
        "days_overdue":         (today - gp.expected_return_date).days if gp.expected_return_date else None,
        "returned_at":          str(gp.returned_at) if gp.returned_at else None,
        "it_contacts_all_locations": [{"name": c.person_name, "email": c.email, "location": c.location} for c in it_contacts],
        "it_contacts_this_location": [{"name": c.person_name, "email": c.email} for c in it_loc_contacts],
        "admin_contacts_this_location": [{"name": c.person_name, "email": c.email} for c in admin_loc_contacts],
    }

    # Actually send
    try:
        send_gatepass_overdue_notification(gp)
        diag["email_send"] = "triggered — check Flask logs for per-contact result"
    except Exception as e:
        diag["email_send"] = f"FAILED: {e}"

    return jsonify(diag)


# ── DAILY OVERDUE EMAIL SCHEDULER ───────────────────────────────────────────
# Runs automatically every day at 10:00 AM IST (Asia/Kolkata).
# No cron or external task needed — APScheduler runs inside the Flask process.
# ─────────────────────────────────────────────────────────────────────────────

def run_daily_overdue_job():
    """
    Called by APScheduler every day at 10:00 AM IST.
    Runs inside the Flask app context so DB and config are available.
    """
    with app.app_context():
        from datetime import date as _date
        IST   = pytz.timezone("Asia/Kolkata")
        today = datetime.now(IST).date()   # use IST date, not UTC

        app.logger.info("=== Daily Overdue Job START | IST date: %s ===", today)

        # ── Query: returnable, not yet returned, not declined, past due date ──
        overdue_passes = GatePass.query.filter(
            GatePass.returnable == "yes",
            GatePass.expected_return_date != None,
            GatePass.expected_return_date < today,      # strictly before today
            GatePass.returned_at == None,               # not yet physically returned
            GatePass.security_status != "Declined",     # item was never sent out
        ).all()

        app.logger.info("Overdue job: found %d overdue pass(es) for %s", len(overdue_passes), today)

        sent_count   = 0
        failed_count = 0
        skipped_count = 0

        for gp in overdue_passes:
            # Also skip if IT or Admin declined (item blocked before gate)
            if gp.it_declined_at or gp.admin_declined_at:
                app.logger.info(
                    "Overdue job: skipping %s — IT/Admin declined, item never left", gp.pass_no
                )
                skipped_count += 1
                continue
            try:
                send_gatepass_overdue_notification(gp)
                sent_count += 1
                app.logger.info("Overdue job: notification sent for %s", gp.pass_no)
            except Exception:
                app.logger.exception(
                    "Overdue job: FAILED to notify for pass_no=%s id=%s", gp.pass_no, gp.id
                )
                failed_count += 1

        app.logger.info(
            "=== Daily Overdue Job END | sent=%d  failed=%d  skipped=%d  date=%s ===",
            sent_count, failed_count, skipped_count, today
        )


_scheduler_started = False   # module-level flag — survives reloader in same process

def start_scheduler():
    """
    Start APScheduler with a daily CronTrigger at 10:00 AM IST.
    Uses a module-level flag so it starts exactly ONCE per process,
    guarding against Flask debug reloader double-start.
    """
    global _scheduler_started
    if _scheduler_started:
        app.logger.info("Scheduler already started in this process — skipping duplicate start.")
        return
    _scheduler_started = True

    IST = pytz.timezone("Asia/Kolkata")
    scheduler = BackgroundScheduler(timezone=IST)
    scheduler.add_job(
        func    = run_daily_overdue_job,
        trigger = CronTrigger(hour=10, minute=0, timezone=IST),
        id      = "daily_overdue_notification",
        name    = "Daily Overdue GatePass Email at 10AM IST",
        replace_existing = True,
    )
    scheduler.start()
    app.logger.info(
        "APScheduler started — daily overdue job scheduled at 10:00 AM IST (pid=%s)", os.getpid()
    )
    import atexit
    atexit.register(lambda: scheduler.shutdown(wait=False))

# Start scheduler when app module loads (works with gunicorn + Flask dev server)
with app.app_context():
    start_scheduler()

@app.route("/user-management-preview")
def user_management_preview():
    return render_template("user_management.html")


# ── GATEPASS ACKNOWLEDGE ──────────────────────────────────────────────────────

@app.route("/gatepass/acknowledge/<token>", methods=["GET", "POST"])
def gatepass_acknowledge(token):
    gp = GatePass.query.filter_by(ack_token=token).first()

    if not gp:
        return render_template("gatepass/gatepass_ack.html", error="invalid", gp=None, token=token, items=[])

    if gp.ack_token_sent_at:
        expiry = gp.ack_token_sent_at + timedelta(days=7)
        if datetime.now(IST).replace(tzinfo=None) > expiry:
            return render_template("gatepass/gatepass_ack.html", error="expired", gp=None, token=token, items=[])

    if gp.acknowledged_at:
        return render_template("gatepass/gatepass_ack.html", error="used", gp=gp, token=token, items=[])

    if request.method == "GET":
        try:
            items = json.loads(gp.item_description or "[]")
        except Exception:
            items = []
        return render_template("gatepass/gatepass_ack.html", error=None, gp=gp, token=token, items=items)

    # POST — save acknowledgement
    data        = request.get_json(silent=True) or {}
    ack_by      = (data.get("acknowledged_by") or "").strip()
    ack_company = (data.get("ack_company") or "").strip()

    if not ack_by:
        return jsonify({"success": False, "message": "Your name is required."}), 400

    gp.acknowledged_by = ack_by
    gp.ack_company     = ack_company
    gp.acknowledged_at = datetime.now(IST).replace(tzinfo=None)

    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"success": False, "message": "Database error. Please try again."}), 500

    try:
        _send_ack_confirmation_to_raiser(gp)
    except Exception:
        app.logger.exception("Failed to send ack confirmation for gatepass id=%s", gp.id)

    return jsonify({"success": True, "message": "Acknowledged successfully."})


def _send_ack_confirmation_to_raiser(gp):
    """Notify the gatepass raiser that the collector has acknowledged receipt."""
    raiser_email = (gp.raised_by_email or "").strip()
    if not raiser_email:
        return
    import html as _html
    subject  = f"Items Acknowledged — GatePass {gp.pass_no}"
    ack_date = gp.acknowledged_at.strftime('%d-%m-%Y %H:%M') if gp.acknowledged_at else "—"
    body = f"""<html><body style="font-family:Arial,sans-serif;background:#f1f5f9;padding:32px 0;margin:0;">
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background:#f1f5f9;">
<tr><td align="center">
<table border="0" cellpadding="0" cellspacing="0" width="560"
       style="background:#ffffff;border:1px solid #cbd5e1;max-width:560px;">
  <tr><td style="background:#065f46;padding:22px 28px;">
    <div style="color:#6ee7b7;font-size:10px;letter-spacing:2px;font-weight:700;
                text-transform:uppercase;">GatePass &mdash; Magnasoft</div>
    <div style="color:#ffffff;font-size:18px;font-weight:700;margin-top:4px;">
      &#10003; Items Acknowledged
    </div>
  </td></tr>
  <tr><td style="padding:24px 28px;">
    <p style="font-size:14px;color:#374151;margin:0 0 16px;">
      Items for GatePass <strong>{_html.escape(gp.pass_no or '')}</strong>
      have been acknowledged by the collector.
    </p>
    <table border="0" cellpadding="0" cellspacing="0" width="100%"
           style="border:1px solid #e2e8f0;">
      <tr style="background:#f4f6fb;">
        <td style="padding:8px 14px;font-size:12px;font-weight:700;color:#64748b;
                   border-bottom:1px solid #e2e8f0;">Acknowledged By</td>
        <td style="padding:8px 14px;font-size:13px;color:#1a202c;
                   border-bottom:1px solid #e2e8f0;">{_html.escape(gp.acknowledged_by or '—')}</td>
      </tr>
      <tr>
        <td style="padding:8px 14px;font-size:12px;font-weight:700;color:#64748b;
                   border-bottom:1px solid #e2e8f0;">Company / Designation</td>
        <td style="padding:8px 14px;font-size:13px;color:#1a202c;
                   border-bottom:1px solid #e2e8f0;">{_html.escape(gp.ack_company or '—')}</td>
      </tr>
      <tr style="background:#f4f6fb;">
        <td style="padding:8px 14px;font-size:12px;font-weight:700;color:#64748b;">
          Date &amp; Time</td>
        <td style="padding:8px 14px;font-size:13px;color:#1a202c;">{ack_date}</td>
      </tr>
    </table>
  </td></tr>
  <tr><td style="background:#f8faff;border-top:1px solid #e2e8f0;padding:12px 28px;
                 font-size:11px;color:#94a3b8;">
    Automated notification &mdash; Magnasoft GatePass System
  </td></tr>
</table></td></tr></table>
</body></html>"""
    message = MIMEMultipart("alternative")
    message["From"]    = formataddr((str(Header(SMTP_FROM_NAME, "utf-8")), SMTP_MAIL))
    message["To"]      = raiser_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "html", "utf-8"))
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(message["From"], raiser_email, message.as_string())


def _send_ack_email(gp, to_email, token):
    """Send acknowledgement link email to the handover person."""
    import html as _html
    try:
        base = VISITOR_BASE_URL or "http://myportal.magnasoft.com"
    except Exception:
        base = "http://myportal.magnasoft.com"
    ack_link = f"{base.rstrip('/')}/gatepass/acknowledge/{token}"

    try:
        items = json.loads(gp.item_description or "[]")
    except Exception:
        items = []

    items_rows = ""
    for i, x in enumerate(items):
        bg = "#f8f9fc" if i % 2 else "#ffffff"
        items_rows += (
            f'<tr style="background:{bg};">'
            f'<td style="padding:8px 14px;font-size:13px;font-family:Arial,sans-serif;'
            f'border-bottom:1px solid #e2e8f0;">{_html.escape(str(x.get("item_name") or "—"))}</td>'
            f'<td style="padding:8px 10px;font-size:13px;font-family:Arial,sans-serif;'
            f'text-align:center;border-bottom:1px solid #e2e8f0;">{_html.escape(str(x.get("qty") or "—"))}</td>'
            f'<td style="padding:8px 14px;font-size:12px;font-family:Arial,sans-serif;'
            f'border-bottom:1px solid #e2e8f0;">{_html.escape(str(x.get("serial_no") or "—"))}</td>'
            f'</tr>'
        )

    subject = f"Please Acknowledge Receipt — GatePass {gp.pass_no}"
    body = f"""<html><body style="font-family:Arial,sans-serif;background:#f1f5f9;padding:32px 0;margin:0;">
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="background:#f1f5f9;">
<tr><td align="center">
<table border="0" cellpadding="0" cellspacing="0" width="620"
       style="background:#ffffff;border:1px solid #cbd5e1;max-width:620px;">
  <tr><td style="background:#1e3a5f;padding:24px 32px;">
    <div style="color:#93c5fd;font-size:10px;letter-spacing:2px;font-weight:700;
                text-transform:uppercase;">GatePass Management &mdash; Magnasoft</div>
    <div style="color:#ffffff;font-size:20px;font-weight:700;margin-top:4px;">
      Acknowledgement Required
    </div>
  </td></tr>
  <tr><td style="padding:28px 32px;">
    <p style="font-size:14px;color:#374151;margin:0 0 16px;">
      You are listed as the collector for the following items from
      <strong>Magnasoft Consulting pvt ltd</strong>.
    </p>
    <table border="0" cellpadding="0" cellspacing="0" width="100%"
           style="border:1px solid #e2e8f0;margin-bottom:20px;">
      <tr style="background:#f4f6fb;">
        <td style="padding:8px 14px;font-size:11px;font-weight:700;text-transform:uppercase;
                   letter-spacing:0.5px;color:#64748b;border-bottom:1px solid #e2e8f0;">Pass No</td>
        <td style="padding:8px 14px;font-size:13px;font-weight:700;color:#1e3a5f;
                   border-bottom:1px solid #e2e8f0;">{_html.escape(gp.pass_no or '')}</td>
      </tr>
      <tr>
        <td style="padding:8px 14px;font-size:11px;font-weight:700;text-transform:uppercase;
                   letter-spacing:0.5px;color:#64748b;border-bottom:1px solid #e2e8f0;">Location</td>
        <td style="padding:8px 14px;font-size:13px;color:#374151;
                   border-bottom:1px solid #e2e8f0;">{_html.escape(gp.location or '—')}</td>
      </tr>
      <tr style="background:#f4f6fb;">
        <td style="padding:8px 14px;font-size:11px;font-weight:700;text-transform:uppercase;
                   letter-spacing:0.5px;color:#64748b;">Date</td>
        <td style="padding:8px 14px;font-size:13px;color:#374151;">
          {(gp.ack_token_sent_at or gp.security_checked_at or gp.created_at).strftime('%d-%m-%Y') if (gp.ack_token_sent_at or gp.security_checked_at or gp.created_at) else '—'}
        </td>
      </tr>
    </table>
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;
                color:#64748b;margin-bottom:8px;">Items Being Collected</div>
    <table border="0" cellpadding="0" cellspacing="0" width="100%"
           style="border:1px solid #e2e8f0;margin-bottom:24px;">
      <tr style="background:#f4f6fb;">
        <th style="padding:8px 14px;font-size:11px;font-weight:700;text-transform:uppercase;
                   color:#64748b;text-align:left;border-bottom:1px solid #e2e8f0;">Item</th>
        <th style="padding:8px 10px;font-size:11px;font-weight:700;text-transform:uppercase;
                   color:#64748b;text-align:center;border-bottom:1px solid #e2e8f0;">Qty</th>
        <th style="padding:8px 14px;font-size:11px;font-weight:700;text-transform:uppercase;
                   color:#64748b;text-align:left;border-bottom:1px solid #e2e8f0;">Model/Serial</th>
      </tr>
      {items_rows}
    </table>
    <div style="text-align:center;margin-bottom:20px;">
      <a href="{ack_link}"
         style="display:inline-block;background:#1a56db;color:#ffffff;text-decoration:none;
                padding:13px 32px;font-size:15px;font-weight:700;font-family:Arial,sans-serif;">
        &#10003; Acknowledge Receipt
      </a>
    </div>
    <p style="font-size:12px;color:#94a3b8;text-align:center;margin:0;">
      This link is valid for 7 days. If you did not collect these items, ignore this email.
    </p>
  </td></tr>
  <tr><td style="background:#f8faff;border-top:1px solid #e2e8f0;padding:14px 32px;
                 font-size:11px;color:#94a3b8;">
    Automated notification from Magnasoft GatePass Management System.
  </td></tr>
</table>
</td></tr></table>
</body></html>"""

    message = MIMEMultipart("alternative")
    message["From"]    = formataddr((str(Header(SMTP_FROM_NAME, "utf-8")), SMTP_MAIL))
    message["To"]      = to_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "html", "utf-8"))
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(message["From"], to_email, message.as_string())


# ── GATEPASS PRINT ────────────────────────────────────────────────────────────

@app.route("/gatepass/print/<int:gp_id>")
@login_required_strict
@gatepass_access_required
def gatepass_print(gp_id):
    gp = GatePass.query.get(gp_id)
    if not gp:
        return "GatePass not found", 404
    if not gp.acknowledged_at:
        return "Print is available only after collector acknowledgement.", 403
    try:
        items = json.loads(gp.item_description or "[]")
    except Exception:
        items = []
    return render_template("gatepass/gatepass_print.html", gp=gp, items=items)

@app.route("/gatepass/ack-status/<int:gp_id>")
@login_required_strict
@gatepass_access_required
def gatepass_ack_status(gp_id):
    gp = GatePass.query.get(gp_id)
    if not gp:
        return jsonify({"acknowledged": False}), 404
    return jsonify({
        "acknowledged":    bool(gp.acknowledged_at),
        "acknowledged_by": gp.acknowledged_by or "",
        "ack_company":     gp.ack_company or "",
        "acknowledged_at": gp.acknowledged_at.strftime('%d-%m-%Y %H:%M') if gp.acknowledged_at else ""
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)