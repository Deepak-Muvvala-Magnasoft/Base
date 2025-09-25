import os
import pandas as pd
import json
import smtplib
from flask import g

from flask import (
    Flask, render_template, request, redirect, url_for, flash, jsonify,
    make_response
)
from flask_sqlalchemy import SQLAlchemy
# from flask_pymongo import PyMongo
# from bson.objectid import ObjectId
from datetime import datetime
# from authlib.integrations.flask_client import OAuth
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text
# from flask import redirect, url_for
from sqlalchemy import func, inspect
from werkzeug.security import generate_password_hash, check_password_hash
from config import (
    MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, MYSQL_PORT,
    SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_MAIL,
    VISITOR_BASE_URL, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
)
# from datetime import datetime
from flask_dance.contrib.google import make_google_blueprint, google
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
# from urllib.parse import quote_plus
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest

app = Flask(__name__)

from werkzeug.middleware.proxy_fix import ProxyFix
# Trust first proxy's X-Forwarded-* headers (adjust counts if you have more hops)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ.get("FLASK_SECRET", "super_secret_key")
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['PREFERRED_URL_SCHEME'] = 'https'


# ----------------- Cookie-based auth helpers (paste after imports) -----------------
from flask import request as _request


def get_current_username():
    """Return username from cookie or None."""
    return _request.cookies.get("auth_user")


def get_current_role():
    """Normalized role (lowercase) from cookie."""
    return (_request.cookies.get("auth_role") or "").strip().lower()

def current_role_authoritative():
    """
    Prefer DB-backed g.current_user.role (if loaded), otherwise fall back to auth_role cookie.
    Returns a lowercase string.
    """
    db_user = getattr(g, "current_user", None)
    if db_user and getattr(db_user, "role", None):
        return (db_user.role or "").strip().lower()
    return (_request.cookies.get("auth_role") or "").strip().lower()

   


def get_role_display():
    """Role display value (title-case) from cookie."""
    return _request.cookies.get("auth_role_display") or ""


def get_selected_project():
    return _request.cookies.get("selected_project") or ""


def set_auth_cookies(response, username, role="", role_display="", selected_project=""):
    """Set httponly cookies for auth state. Return the response object."""
    # choose secure=True when using HTTPS/production and set appropriate samesite
    response.set_cookie("auth_user", username or "", httponly=True, samesite="Lax")
    response.set_cookie("auth_role", (role or "").strip().lower(), httponly=True, samesite="Lax")
    response.set_cookie("auth_role_display", role_display or "", httponly=True, samesite="Lax")
    response.set_cookie("selected_project", selected_project or "", httponly=True, samesite="Lax")
    return response


def clear_auth_cookies(response):
    response.delete_cookie("auth_user")
    response.delete_cookie("auth_role")
    response.delete_cookie("auth_role_display")
    response.delete_cookie("selected_project")
    return response

# -----------------------------------------------------------------------------------


@app.before_request
def load_current_user():
    """
    Optional: load a DB-backed User into `g.current_user` when a username cookie exists.
    This lets templates / code use g.current_user safely (avoids trusting cookies only).
    """
    uname = get_current_username()  # returns None or the cookie value
    g.current_user = None
    if uname:
        try:
            g.current_user = User.query.filter_by(username=uname).first()
        except Exception:
            # swallow DB errors here — injector will still work using cookies
            g.current_user = None


@app.context_processor
def inject_user_role():
    """
    Provide role/user info to templates using cookies (and fallback to DB when necessary).
    Returns:
      - current_user: username or None
      - is_authenticated: bool
      - user_role: normalized role (lowercase)
      - role_display: nice display string (title-case)
      - is_superadmin: bool
      - selected_project: project name (if present)
    """
    # prefer DB-loaded user (safer) but fall back to cookies
    db_user = getattr(g, "current_user", None)
    username = db_user.username if db_user else (get_current_username() or None)
    is_authenticated = bool(username)

    # Prefer authoritative DB role if available, otherwise use cookie
    if db_user:
        role_raw = (db_user.role or "").strip()
    else:
        role_raw = (get_current_role() or "").strip()

    role_norm = role_raw.lower()
    role_display = get_role_display() or (role_raw.title() if role_raw else "")

    selected_project = get_selected_project() or ""

    return {
        "current_user": username,
        "is_authenticated": is_authenticated,
        "user_role": role_norm,
        "role_display": role_display,
        "is_superadmin": role_norm == "super admin",
        "selected_project": selected_project
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

        # ✅ Create cookie-based session
        role_norm = (user.role or "").strip().lower()
        role_display = (user.role or "").strip()


        resp = make_response(render_template("landing.html"))
        set_auth_cookies(resp, email, role=role_norm, role_display=role_display)
        return resp

    return "Google login failed!", 400


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Try to find user in DB
        user = None
        try:
            user = User.query.filter_by(username=username).first()
        except Exception:
            # DB may be unreachable; swallow and continue to allow dev fallback
            app.logger.exception("DB lookup failed in login()")

        # Normal DB-auth path (supports hashed OR plaintext DB passwords)
        if user and verify_password(user.password, password):
            role_norm = (user.role or "").strip().lower()
            role_display = (user.role or "").strip()
        

            resp = redirect(url_for("landing_page"))
            set_auth_cookies(
                resp,
                user.username,
                role=role_norm,
                role_display=role_display,
    
            )
            flash("✅ Logged in", "success")
            return resp

        # Dev-friendly fallback: create/accept admin/admin if DB user missing
        # NOTE: Remove or secure this behavior before production use.
        if username == "admin" and password == "admin":
            try:
                # If admin exists but password mismatch, overwrite? we create only if missing.
                if not user:
                    hashed = generate_password_hash("admin")
                    admin_user = User(username="admin", password=hashed, role="Super Admin")
                    db.session.add(admin_user)
                    db.session.commit()
                    user = admin_user
                    app.logger.info("✅ Created default admin user (development): admin / admin")

                # Log in admin (use DB role if present)
                role_norm = (user.role or "Super Admin").strip().lower()
                role_display = (user.role or "Super Admin").strip()
        

                resp = redirect(url_for("landing_page"))
                set_auth_cookies(
                    resp,
                    user.username,
                    role=role_norm,
                    role_display=role_display,
                )
                flash("✅ Logged in (dev fallback)", "success")
                return resp

            except Exception:
                # If DB create fails (e.g., no DB), still set cookie so developer can proceed.
                app.logger.exception("Failed to create admin user; using cookie fallback")
                role_norm = "super admin"
                role_display = "Super Admin"

                resp = redirect(url_for("landing_page"))
                set_auth_cookies(resp, "admin", role=role_norm, role_display=role_display)
                flash("✅ Logged in (cookie fallback)", "success")
                return resp

        # If we reach here, authentication failed
        flash("❌ Invalid username or password!", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    resp = redirect(url_for("landing_page"))
    clear_auth_cookies(resp)
    return resp

@app.route('/vms_demo')
def vms_demo():
    return render_template('vms.html')


@app.route("/vms")
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
        items=json.dumps(normalized_items),
        otherItems=other_text,
        check_in=None,
        check_out=None,
        remarks=None,
        verified=False,
        approved=None,
        electronics_approved=None   # new field to be set by IT approve/decline
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
                    try:
                        send_email_to_it(v, it_user["username"], it_user["email"], visitor_id=new_id)
                    except TypeError:
                        send_email_to_it(v, visitor_id=new_id, to_email=it_user["email"])
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
        purpose = getattr(v, "purpose", "") or ""
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
        base = VISITOR_BASE_URL or "http://localhost:5001"
    base = base.rstrip('/')

    approve_link = f"{base}/approve_electronics/{vid}"
    decline_link = f"{base}/decline_electronics/{vid}"

    subject = "IT Approval Required — Visitor carrying electronic item(s)"
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
        <a href="{approve_link}">✅ Approve electronics</a>&nbsp;&nbsp;
        <a href="{decline_link}">❌ Decline</a>
      </p>
      <p>Regards,<br>VMS System</p>
    </body></html>
    """

    message = MIMEMultipart()
    message["From"] = SMTP_MAIL
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
        base = VISITOR_BASE_URL or "http://localhost:5001"
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
    message["From"] = SMTP_MAIL
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
def visitors_list():
    import json as _json
    all_visitors = Visitor.query.order_by(Visitor.created_at.desc()).all()
     # Prefer DB-backed role (g.current_user) when available; otherwise fallback to cookie
    user_role = current_role_authoritative()

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
    # Authoritative server-side role check (prefer DB role then cookie)
   # Authoritative server-side role check (prefer DB-loaded user then cookie)
    role = current_role_authoritative()
    app.logger.debug("Checkin attempt: visitor_id=%s, cookie_role=%s, cookie_user=%s, db_user=%s, authoritative=%s",
                    visitor_id, request.cookies.get("auth_role"), request.cookies.get("auth_user"),
                    getattr(g, "current_user").username if getattr(g, "current_user", None) else None, role)
    if role != "security":
        return jsonify(success=False, message="Forbidden: insufficient permissions"), 403


    try:
        data = request.get_json(silent=True) or {}
        badge = (data.get('badge') or "").strip()
        override = data.get('override') in (True, 'true', '1', 'yes')

        if not badge:
            return jsonify(success=False, message="Missing badge"), 400

        v = Visitor.query.get(visitor_id)
        if not v:
            return jsonify(success=False, message="Visitor not found"), 404

        # prevent double check-in
        if v.check_in:
            return jsonify(success=False, message="Visitor already checked in"), 400

        # enforce approvals server-side, but allow explicit security override
        allowed, reason = visitor_allowed_to_checkin(v)
        if not allowed and not override:
            return jsonify(success=False, message=f"Not allowed to check in: {reason}"), 403

        # all good — record badge and check-in time
        v.badge_number = badge
        v.check_in = datetime.utcnow()
        db.session.commit()

        return jsonify(success=True, message="Checked in", badge=badge, check_in=v.check_in.isoformat()), 200

    except Exception:
        app.logger.exception("Checkin error")
        return jsonify(success=False, message="Server error"), 500

@app.route("/checkout/<int:visitor_id>", methods=["POST"])
def checkout(visitor_id):
    # Authoritative server-side role check (prefer DB role then cookie)
    # Authoritative server-side role check (prefer DB-loaded user then cookie)
    role = current_role_authoritative()
    app.logger.debug("Checkout attempt: visitor_id=%s, cookie_role=%s, cookie_user=%s, db_user=%s, authoritative=%s",
                    visitor_id, request.cookies.get("auth_role"), request.cookies.get("auth_user"),
                    getattr(g, "current_user").username if getattr(g, "current_user", None) else None, role)
    if role != "security":
        return jsonify({"success": False, "message": "Forbidden: insufficient permissions"}), 403



    try:
        data = request.get_json(silent=True) or {}
        remarks = (data.get("remarks") or "").strip()

        # optional: allow client to send checked_items for auditing (not required)
        # checked_items = data.get("checked_items", [])

        v = Visitor.query.get(visitor_id)
        if not v:
            return jsonify({"success": False, "message": "Visitor not found"}), 404

        # must be checked-in before checking out
        if not v.check_in:
            return jsonify({"success": False, "message": "Cannot checkout: visitor is not checked in"}), 400

        # prevent double checkout
        if v.check_out:
            return jsonify({"success": False, "message": "Visitor already checked out"}), 400

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

@app.route("/auth_debug")
def auth_debug():
    """
    Temporary debug endpoint — returns cookie values and DB user (if loaded).
    Use it from the browser while logged in to confirm cookie vs DB role.
    """
   
    db_user = getattr(g, "current_user", None)
    db_username = getattr(db_user, "username", None) if db_user else None
    db_role = getattr(db_user, "role", None) if db_user else None
    return jsonify({
  
        "db_username": db_username,
        "db_role": db_role,
        "authoritative_role": current_role_authoritative()
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
