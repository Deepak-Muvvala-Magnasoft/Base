# app.py
import os
import json
import pandas as pd
import smtplib
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, flash, jsonify,
    make_response, session
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text, inspect, func
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# load configuration values from config.py (keep same names as before)
from config import (
    MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, MYSQL_PORT,
    SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_MAIL,
    VISITOR_BASE_URL
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "super_secret_key")
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['PREFERRED_URL_SCHEME'] = 'https'

# SQLAlchemy
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# ---------------------------
# Models
# ---------------------------
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


# ---------------------------
# Utilities
# ---------------------------
def safe_colname(col: str) -> str:
    """
    Sanitize a column name for MySQL identifiers.
    Converts spaces/dashes to underscores and strips weird chars.
    """
    name = (col or "").strip().replace(" ", "_").replace("-", "_")
    import re
    name = re.sub(r"[^0-9a-zA-Z_]", "", name)
    if not name:
        name = "col"
    if name[0].isdigit():
        name = f"c_{name}"
    return name


def ensure_excel_columns_exist(new_columns):
    """
    Ensure columns exist on the shared `excel_data` table.
    Adds TEXT columns for any missing column names in `new_columns`.
    """
    insp = inspect(db.engine)
    table_name = "excel_data"
    # create table if not exists with base columns
    base_cols = [
        "id INT AUTO_INCREMENT PRIMARY KEY",
        "uploaded_by VARCHAR(100)",
        "upload_time VARCHAR(20)",
        "file_name VARCHAR(255)"
    ]
    db.session.execute(text(f"CREATE TABLE IF NOT EXISTS `{table_name}` ({', '.join(base_cols)})"))
    db.session.commit()

    existing = {c["name"] for c in insp.get_columns(table_name)}
    for col in new_columns:
        c = safe_colname(col)
        if c and c not in existing and c not in {"id", "uploaded_by", "upload_time", "file_name"}:
            db.session.execute(text(f"ALTER TABLE `{table_name}` ADD COLUMN `{c}` TEXT"))
            db.session.commit()
            existing.add(c)

@app.route("/")
def index():
    """
    Root URL: if user already in session go to landing, otherwise show login.
    Keeps behavior minimal — does not change auth logic elsewhere.
    """
    # If you set session['username'] during login, this will redirect to landing.
    # Otherwise it will show the login page (same as /login).
    if session.get("username"):
        return redirect(url_for("landing"))
    # option A: redirect to /login
    return redirect(url_for("login"))
    # --- OR render inline (uncomment if you prefer):
    # return render_template("login.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Simple login handler: on POST redirect to /landing (or render on GET).
    Also safely prepares a google login URL if the 'google.login' endpoint exists.
    """
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        # Temporary auth: treat non-empty username as success; replace with DB check later.
        if username:
            # if other routes check session, enable next line
            session['username'] = username
            return redirect(url_for("landing"))
        flash("Invalid username or password", "danger")

    # Safely build google login URL (avoid BuildError if blueprint not registered)
    try:
        google_login_url = url_for('google.login', next=request.args.get('next', ''))
    except Exception:
        google_login_url = None

    return render_template("login.html", google_login_url=google_login_url)

@app.route("/logout")
def logout():
    """
    Simple logout that performs no session manipulation and redirects to /login.
    (If you previously used cookie helpers like `clear_auth_cookies`, keep or call them here
    — but per your request we are not touching session.)
    """
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# ---------------------------
# Visitor flows (unchanged logic, no auth)
# ---------------------------
@app.route('/visitor', methods=['GET', 'POST'])
def visitor_qr():
    # If POST, reuse add_visitor (keeps previous behaviour)
    if request.method == 'POST':
        return add_visitor()
    return render_template('visitor_form.html', visitor_only=True)


@app.route('/vms')
def vms():
    app.logger.info("✔ /vms route HIT — remote=%s, args=%s", request.remote_addr, request.args)
    return render_template('visitor_form.html')

# add this to app.py (minimal)
# paste into app.py (minimal)
@app.route("/landing")
def landing():
    """Landing page used after successful login."""
    try:
        return render_template("landing.html")
    except Exception:
        app.logger.exception("Failed to render landing.html")
        # Fallback: if template missing, redirect to /vms so user doesn't get 404
        return redirect(url_for("vms"))




@app.route("/add_visitor", methods=["POST"])
def add_visitor():
    form = request.form
    visitor_only = form.get("visitor_only")
    dept = form.get('dept')
    location = form.get('location')
    selected_contact_person = form.get('contact_person')

    # normalize items & dedupe preserving order (case-insensitive)
    items_raw = request.form.getlist("items") or request.form.getlist("items[]") or []
    other_text = (form.get("otherItems") or "").strip()
    normalized_items = []
    for it in items_raw:
        if not it:
            continue
        if it == "Other":
            if other_text:
                normalized_items.append(other_text)
        else:
            normalized_items.append(it)
    if other_text and other_text not in normalized_items:
        normalized_items.append(other_text)

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
    normalized_items = normalized_items_unique

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
        electronics_approved=None
    )

    # handle uploaded photo (optional)
    photo_file = request.files.get('photo')
    if photo_file and photo_file.filename:
        safe_name = secure_filename(photo_file.filename)
        visitor.photo_filename = safe_name
        visitor.photo_mime = photo_file.mimetype or 'image/jpeg'
        visitor.photo_data = photo_file.read()

    def respond_success(msg, visitor_id=None):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or "application/json" in request.headers.get("Accept", ""):
            payload = {"success": True, "message": msg}
            if visitor_id:
                payload["visitor_id"] = visitor_id
            return jsonify(payload), 200
        if visitor_only:
            return redirect(url_for("visitor_qr", alert=msg, alert_cat="success"))
        return redirect(url_for("vms", alert=msg, alert_cat="success"))

    def respond_error(msg, status=500):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or "application/json" in request.headers.get("Accept", ""):
            return jsonify({"success": False, "message": msg}), status
        if visitor_only:
            return redirect(url_for("visitor_qr", alert=msg, alert_cat="danger"))
        return redirect(url_for("vms", alert=msg, alert_cat="danger"))

    try:
        db.session.add(visitor)
        db.session.commit()
        new_id = visitor.id
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.exception("Failed to save visitor to DB")
        return respond_error(f"Failed saving visitor (DB error): {e.__class__.__name__}", 500)

    # send notification emails (best-effort)
    try:
        v = Visitor.query.get(new_id)
        if selected_contact_person:
            try:
                send_email_to_contact(v, visitor_id=new_id)
            except Exception:
                app.logger.exception("Failed to send contact-person email for visitor %s", new_id)
        else:
            # fetch contacts for dept/location if table exists
            try:
                users = db.session.execute(
                    text("SELECT username, email FROM contact_person WHERE dept = :dept AND location = :location"),
                    {"dept": dept, "location": location}
                ).mappings().all()
            except Exception:
                users = []
            for user in users:
                orig_contact_person = v.contact_person
                orig_contact_email = v.contact_email
                try:
                    v.contact_person = user["username"]
                    v.contact_email = user["email"]
                    send_email_to_contact(v, visitor_id=new_id)
                except Exception:
                    app.logger.exception("Failed to send contact-person email to %s for visitor %s", user.get("email"), new_id)
                finally:
                    v.contact_person = orig_contact_person
                    v.contact_email = orig_contact_email
    except Exception as e:
        app.logger.exception("Email sending failed after saving visitor (department emails)")
        return respond_success(f"Visitor saved but department email failed: {str(e)}", visitor_id=new_id)

    # IT electronics approval flow
    try:
        electronics_keywords = {
            "laptop", "pendrive", "usb", "usb-drive", "usb drive",
            "ipad", "tablet", "mobile", "phone", "charger", "powerbank", "notebook", "macbook"
        }
        items_to_check = normalized_items
        if not items_to_check:
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
            try:
                it_users = db.session.execute(
                    text("SELECT username, email FROM contact_person WHERE dept = :dept AND location = :location"),
                    {"dept": "IT", "location": location}
                ).mappings().all()
            except Exception:
                it_users = []
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

    return respond_success("Visitor saved and email(s) sent successfully!", visitor_id=new_id)


@app.route('/visitor_photo/<int:visitor_id>')
def visitor_photo(visitor_id):
    v = Visitor.query.get(visitor_id)
    if not v or not v.photo_data:
        return '', 404
    resp = make_response(v.photo_data)
    resp.headers.set('Content-Type', v.photo_mime or 'image/jpeg')
    resp.headers.set('Content-Disposition', 'inline', filename=v.photo_filename or f'photo_{visitor_id}.jpg')
    return resp


def send_email_to_it(visitor_obj_or_dict, contact_name=None, contact_email=None, visitor_id=None, to_email=None):
    """
    Send IT approval email for electronics. Returns True/False.
    """
    import html as _html
    # normalize visitor object/dict
    if hasattr(visitor_obj_or_dict, "__table__"):
        v = visitor_obj_or_dict
        vid = visitor_id or v.id
        name = getattr(v, "name", "") or ""
        company = getattr(v, "company", "") or ""
        phone = getattr(v, "phone", "") or ""
        purpose = getattr(v, "purpose", "") or ""
        location = getattr(v, "location", "") or ""
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

    # build items list
    items_list = []

    def extend_from(src):
        if not src:
            return
        if isinstance(src, (list, tuple, set)):
            for x in src:
                if x is not None:
                    items_list.append(str(x).strip())
            return
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
                cleaned = s.strip("[]").replace('"', "").replace("'", "")
                for part in (p.strip() for p in cleaned.split(",") if p.strip()):
                    items_list.append(part)
                return
        items_list.append(str(src).strip())

    extend_from(items_field)
    if other_text_field:
        extend_from(other_text_field)

    # dedupe preserving order
    seen = set()
    items_clean = []
    for it in items_list:
        if not it:
            continue
        key = it.lower()
        if key not in seen:
            items_clean.append(it)
            seen.add(key)

    electronics_keywords = {
        "laptop", "pendrive", "usb", "usb-drive", "usb drive",
        "ipad", "tablet", "mobile", "phone", "charger", "powerbank",
        "notebook", "macbook"
    }
    items_electronic = [it for it in items_clean if any(k in it.lower() for k in electronics_keywords)]
    items_line = ", ".join(items_electronic) if items_electronic else "—"

    try:
        base = VISITOR_BASE_URL or request.url_root.rstrip('/')
    except Exception:
        base = VISITOR_BASE_URL or "http://localhost:5001"
    base = base.rstrip('/')
    approve_link = f"{base}/approve_electronics/{vid}"
    decline_link = f"{base}/decline_electronics/{vid}"

    to_addr = to_email or contact_email
    if not to_addr:
        return False

    subject = "IT Approval Required — Visitor carrying electronic item(s)"
    body = f"""
    <html><body>
      <p>Hello {_html.escape(str(contact_name or ''))},</p>
      <p>A visitor has registered and marked that they are carrying electronic item(s):</p>
      <ul>
        <li><strong>Name:</strong> {_html.escape(str(name))}</li>
        <li><strong>Company:</strong> {_html.escape(str(company))}</li>
        <li><strong>Phone:</strong> {_html.escape(str(phone))}</li>
        <li><strong>Purpose:</strong> {_html.escape(str(purpose))}</li>
        <li><strong>Location:</strong> {_html.escape(str(location))}</li>
      </ul>
      <p>Please approve/decline the electronics request:</p>
      <ul>
        <li><strong>Items:</strong> {_html.escape(items_line)}</li>
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
    message["To"] = to_addr
    message["Subject"] = subject
    message.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(message["From"], to_addr, message.as_string())
    except Exception:
        app.logger.exception("Failed to send IT approval email to %s for visitor %s", to_addr, vid)
        return False
    return True


def send_email_to_contact(visitor_obj_or_dict, visitor_id=None):
    """
    Send contact-person email for visitor. Returns True/False.
    """
    if hasattr(visitor_obj_or_dict, "__table__"):
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

    try:
        base = VISITOR_BASE_URL or request.url_root.rstrip('/')
    except Exception:
        base = VISITOR_BASE_URL or "http://localhost:5001"
    base = base.rstrip('/')

    approve_link = f"{base}/approve_visitor/{vid}"
    decline_link = f"{base}/decline_visitor/{vid}"

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

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(message["From"], contact_email, message.as_string())
    except Exception:
        app.logger.exception("Failed to send contact email to %s for visitor %s", contact_email, vid)
        return False
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
    """
    Helper API used previously to fetch contact_person rows.
    Returns empty list gracefully if the table doesn't exist.
    """
    dept = request.args.get("dept")
    location = request.args.get("location")
    if not dept or not location:
        return jsonify([])

    try:
        users = db.session.execute(
            text("SELECT username, email FROM contact_person WHERE dept = :dept AND location = :location"),
            {"dept": dept, "location": location}
        ).mappings().all()
    except Exception:
        users = []
    return jsonify([{"username": u["username"], "email": u["email"]} for u in users])


@app.route("/visitors")
def visitors_list():
    """
    Render visitors_list.html (keeps template usage the same).
    If you prefer JSON, replace render_template with jsonify(out).
    """
    import json as _json
    all_visitors = Visitor.query.order_by(Visitor.created_at.desc()).all()
    out = []
    keywords = ['laptop','pendrive','usb','notebook','macbook','ipad','tablet','mobile','phone','charger','powerbank']

    for v in all_visitors:
        # normalize items
        items_value = getattr(v, "items", None)
        items_list = []
        try:
            if isinstance(items_value, str):
                try:
                    parsed = _json.loads(items_value)
                    if isinstance(parsed, (list, tuple, set)):
                        items_list = [str(x).strip() for x in parsed if str(x).strip()]
                    else:
                        items_list = [str(parsed).strip()] if str(parsed).strip() else []
                except Exception:
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

        other_text = getattr(v, "otherItems", "") or ""
        other_text = other_text.strip() if isinstance(other_text, str) else ""
        items_clean = [str(it).strip() for it in items_list if str(it).strip().lower() != "other"]

        combined = items_clean[:]
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

        # compute has_electronics
        has_electronics_flag = False
        for itm in items_with_other_for_pass:
            itm_low = str(itm).strip().lower()
            for kw in keywords:
                if kw in itm_low:
                    has_electronics_flag = True
                    break
            if has_electronics_flag:
                break

        dept_ok = bool(v.approved)
        it_ok = (v.electronics_approved is True) if has_electronics_flag else True
        allowed_to_checkin = dept_ok and it_ok

        checked_items = getattr(v, "checked_items", []) or []
        badge_number = getattr(v, "badge_number", "") or ""
        idNumber = getattr(v, "idNumber", "") or ""
        photo_url = url_for('visitor_photo', visitor_id=v.id) if getattr(v, "photo_data", None) else None

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
            "otherItems": other_text,
            "items_with_other": items_with_other_for_pass,
            "checked_items": checked_items,
            "check_in": v.check_in.strftime("%Y-%m-%d %H:%M:%S") if v.check_in else None,
            "check_out": v.check_out.strftime("%Y-%m-%d %H:%M:%S") if v.check_out else None,
            "verified": bool(v.verified),
            "approved": v.approved,
            "electronics_approved": getattr(v, "electronics_approved", None),
            "has_electronics": has_electronics_flag,
            "remarks": v.remarks or "",
            "photo_url": photo_url,
        })

    # Render the same visitors_list.html you used previously; if you removed templates, return JSON:
    try:
        return render_template("visitors_list.html", visitors=out)
    except Exception:
        # fallback: return JSON if template missing
        return jsonify(visitors=out)


@app.route("/api/visitors")
def visitors_api():
    visitors = Visitor.query.order_by(Visitor.created_at.desc()).all()
    out = []
    for v in visitors:
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
    try:
        data = request.get_json(silent=True) or {}
        badge = (data.get('badge') or "").strip()
        if not badge:
            return jsonify(success=False, message="Missing badge"), 400
        v = Visitor.query.get(visitor_id)
        if not v:
            return jsonify(success=False, message="Visitor not found"), 404
        v.badge_number = badge
        v.check_in = datetime.utcnow()
        db.session.commit()
        return jsonify(success=True, message="Checked in", badge=badge, check_in=v.check_in.isoformat()), 200
    except Exception:
        app.logger.exception("Checkin error")
        return jsonify(success=False, message="Server error"), 500


@app.route("/checkout/<int:visitor_id>", methods=["POST"])
def checkout(visitor_id):
    """
    Checkout does not require roles in this simplified app.
    """
    try:
        data = request.get_json(silent=True) or {}
        remarks = data.get("remarks", "")
        v = Visitor.query.get(visitor_id)
        if not v:
            return jsonify({"success": False, "message": "Visitor not found"}), 404
        v.check_out = datetime.now()
        v.remarks = (v.remarks or "") + ("\n" + remarks if remarks else "")
        db.session.commit()
        return jsonify({"success": True, "message": "Visitor checked out successfully"})
    except Exception:
        app.logger.exception("Checkout error")
        return jsonify({"success": False, "message": "Server error"}), 500


# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
