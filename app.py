from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime
from authlib.integrations.flask_client import OAuth
from sqlalchemy import func, inspect, text
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash
from config import MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, MYSQL_PORT, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, MONGO_URI, SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_MAIL
from datetime import datetime
from flask_dance.contrib.google import make_google_blueprint, google
import os
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from urllib.parse import quote_plus


app = Flask(__name__)
app.secret_key = "super_secret_key"
app.config["TEMPLATES_AUTO_RELOAD"] = True

app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config["MONGO_URI"] = MONGO_URI
mongo = PyMongo(app)

# Add Google OAuth config
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For HTTP (development only)
google_bp = make_google_blueprint(
    client_id= GOOGLE_CLIENT_ID,
    client_secret= GOOGLE_CLIENT_SECRET,
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")


# --- SQLAlchemy / MySQL ---
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# --- Models ---
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Project(db.Model):
    __tablename__ = "projects"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)


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
    if tbl[0].isdigit():
        tbl = f"t_{tbl}"
    return tbl.lower()

def ensure_columns_exist(new_columns):
    """
    ALTER TABLE excel_data ADD COLUMN `<col>` TEXT for any missing Excel columns.
    """
    inspector = inspect(db.engine)
    existing = {c["name"] for c in inspector.get_columns("excel_data")}
    for col in new_columns:
        c = safe_colname(col)
        if c not in existing and c not in {"id", "project_name", "uploaded_by", "upload_time", "file_name"}:
            db.session.execute(text(f"ALTER TABLE `excel_data` ADD COLUMN `{c}` TEXT"))
            db.session.commit()
            existing.add(c)


# --- Routes ---
@app.route('/')
def home():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template('landing.html')


@app.route("/google")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))  # Redirect to Google OAuth

    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        user_info = resp.json()
        email = user_info["email"]
        name = user_info.get("name", email.split("@")[0])

        # ✅ Check if user exists in DB, else create
        user = User.query.filter_by(username=email).first()
        if not user:
            user = User(username=email, password="", role="User")  # No password for SSO users
            db.session.add(user)
            db.session.commit()

        # ✅ Create session
        session["username"] = email
        session["role"] = user.role

        first_project = Project.query.order_by(Project.name).first()
        project_name = first_project.name if first_project else ""
        session["selected_project"] = project_name

        return render_template("landing.html")
        # ✅ Redirect to data page
        # return redirect(url_for("upload_file", project_name=project_name))

    return "Google login failed!", 400


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["username"] = username
            session["role"] = user.role or "User"

            # ✅ Find the first project name alphabetically
            first_project = Project.query.order_by(Project.name).first()
            project_name = first_project.name if first_project else ""

            # ✅ Save in session
            session["selected_project"] = project_name

            return render_template("landing.html")
            # ✅ Redirect to /data?project_name=<first_project>
            #return redirect(url_for("upload_file", project_name=project_name))

        else:
            flash("❌ Invalid username or password!", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("role", None)
    return redirect(url_for("login"))


@app.route("/data", methods=["GET", "POST"])
def upload_file():
    if "username" not in session:
        return redirect(url_for("login"))

    error_msg = None
    uploaded_data = []
    columns = []
    grouped_data = []

    # ✅ Capture project_name from URL, form, or session
    project_name = request.args.get("project_name") or request.form.get("project_name") or session.get("selected_project")
    if project_name:
        session["selected_project"] = project_name
    else:
        project_name = ""
    selected_project = session.get('selected_project')
    # ✅ Handle file upload if POST request
    if request.method == "POST" and request.files.get("file"):
        file = request.files.get("file")
        email = session["username"]
        table_name = safe_table_name(project_name)

        try:
            # Read Excel
            df = pd.read_excel(file)
            df.columns = df.columns.str.strip()
            col_map = {col: safe_colname(col) for col in df.columns}
            df.rename(columns=col_map, inplace=True)
            df = df.where(pd.notnull(df), None)
            df.dropna(how="all", inplace=True)
            df.dropna(axis=1, how="all", inplace=True)
            upload_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            file_name = file.filename

            # Ensure table exists
            base_cols = ["id INT AUTO_INCREMENT PRIMARY KEY",
                         "uploaded_by VARCHAR(100)",
                         "upload_time VARCHAR(20)",
                         "file_name VARCHAR(255)"]
            db.session.execute(text(f"CREATE TABLE IF NOT EXISTS `{table_name}` ({', '.join(base_cols)})"))
            db.session.commit()

            # Ensure columns exist
            insp = inspect(db.engine)
            existing = {c["name"] for c in insp.get_columns(table_name)}
            for col in df.columns:
                if col not in existing and col not in {"id", "uploaded_by", "upload_time", "file_name"}:
                    db.session.execute(text(f"ALTER TABLE `{table_name}` ADD COLUMN `{col}` TEXT"))
                    db.session.commit()

            # Insert rows
            for row_dict in df.to_dict(orient="records"):
                row_dict.update({
                    "uploaded_by": email,
                    "upload_time": upload_time,
                    "file_name": file_name
                })
                cols = ", ".join(f"`{c}`" for c in row_dict.keys())
                placeholders = ", ".join(f":{c}" for c in row_dict.keys())
                stmt = text(f"INSERT INTO `{table_name}` ({cols}) VALUES ({placeholders})")
                db.session.execute(stmt, row_dict)

            db.session.commit()
            flash(f"File '{file_name}' uploaded successfully into '{project_name}'!", "success")

        except Exception as e:
            db.session.rollback()
            error_msg = str(e)

    # ✅ Always fetch data if project_name is set
    if project_name:
        try:
            table_name = safe_table_name(project_name)
            insp = inspect(db.engine)
            # ✅ Check if the table exists first
            if table_name in insp.get_table_names():
                table_cols = [c["name"] for c in insp.get_columns(table_name)]

                if table_cols:
                    rows = db.session.execute(
                        text(f"SELECT * FROM `{table_name}` WHERE uploaded_by = :user"),
                        {"user": session["username"]}
                    ).mappings().all()
                else:
                    # Table exists but no columns yet (new empty table)
                    table_cols = ["upload_time", "file_name"]
                    rows = []
            else:
                table_cols = []
                rows = []

            uploaded_data = [dict(r) for r in rows]
            meta_cols = ["upload_time", "file_name"]
            data_cols = sorted([c for c in table_cols if c not in {"id", "uploaded_by", *meta_cols}])
            columns = meta_cols + data_cols

            grouped_rows = db.session.execute(text(f"""
                SELECT uploaded_by, upload_time, file_name, COUNT(id) AS count
                FROM `{table_name}`
                WHERE uploaded_by = :user
                GROUP BY uploaded_by, upload_time, file_name
                ORDER BY upload_time DESC
            """), {"user": session["username"]}).mappings().all()

            grouped_data = []
            for row in grouped_rows:
                row_dict = dict(row)
                row_dict["project_name"] = project_name
                row_dict["table_name"] = table_name
                grouped_data.append(row_dict)
        except Exception:
            pass

    # ✅ List all projects
    projects_list = [p.name for p in Project.query.order_by(Project.name).all()]
    selected_project = session.get("selected_project")  # removes it from session
    return render_template(
        "data.html",
        email=session["username"],
        uploaded_data=uploaded_data,
        columns=columns,
        grouped_data=grouped_data,
        projects=projects_list,
        error_msg=error_msg,
        selected_project=selected_project
    )


@app.route('/vms_demo')
def vms_demo():
    return render_template('vms.html')


@app.route("/superadmin", methods=["GET", "POST"])
def superadmin():
    if not session.get("username"):
        flash("Login required", "danger")
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()
    if not user or user.role != "Super Admin":
        flash("Access denied", "danger")
        return redirect(url_for("upload_file"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "warning")
        else:
            hashed_pw = generate_password_hash(password)
            new_user = User(username=username, password=hashed_pw, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash("User added successfully", "success")

    # Provide data to template similar to your Mongo shape (but without password)
    all_users = [{"username": u.username, "role": u.role} for u in User.query.order_by(User.username).all()]
    all_projects = [{"id": p.id, "name": p.name} for p in Project.query.order_by(Project.name).all()]
    first_project = Project.query.order_by(Project.name).first()
    first_project_name = first_project.name if first_project else ""
    return render_template("admin.html", all_users=all_users, all_projects=all_projects, first_project_name=first_project_name) 


@app.route("/edit_user_role", methods=["POST"])
def edit_user_role():
    username = request.form.get("username")
    new_role = request.form.get("new_role")

    if not username or not new_role:
        flash("Missing username or role", "danger")
        return redirect(request.referrer or url_for("superadmin"))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("superadmin"))

    user.role = new_role
    db.session.commit()
    flash(f"Role for '{username}' updated to '{new_role}' successfully!", "success")
    return redirect(url_for("superadmin"))


@app.route("/edit_user_password", methods=["POST"])
def edit_user_password():
    username = request.form.get("username")
    new_password = request.form.get("new_password")

    if not username or not new_password:
        flash("Missing username or password", "danger")
        return redirect(request.referrer or url_for("upload_file"))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(request.referrer or url_for("upload_file"))

    user.password = generate_password_hash(new_password)
    db.session.commit()
    flash(f"Password for '{username}' updated successfully!", "success")
    return redirect(request.referrer or url_for("upload_file"))


@app.route("/delete_user", methods=["POST"])
def delete_user():
    username_to_delete = request.form["username"]
    user = User.query.filter_by(username=username_to_delete).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"User '{username_to_delete}' deleted successfully!", "success")
    else:
        flash(f"User '{username_to_delete}' not found.", "danger")
    return redirect(url_for("superadmin"))


@app.route("/add_project", methods=["POST"])
def add_project():
    name = request.form["project_name"].strip()
    if not name:
        flash("Project name required.", "warning")
        return redirect(url_for("superadmin"))

    new_project = Project(name=name)
    db.session.add(new_project)
    db.session.commit()

    # Create a dedicated table for this project
    table_name = safe_table_name(name)
    create_sql = f"""
        CREATE TABLE IF NOT EXISTS `{table_name}` (
            id INT AUTO_INCREMENT PRIMARY KEY,
            uploaded_by VARCHAR(100),
            upload_time VARCHAR(20),
            file_name VARCHAR(255)
        )
    """
    db.session.execute(text(create_sql))
    db.session.commit()

    flash(f"Project '{name}' created with table '{table_name}'.", "success")
    return redirect(url_for("superadmin"))


@app.route("/edit_project", methods=["POST"])
def edit_project():
    project_id = request.form["project_id"]
    new_name = request.form["project_name"].strip()

    proj = Project.query.get(project_id)
    if not proj:
        flash("Project not found.", "danger")
        return redirect(url_for("superadmin"))

    old_name = proj.name
    old_table = safe_table_name(old_name)
    new_table = safe_table_name(new_name)

    # Update project name in projects table
    proj.name = new_name

    # Rename the DB table
    rename_sql = f"RENAME TABLE `{old_table}` TO `{new_table}`"
    db.session.execute(text(rename_sql))

    # ✅ Update all rows in excel_data where project_name = old_name
    update_sql = text("UPDATE excel_data SET project_name = :new_name WHERE project_name = :old_name")
    db.session.execute(update_sql, {"new_name": new_name, "old_name": old_name})

    db.session.commit()
    flash(f"Project '{old_name}' renamed to '{new_name}' and updated in excel_data.", "success")
    return redirect(url_for("superadmin"))


@app.route("/delete_project", methods=["POST"])
def delete_project():
    project_id = request.form["project_id"]
    proj = Project.query.get(project_id)
    if not proj:
        flash("Project not found.", "danger")
        return redirect(url_for("superadmin"))
    db.session.delete(proj)
    db.session.commit()
    return redirect(url_for("superadmin"))


@app.route("/vms")
def vms():
    if "username" not in session:
        return redirect(url_for("login"))  # force login first

    return render_template("visitor_form.html", user=session["username"])


@app.route("/add_visitor", methods=["POST"])
def add_visitor():
    form = request.form
    contact_person_email = request.form.get('contact_email')
    visitor = {
        "name": form.get("name"),
        "company": form.get("company"),
        "phone": form.get("phone"),
        "email": form.get("email"),
        "location": form.get("location"),
        "idType": form.get("idType"),
        "idNumber": form.get("idNumber"),
        "purpose": form.get("purpose"),
        "otherPurpose": form.get("otherPurpose"),
        "contact_person": form.get("contact_person"),
        "contact_email": form.get("contact_email"),
        "notes": form.get("notes"),
        "items": request.form.getlist("items"),
        "otherItems": form.get("otherItems"),
        "check_in": None,
        "check_out": None,
        "remarks": None,
        "verified": False,
        "approved": None,
    }
    mongo.db.visitors.insert_one(visitor)

    # Send email notification
    try:
        send_email_to_contact(visitor)
        flash("Visitor saved and email sent successfully!", "success")
    except Exception as e:
        flash(f"Visitor saved but email failed: {str(e)}", "warning")

    flash("Visitor saved successfully!", "success")
    return redirect(url_for("vms"))


def send_email_to_contact(visitor):
    contact_email = visitor.get("contact_email")
    contact_name = visitor.get("contact_person")
    visitor_id = str(visitor["_id"])

    approve_link = f"http://localhost:5001/approve_visitor/{visitor_id}"
    decline_link = f"http://localhost:5001/decline_visitor/{visitor_id}"

    subject = "New Visitor Approval Required"
    body = f"""
    <html>
    <body>
        <p>Hello {contact_name},</p>

        <p>A new visitor has registered to meet you:</p>

        <ul>
            <li><strong>Name:</strong> {visitor.get('name')}</li>
            <li><strong>Company:</strong> {visitor.get('company')}</li>
            <li><strong>Phone:</strong> {visitor.get('phone')}</li>
            <li><strong>Purpose:</strong> {visitor.get('purpose')}</li>
        </ul>

        <p>Please choose an option below:</p>
        <a href="{approve_link}" style="display: inline-block; padding: 10px 20px; margin-right: 10px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px;">✅ Approve</a>
        <a href="{decline_link}" style="display: inline-block; padding: 10px 20px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 5px;">❌ Decline</a>

        <p>Regards,<br>VMS System</p>
    </body>
    </html>
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


@app.route("/approve_visitor/<visitor_id>")
def approve_visitor(visitor_id):
    mongo.db.visitors.update_one(
        {"_id": ObjectId(visitor_id)},
        {"$set": {"approved": True}}
    )
    return "Visitor approved ✅. Security can now check-in the visitor."


@app.route("/decline_visitor/<visitor_id>")
def decline_visitor(visitor_id):
    mongo.db.visitors.update_one(
        {"_id": ObjectId(visitor_id)},
        {"$set": {"approved": False}}
    )
    return "Visitor declined ❌. They will not be allowed to check-in."


@app.route("/get_users/<dept>")
def get_users(dept):
    users = db.session.execute(
        text("SELECT username, email FROM contact_person WHERE dept = :dept"),
        {"dept": dept}
    ).mappings().all()

    # Return list of objects: name + email
    return jsonify([{"username": u["username"], "email": u["email"]} for u in users])


@app.route("/visitors")
def visitors_list():
    all_visitors = list(mongo.db.visitors.find())
    user_role = session.get('role')

    # 🟢 Convert datetime → string (safe for template)
    for v in all_visitors:
        for field in ["check_in", "check_out"]:
            if isinstance(v.get(field), datetime):
                v[field] = v[field].strftime("%Y-%m-%d %H:%M:%S")
            elif v.get(field) is None:
                v[field] = ""  # empty if no value

    return render_template("visitors_list.html", visitors=all_visitors, user_role=user_role)



@app.route("/api/visitors")
def visitors_api():
    visitors = list(mongo.db.visitors.find())
    for v in visitors:
        v["_id"] = str(v["_id"])
    return jsonify(visitors)


@app.route("/checkin/<visitor_id>", methods=["POST"])
def checkin(visitor_id):
    data = request.get_json()
    badge = data.get("badge")

    if not badge:
        return jsonify({"success": False, "message": "Badge number required"}), 400

    mongo.db.visitors.update_one(
        {"_id": ObjectId(visitor_id)},
        {"$set": {
            "check_in": datetime.now(),
            "badge_number": badge,
            "verified": True
        }}
    )

    return jsonify({"success": True, "message": "Visitor checked in successfully"})


@app.route("/checkout/<visitor_id>", methods=["POST"])
def checkout(visitor_id):
    data = request.get_json()
    remarks = data.get("remarks", "")

    mongo.db.visitors.update_one(
        {"_id": ObjectId(visitor_id)},
        {"$set": {
            "check_out": datetime.now(),
            "remarks": remarks
        }}
    )

    return jsonify({"success": True, "message": "Visitor checked out successfully"})


if __name__ == "__main__":
    app.run(debug=True)
