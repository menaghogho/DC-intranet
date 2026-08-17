"""
Digital Champions intranet — Flask backend.

- Staff can register and sign in; accounts live in a local SQLite database.
- Passwords are never stored in plain text — only a salted hash
  (Werkzeug's PBKDF2-SHA256) is kept, so even someone with direct access
  to the database file cannot read a password back out.
- Sessions use Flask's signed cookie (tamper-proof via SECRET_KEY),
  httponly + expiring after a few hours, so a stolen cookie file alone
  is not enough to forge a session past its lifetime.
- Every page except /login and /register requires a signed-in session.

Run with:
    pip install -r requirements.txt
    copy .env.example .env      (then edit SECRET_KEY)
    python app.py

Visit http://localhost:5000
"""

import os
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

VALID_PLACES = ["Coventry", "Rugby", "Warwickshire-North", "South-Warwickshire"]

# Emails listed here (comma-separated in .env) are permanent "root" admins —
# this is the one thing about admin access that can ONLY be changed by
# someone with server/file access, never through the website itself. Root
# admins can promote other registered accounts to admin from /admin/staff;
# those promoted admins can manage staff too, but can't create more admins
# or touch root admins. That keeps "who can grant admin" anchored outside
# the web-facing attack surface, while still letting you delegate day-to-day
# staff management through the browser.
ADMIN_EMAILS = {
    e.strip().lower()
    for e in os.environ.get("ADMIN_EMAILS", "").split(",")
    if e.strip()
}

# "Find resources" chat widget — a rule-based wayfinder, not a real AI model.
# Each entry is (keywords, reply, link path, link label); the first entry
# whose keyword appears in the visitor's message wins, so put more specific
# topics before general ones. "link" lets the widget show a clickable button
# straight to the right page/section, instead of just naming it in text.
CHAT_RULES = [
    (("gpad", "appointment data", "appointment slot"),
     "The full Understanding GPAD guide — categories, FAQ and video — is at /gpad. "
     "You'll also find it linked from Resource → Team insights, or as a card on the About page.",
     "/gpad", "Open the GPAD guide"),
    (("emis",),
     "EMIS Web general training is run by the Digital Champions. Look for the EMIS banner "
     "and the “EMIS Content” tile in the Resource Centre — Resource → Case studies.",
     "/resource#resources", "Go to the Resource Centre"),
    (("nhs app", "accurx"),
     "NHS App and Accurx resources are in the Resource Centre — go to Resource → Case studies "
     "and look for the “NHS App Resources” or “Accurx resources” tiles.",
     "/resource#resources", "Go to the Resource Centre"),
    (("ai resource", "artificial intelligence"),
     "AI resources are in the Resource Centre — Resource → Case studies → “AI resources” tile.",
     "/resource#resources", "Go to the Resource Centre"),
    (("dsp", "toolkit"),
     "The DSP Toolkit resources are in the Resource Centre — Resource → Case studies → “DSP Toolkit” tile.",
     "/resource#resources", "Go to the Resource Centre"),
    (("dhsc", "campaign"),
     "DHSC campaign materials are in the Resource Centre — Resource → Case studies → “DHSC Campaigns” tile.",
     "/resource#resources", "Go to the Resource Centre"),
    (("pcit",),
     "PCIT resources are in the Resource Centre — Resource → Case studies → “PCIT Resources” tile.",
     "/resource#resources", "Go to the Resource Centre"),
    (("map", "place", "coventry", "rugby", "warwickshire"),
     "Place maps for Warwickshire-North, South-Warwickshire, Rugby and Coventry are on the "
     "Contact page, and also under About → Partnership working.",
     "/contact", "Go to Contact"),
    (("partnership",),
     "Partnership working across the four places is covered on the About page — see the "
     "“Partnership working” section.",
     "/about#partnership", "Go to Partnership working"),
    (("team", "who is", "who's", "meet the"),
     "Meet the team on the About page under “Our team”, or see the full contact "
     "directory on the Contact page.",
     "/about#team", "Meet the team"),
    (("contact", "email", "who do i", "phone", "reach", "get in touch"),
     "Head to the Contact page for the full team directory and place maps, or email "
     "contact@cwdigitalchampions.nhs.uk and it'll reach the right person.",
     "/contact", "Go to Contact"),
    (("news", "article", "update"),
     "All the latest news and updates are on the Resource page, in the News feed section.",
     "/resource#news", "Go to the News feed"),
    (("case stud",),
     "Case studies and downloadable resources are in the Resource Centre — Resource → Case studies.",
     "/resource#resources", "Go to the Resource Centre"),
    (("insight",),
     "Team insights — like the GPAD walkthrough from Dr Raj Kanwar — are on the Resource page "
     "under Team insights.",
     "/resource#team-insight", "Go to Team insights"),
]
CHAT_FALLBACK_REPLY = (
    "I couldn't find an exact match for that. Try the Resource Centre under Resource → "
    "Case studies, or email contact@cwdigitalchampions.nhs.uk and the team will point you "
    "in the right direction."
)
CHAT_FALLBACK_LINK = ("/resource#resources", "Go to the Resource Centre")


def find_reply(message):
    lowered = message.lower()
    for keywords, reply, link, label in CHAT_RULES:
        if any(keyword in lowered for keyword in keywords):
            return reply, link, label
    return (CHAT_FALLBACK_REPLY,) + CHAT_FALLBACK_LINK


# instance_relative_config puts runtime data (the database) in instance/,
# Flask's standard convention for files that shouldn't be in the codebase
# or version control — separate from static/templates, which are code.
app = Flask(__name__, instance_relative_config=True)
os.makedirs(app.instance_path, exist_ok=True)
DB_PATH = os.path.join(app.instance_path, "data.sqlite")

app.secret_key = os.environ.get("SECRET_KEY", "change-this-before-real-use")
app.permanent_session_lifetime = timedelta(hours=8)

# Set to True once the site is served over HTTPS, so the session cookie is
# never sent unencrypted.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# ---------------------------------------------------------------- database

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS staff (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'staff',
            place TEXT,
            practice_name TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    db.commit()
    db.close()


# ------------------------------------------------------------------- auth

def current_user():
    if "user" not in g:
        g.user = None
        user_id = session.get("user_id")
        if user_id is not None:
            row = get_db().execute(
                "SELECT id, name, email, place, practice_name, role FROM staff WHERE id = ?",
                (user_id,),
            ).fetchone()
            if row:
                g.user = dict(row)
                is_root = g.user["email"].lower() in ADMIN_EMAILS
                g.user["is_root_admin"] = is_root
                g.user["is_admin"] = is_root or g.user["role"] == "admin"
    return g.user


def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def inject_globals():
    return {"current_user": current_user(), "csrf_token": get_csrf_token()}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login", next=request.path))
        if not user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def root_admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login", next=request.path))
        if not user["is_root_admin"]:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def csrf_protect(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get("csrf_token", "")
            if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
                abort(400)
        return view(*args, **kwargs)

    return wrapped


# ------------------------------------------------------------------ routes

@app.route("/")
def index():
    if current_user():
        return redirect(url_for("about"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("about"))

    error = None
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        place = request.form.get("place") or ""
        practice_name = (request.form.get("practiceName") or "").strip()

        if not name or not email or not password or not place or not practice_name:
            error = "All fields are required."
        elif place not in VALID_PLACES:
            error = "Please select a valid place."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        else:
            db = get_db()
            existing = db.execute("SELECT id FROM staff WHERE email = ?", (email,)).fetchone()
            if existing:
                error = "An account with that email already exists."
            else:
                password_hash = generate_password_hash(password)
                cursor = db.execute(
                    "INSERT INTO staff (name, email, password_hash, place, practice_name) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (name, email, password_hash, place, practice_name),
                )
                db.commit()
                session.clear()
                session.permanent = True
                session["user_id"] = cursor.lastrowid
                return redirect(request.args.get("next") or url_for("about"))

    return render_template("register.html", error=error, places=VALID_PLACES, form=request.form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("about"))

    error = None
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email or not password:
            error = "Email and password are required."
        else:
            user = get_db().execute("SELECT * FROM staff WHERE email = ?", (email,)).fetchone()
            if user is None or not check_password_hash(user["password_hash"], password):
                error = "Incorrect email or password."
            else:
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                return redirect(request.args.get("next") or url_for("about"))

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
@csrf_protect
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/resource")
@login_required
def resource():
    return render_template("resource.html")


@app.route("/contact")
@login_required
def contact():
    return render_template("contact.html")


@app.route("/gpad")
@login_required
def gpad():
    return render_template("gpad.html")


@app.route("/admin/staff")
@admin_required
def admin_staff():
    rows = get_db().execute(
        "SELECT id, name, email, place, practice_name, role, created_at FROM staff ORDER BY created_at DESC"
    ).fetchall()
    accounts = []
    for row in rows:
        account = dict(row)
        account["is_root_admin"] = account["email"].lower() in ADMIN_EMAILS
        accounts.append(account)
    return render_template("admin_staff.html", accounts=accounts, admin_emails=sorted(ADMIN_EMAILS))


@app.route("/admin/staff/<int:staff_id>/delete", methods=["POST"])
@admin_required
@csrf_protect
def admin_staff_delete(staff_id):
    db = get_db()
    if staff_id == current_user()["id"]:
        abort(400)
    target = db.execute("SELECT email FROM staff WHERE id = ?", (staff_id,)).fetchone()
    if target and target["email"].lower() in ADMIN_EMAILS:
        # Root admins are defined in .env, not the database — deleting the
        # row here wouldn't actually remove their access, so don't allow it
        # to avoid a confusing "deleted but they can still sign in" state.
        abort(400)
    db.execute("DELETE FROM staff WHERE id = ?", (staff_id,))
    db.commit()
    return redirect(url_for("admin_staff"))


@app.route("/admin/staff/<int:staff_id>/promote", methods=["POST"])
@root_admin_required
@csrf_protect
def admin_staff_promote(staff_id):
    db = get_db()
    db.execute("UPDATE staff SET role = 'admin' WHERE id = ?", (staff_id,))
    db.commit()
    return redirect(url_for("admin_staff"))


@app.route("/admin/staff/<int:staff_id>/demote", methods=["POST"])
@root_admin_required
@csrf_protect
def admin_staff_demote(staff_id):
    db = get_db()
    target = db.execute("SELECT email FROM staff WHERE id = ?", (staff_id,)).fetchone()
    if target and target["email"].lower() in ADMIN_EMAILS:
        # Root admins can't be demoted through the app — their status comes
        # from .env, so this would have no real effect and just confuse.
        abort(400)
    db.execute("UPDATE staff SET role = 'staff' WHERE id = ?", (staff_id,))
    db.commit()
    return redirect(url_for("admin_staff"))


@app.route("/api/chat", methods=["POST"])
@login_required
def chat():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"error": "Message is required."}), 400
    if len(message) > 2000:
        return jsonify({"error": "Message is too long."}), 400

    reply, link, label = find_reply(message)
    return jsonify({"reply": reply, "link": link, "label": label})


if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", "true").lower() == "true", port=int(os.environ.get("PORT", 5000)))
else:
    init_db()
