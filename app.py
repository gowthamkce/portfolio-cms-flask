"""
Portfolio CMS — Flask Backend
Compatible with Python 3.14+ and supabase-py v2.x
"""

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from functools import wraps
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from supabase import create_client, Client
from flask import send_from_directory

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

# ── Supabase ──────────────────────────────────────────────────────────────────
SUPABASE_URL: str = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY: str = os.environ.get("SUPABASE_KEY", "")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise EnvironmentError(
        "\nMissing SUPABASE_URL or SUPABASE_KEY in .env file.\n"
        "Copy .env.example to .env and fill in your values.\n"
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── Flask ─────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-prod")

CORS(
    app,
    supports_credentials=True,
    resources={r"/api/*": {"origins": ["http://127.0.0.1:5500", "http://localhost:5500"]}}
)

IS_PROD      = os.environ.get("FLASK_ENV") == "production"
FRONTEND_URL = os.environ.get("FRONTEND_URL", "")
BASE_URL     = os.environ.get("BASE_URL", "http://localhost:5000")

# ── CORS — manual implementation to support wildcard Vercel subdomains ────────
def is_allowed_origin(origin: str) -> bool:
    if not origin:
        return False
    allowed = [
        "http://localhost:5500", "http://127.0.0.1:5500",
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:5000", "http://127.0.0.1:5000",
        FRONTEND_URL,
    ]
    if origin in allowed:
        return True
    # Allow ALL vercel.app subdomains (covers preview deployments too)
    if origin.endswith(".vercel.app"):
        return True
    return False

@app.route('/static/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(
        os.path.join(app.root_path, "static/uploads"),
        filename
    )

@app.after_request
def apply_cors(response):
    origin = request.headers.get("Origin", "")
    if is_allowed_origin(origin):
        response.headers["Access-Control-Allow-Origin"]      = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Vary"]                             = "Origin"
    return response


@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        origin = request.headers.get("Origin", "")
        res = jsonify({"status": "ok"})
        if is_allowed_origin(origin):
            res.headers["Access-Control-Allow-Origin"]      = origin
            res.headers["Access-Control-Allow-Credentials"] = "true"
            res.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
            res.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
            res.headers["Vary"]                             = "Origin"
        return res, 200


# ── Session / Cookie config ───────────────────────────────────────────────────
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=IS_PROD,
    SESSION_COOKIE_SAMESITE="None" if IS_PROD else "Lax",
    SESSION_COOKIE_NAME="portfolio_session",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

app.url_map.strict_slashes = False

# ── File Upload ───────────────────────────────────────────────────────────────
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin_id" not in session:
            return jsonify({"error": "Unauthorized. Please log in."}), 401
        return f(*args, **kwargs)
    return decorated

def ok(data, status: int = 200):      return jsonify(data), status
def err(msg: str, status: int = 400): return jsonify({"error": msg}), status
def new_id() -> str:                  return str(uuid.uuid4())
def now_iso() -> str:                 return datetime.now(timezone.utc).isoformat()

def track_visit(page: str):
    try:
        supabase.table("page_views").insert({
            "id": new_id(), "page": page, "visited_at": now_iso(),
            "ip": request.remote_addr or "unknown",
            "user_agent": (request.headers.get("User-Agent") or "")[:200],
        }).execute()
    except Exception as exc:
        print(f"[analytics] {exc}")

def sb_insert(table, data):
    res = supabase.table(table).insert(data).execute()
    return res.data[0] if res.data else data

def sb_update(table, pk_col, pk_val, data):
    res = supabase.table(table).update(data).eq(pk_col, pk_val).execute()
    return res.data[0] if res.data else {"message": "Updated"}

def sb_delete(table, pk_col, pk_val):
    supabase.table(table).delete().eq(pk_col, pk_val).execute()


# ── Health ────────────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    import sys
    return ok({"status": "ok", "time": now_iso(), "python": sys.version})


# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    body     = request.get_json(silent=True) or {}
    email    = body.get("email", "").strip().lower()
    password = body.get("password", "")
    if not email or not password:
        return err("Email and password are required.", 400)
    try:
        rows = supabase.table("admin").select("*").eq("email", email).limit(1).execute().data
    except Exception as exc:
        return err(f"Database error: {exc}", 500)
    if not rows:
        return err("Invalid credentials.", 401)
    admin  = rows[0]
    stored = admin.get("password", "")
    if stored.startswith("pbkdf2:") or stored.startswith("scrypt:"):
        valid = check_password_hash(stored, password)
    else:
        valid = (stored == password)
    if not valid:
        return err("Invalid credentials.", 401)
    session.clear()
    session["admin_id"]   = admin["admin_id"]
    session["admin_name"] = admin.get("name", "Admin")
    session.permanent     = True
    return ok({"message": "Login successful", "name": admin.get("name", "Admin")})


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return ok({"message": "Logged out."})


@app.route("/api/auth/me")
def me():
    if "admin_id" not in session:
        return ok({"logged_in": False})
    return ok({"logged_in": True, "name": session.get("admin_name", "Admin"), "admin_id": session["admin_id"]})



@app.route("/")
def home():
    return render_template("index.html")

@app.route("/admin")
def admin_panel():
    return render_template("admin.html")


# ── DASHBOARD ─────────────────────────────────────────────────────────────────
@app.route("/api/dashboard")
@login_required
def dashboard_stats():
    try:
        thirty_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        unread    = supabase.table("contact_messages").select("message_id", count="exact").eq("read_status", False).execute()
        total_m   = supabase.table("contact_messages").select("message_id", count="exact").execute()
        projects  = supabase.table("projects").select("project_id", count="exact").execute()
        skills    = supabase.table("skills").select("skill_id", count="exact").execute()
        views_30  = supabase.table("page_views").select("id", count="exact").gte("visited_at", thirty_ago).execute()
        views_all = supabase.table("page_views").select("id", count="exact").execute()
        raw_ip    = supabase.table("page_views").select("ip").gte("visited_at", thirty_ago).execute().data or []
        unique    = len({r["ip"] for r in raw_ip if r.get("ip")})
        return ok({
            "unread_messages": unread.count or 0, "total_messages": total_m.count or 0,
            "projects": projects.count or 0,       "skills": skills.count or 0,
            "views_30": views_30.count or 0,        "views_all": views_all.count or 0,
            "unique_visitors": unique,
        })
    except Exception as exc:
        print("DASHBOARD ERROR:", exc)
        return err(f"Stats unavailable: {exc}", 500)


# ── ANALYTICS ─────────────────────────────────────────────────────────────────
@app.route("/api/analytics")
@login_required
def get_analytics():
    try:
        thirty_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        rows = supabase.table("page_views").select("*").gte("visited_at", thirty_ago).order("visited_at", desc=True).execute().data or []
        pages: dict = {}
        for r in rows:
            p = r.get("page") or "/"; pages[p] = pages.get(p, 0) + 1
        daily: dict = {}
        for i in range(7):
            d = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d"); daily[d] = 0
        for r in rows:
            d = (r.get("visited_at") or "")[:10]
            if d in daily: daily[d] += 1
        return ok({"total": len(rows), "unique": len({r.get("ip") for r in rows if r.get("ip")}),
                   "by_page": pages, "daily_last7": dict(sorted(daily.items()))})
    except Exception as exc:
        return err(f"Analytics error: {exc}", 500)


# ── PROFILE ───────────────────────────────────────────────────────────────────
@app.route("/api/profile")
def get_profile():
    track_visit("profile")
    try:
        res = supabase.table("profile").select("*").limit(1).execute()
        return ok(res.data[0] if res.data else {})
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/profile", methods=["POST"])
@login_required
def create_profile():
    body = request.get_json(silent=True) or {}
    data = {
        "name":         body.get("name", "").strip(),
        "title":        body.get("title", "").strip(),
        "bio":          body.get("bio", "").strip(),
        "email":        body.get("email", "").strip(),
        "resume_link":  body.get("resume_link", "").strip(),
        "github_url":   body.get("github_url", "").strip(),
        "linkedin_url": body.get("linkedin_url", "").strip(),
        "twitter_url":  body.get("twitter_url", "").strip(),
    }
    if body.get("profile_image"):
        data["profile_image"] = body["profile_image"]
    try:
        res = supabase.table("profile").insert(data).execute()
        return ok(res.data[0], 201)
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/profile/<profile_id>", methods=["PUT"])
@login_required
def update_profile(profile_id):
    try:
        body = request.get_json()          # ← must be this, NOT request.form
        data = {
            "name":          body.get("name", "").strip(),
            "title":         body.get("title", "").strip(),
            "bio":           body.get("bio", "").strip(),
            "email":         body.get("email", "").strip(),
            "resume_link":   body.get("resume_link", "").strip(),
            "github_url":    body.get("github_url", "").strip(),
            "linkedin_url":  body.get("linkedin_url", "").strip(),
            "twitter_url":   body.get("twitter_url", "").strip(),
        }
        if body.get("profile_image"):
            data["profile_image"] = body["profile_image"]

        return ok(sb_update("profile", "profile_id", profile_id, data))
    except Exception as exc:
        print("PROFILE UPDATE ERROR:", exc)
        return err(str(exc), 500)

@app.route("/api/upload-profile", methods=["POST"])
@login_required
def upload_profile():
    try:
        file = request.files.get("file")
        if not file: return jsonify({"error": "No file uploaded"}), 400
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        filename = str(uuid.uuid4()) + "_" + secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return jsonify({"url": f"{BASE_URL}/static/uploads/{filename}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PROJECTS ──────────────────────────────────────────────────────────────────
@app.route("/api/project")
def get_projects():
    track_visit("projects")
    try:
        rows = supabase.table("projects").select("*").order("created_at", desc=True).execute().data or []
        return ok(rows)
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/project", methods=["POST"])
@login_required
def create_project():
    try:
        data = {
            "title":       request.form.get("title", "").strip(),
            "description": request.form.get("description", "").strip(),
            "tech_stack":  request.form.get("tech_stack", "").strip(),
            "github_link": request.form.get("github_link", "").strip(),
            "live_link":   request.form.get("live_link", "").strip(),
            "featured":    request.form.get("featured", "false").lower() == "true",
        }
        if not data["title"]: return err("Title is required.", 400)
        image_file = request.files.get("image")
        if image_file and image_file.filename:
            filename = str(uuid.uuid4()) + "_" + secure_filename(image_file.filename)
            image_file.save(os.path.join(UPLOAD_FOLDER, filename))
            data["image"] = f"{BASE_URL}/static/uploads/{filename}"
        res = supabase.table("projects").insert(data).execute()
        return ok(res.data[0] if res.data else data, 201)
    except Exception as exc:
        print("PROJECT CREATE ERROR:", exc)
        return err(str(exc), 500)

@app.route("/api/project/<project_id>", methods=["PUT"])
@login_required
def update_project(project_id):
    try:
        data = {
            "title":       request.form.get("title", "").strip(),
            "description": request.form.get("description", "").strip(),
            "tech_stack":  request.form.get("tech_stack", "").strip(),
            "github_link": request.form.get("github_link", "").strip(),
            "live_link":   request.form.get("live_link", "").strip(),
            "featured":    request.form.get("featured", "false").lower() == "true",
        }
        data = {k: v for k, v in data.items() if v != "" and v is not None}
        data.pop("project_id", None)
        image_file = request.files.get("image")
        if image_file and image_file.filename:
            filename = str(uuid.uuid4()) + "_" + secure_filename(image_file.filename)
            image_file.save(os.path.join(UPLOAD_FOLDER, filename))
            data["image"] = f"{BASE_URL}/static/uploads/{filename}"
        return ok(sb_update("projects", "project_id", project_id, data))
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/project/<project_id>", methods=["DELETE"])
@login_required
def delete_project(project_id):
    try:
        sb_delete("projects", "project_id", project_id)
        return ok({"message": "Project deleted."})
    except Exception as exc:
        return err(str(exc), 500)


# ── SKILLS ────────────────────────────────────────────────────────────────────
@app.route("/api/skills")
def get_skills():
    try:
        rows = supabase.table("skills").select("*").execute().data or []
        return ok(rows)
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/skills", methods=["POST"])
@login_required
def create_skill():
    data = request.get_json(silent=True) or {}
    try:
        return ok(sb_insert("skills", {
            "skill_name":  data.get("skill_name"),
            "category":    data.get("category", "General"),
            "skill_level": data.get("skill_level"),
        }), 201)
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/skills/<skill_id>", methods=["PUT"])
@login_required
def update_skill(skill_id):
    data = request.get_json(silent=True) or {}
    data.pop("skill_id", None)
    try:
        return ok(sb_update("skills", "skill_id", skill_id, data))
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/skills/<skill_id>", methods=["DELETE"])
@login_required
def delete_skill(skill_id):
    try:
        sb_delete("skills", "skill_id", skill_id)
        return ok({"message": "Skill deleted."})
    except Exception as exc:
        return err(str(exc), 500)


# ── EXPERIENCE ────────────────────────────────────────────────────────────────
@app.route("/api/experience")
def get_experience():
    try:
        rows = supabase.table("experience").select("*").order("start_date", desc=True).execute().data or []
        return ok(rows)
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/experience", methods=["POST"])
@login_required
def create_experience():
    data = request.get_json(silent=True) or {}
    if not data.get("company_name") or not data.get("role"):
        return err("company_name and role are required", 400)
    try:
        res = supabase.table("experience").insert({
            "company_name": data.get("company_name"), "role": data.get("role"),
            "start_date": data.get("start_date"),     "end_date": data.get("end_date"),
            "location": data.get("location"),          "description": data.get("description"),
        }).execute()
        return ok(res.data, 201)
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/experience/<experience_id>", methods=["PUT"])
@login_required
def update_experience(experience_id):
    data = request.get_json(silent=True) or {}
    data.pop("experience_id", None)
    try:
        return ok(sb_update("experience", "experience_id", experience_id, data))
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/experience/<experience_id>", methods=["DELETE"])
@login_required
def delete_experience(experience_id):
    try:
        sb_delete("experience", "experience_id", experience_id)
        return ok({"message": "Experience deleted."})
    except Exception as exc:
        return err(str(exc), 500)


# ── EDUCATION ─────────────────────────────────────────────────────────────────
@app.route("/api/education")
def get_education():
    try:
        rows = supabase.table("education").select("*").order("end_year", desc=True).execute().data or []
        return ok(rows)
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/education", methods=["POST"])
@login_required
def create_education():
    data = request.get_json(silent=True) or {}
    if not data.get("institution") or not data.get("degree"):
        return err("institution and degree are required", 400)
    try:
        return ok(sb_insert("education", data), 201)
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/education/<education_id>", methods=["PUT"])
@login_required
def update_education(education_id):
    data = request.get_json(silent=True) or {}
    data.pop("education_id", None)
    try:
        return ok(sb_update("education", "education_id", education_id, data))
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/education/<education_id>", methods=["DELETE"])
@login_required
def delete_education(education_id):
    try:
        sb_delete("education", "education_id", education_id)
        return ok({"message": "Education deleted."})
    except Exception as exc:
        return err(str(exc), 500)


# ── CONTACT ───────────────────────────────────────────────────────────────────
@app.route("/api/contact", methods=["POST"])
def send_message():
    body = request.get_json(silent=True) or {}
    for field in ("name", "email", "subject", "message"):
        if not str(body.get(field, "")).strip():
            return err(f"Field '{field}' is required.", 400)
    try:
        supabase.table("contact_messages").insert({
            "name": body["name"].strip(), "email": body["email"].strip().lower(),
            "subject": body["subject"].strip(), "message": body["message"].strip(),
            "created_at": now_iso(), "read_status": False,
        }).execute()
        return ok({"message": "Message sent successfully!"}, 201)
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/contact")
@login_required
def get_messages():
    try:
        rows = supabase.table("contact_messages").select("*").order("created_at", desc=True).execute().data or []
        return ok(rows)
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/contact/<message_id>/read", methods=["PUT"])
@login_required
def mark_read(message_id):
    try:
        sb_update("contact_messages", "message_id", message_id, {"read_status": True})
        return ok({"message": "Marked as read."})
    except Exception as exc:
        return err(str(exc), 500)

@app.route("/api/contact/<message_id>", methods=["DELETE"])
@login_required
def delete_message(message_id):
    try:
        sb_delete("contact_messages", "message_id", message_id)
        return ok({"message": "Message deleted."})
    except Exception as exc:
        return err(str(exc), 500)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = not IS_PROD
    print(f"\n  Portfolio CMS  →  http://localhost:{port}")
    print(f"  Mode: {'production' if IS_PROD else 'development'}  |  Debug: {debug}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)