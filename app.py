from __future__ import annotations

import os
import re
import secrets
import shlex
import sqlite3
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo

import paramiko
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


ALLOWED_CERT_SUFFIXES = {".pem", ".crt", ".cer"}
ALLOWED_KEY_SUFFIXES = {".key", ".pem"}
PLACEHOLDERS = {"{{CERT_PEM}}": "/tmp/certificate.pem", "{{CERT_KEY}}": "/tmp/certificate.key"}
CRON_HELP = "cron 表达式必须为 5 段，例如：0 2 * * *"


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        DATA_DIR=os.environ.get("APP_DATA_DIR", str(Path(__file__).parent / "data")),
        TIMEZONE=os.environ.get("TZ", "Asia/Shanghai"),
        TESTING=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    if test_config:
        app.config.update(test_config)

    data_dir = Path(app.config["DATA_DIR"])
    upload_dir = data_dir / "uploads"
    data_dir.mkdir(parents=True, exist_ok=True)
    upload_dir.mkdir(parents=True, exist_ok=True)
    try:
        data_dir.chmod(0o700)
        upload_dir.chmod(0o700)
    except OSError:
        pass
    app.config["DATABASE"] = str(data_dir / "cert_deployer.db")
    app.config["UPLOAD_DIR"] = str(upload_dir)
    app.secret_key = _load_or_create(data_dir / "app.secret", lambda: secrets.token_hex(32).encode()).decode()
    app.extensions["credential_cipher"] = Fernet(_load_or_create(data_dir / "credentials.key", Fernet.generate_key))

    app.teardown_appcontext(close_db)
    register_routes(app)
    register_template_helpers(app)

    with app.app_context():
        init_db()
    try:
        Path(app.config["DATABASE"]).chmod(0o600)
    except OSError:
        pass

    if not app.config["TESTING"] and os.environ.get("DISABLE_SCHEDULER") != "1":
        scheduler = BackgroundScheduler(timezone=app.config["TIMEZONE"], daemon=True)
        scheduler.start()
        app.extensions["scheduler"] = scheduler
        with app.app_context():
            sync_scheduler(app)

    return app


def _load_or_create(path: Path, factory) -> bytes:
    if path.exists():
        return path.read_bytes().strip()
    value = factory()
    path.write_bytes(value + b"\n")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return value


def close_db(_error=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def db() -> sqlite3.Connection:
    from flask import current_app

    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def init_db() -> None:
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            center TEXT NOT NULL DEFAULT '',
            domains TEXT NOT NULL DEFAULT '',
            expires_at TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            cert_filename TEXT NOT NULL,
            key_filename TEXT NOT NULL,
            cert_path TEXT NOT NULL,
            key_path TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            domain TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL,
            auth_type TEXT NOT NULL CHECK(auth_type IN ('password', 'key')),
            password_enc TEXT NOT NULL DEFAULT '',
            private_key TEXT NOT NULL DEFAULT '',
            script TEXT NOT NULL,
            certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            cron TEXT NOT NULL,
            site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
            enabled INTEGER NOT NULL DEFAULT 1,
            notes TEXT NOT NULL DEFAULT '',
            last_run_at TEXT,
            last_status TEXT,
            last_output TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS task_sites (
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
            position INTEGER NOT NULL,
            PRIMARY KEY (task_id, site_id),
            UNIQUE (task_id, position)
        );
        CREATE TABLE IF NOT EXISTS deployments (
            id INTEGER PRIMARY KEY,
            site_id INTEGER NOT NULL,
            certificate_id INTEGER,
            task_id INTEGER,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            output TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY,
            category TEXT NOT NULL,
            level TEXT NOT NULL,
            actor TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            reference_type TEXT,
            reference_id INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_category ON audit_logs(category);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_logs_reference
            ON audit_logs(reference_type, reference_id, category)
            WHERE reference_type IS NOT NULL AND reference_id IS NOT NULL;
        """
    )
    user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    if "role" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO users(username, password_hash, role) VALUES (?, ?, 'admin')",
            ("libin", generate_password_hash("admin")),
        )
    elif conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] == 0:
        conn.execute("UPDATE users SET role='admin' WHERE id=(SELECT id FROM users ORDER BY id LIMIT 1)")
    conn.execute(
        "INSERT OR IGNORE INTO task_sites(task_id, site_id, position) SELECT id, site_id, 0 FROM tasks"
    )
    deployments = conn.execute(
        """SELECT d.*, s.name site_name, t.name task_name FROM deployments d
           LEFT JOIN sites s ON s.id=d.site_id LEFT JOIN tasks t ON t.id=d.task_id"""
    ).fetchall()
    for deployment in deployments:
        category = "task" if deployment["task_id"] else "site"
        target = deployment["task_name"] if deployment["task_id"] else deployment["site_name"]
        conn.execute(
            """INSERT OR IGNORE INTO audit_logs
               (category, level, actor, message, details, created_at, reference_type, reference_id)
               VALUES (?, ?, '历史记录', ?, ?, ?, 'deployment', ?)""",
            (
                category,
                "success" if deployment["status"] == "success" else "error",
                f"{'定时任务执行' if category == 'task' else '站点部署'}：{target or '已删除对象'}",
                deployment["output"],
                deployment["finished_at"] or deployment["started_at"],
                deployment["id"],
            ),
        )
    conn.commit()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_log(category: str, level: str, actor: str, message: str, details: str = "", reference_type: str | None = None, reference_id: int | None = None) -> None:
    db().execute(
        """INSERT OR IGNORE INTO audit_logs
           (category, level, actor, message, details, created_at, reference_type, reference_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (category, level, actor[:64], message[:500], details[-10000:], now_iso(), reference_type, reference_id),
    )
    db().commit()


def login_required(view):
    @wraps(view)
    def wrapped(**kwargs):
        if not g.get("user"):
            return redirect(url_for("login", next=request.full_path))
        return view(**kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(**kwargs):
        if not g.get("user"):
            return redirect(url_for("login", next=request.full_path))
        if g.user["role"] != "admin":
            abort(403, "仅管理员可以执行此操作")
        return view(**kwargs)

    return wrapped


def load_logged_in_user() -> None:
    user_id = session.get("user_id")
    g.user = db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone() if user_id else None
    if user_id and g.user is None:
        session.clear()


def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def validate_csrf() -> None:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not secrets.compare_digest(request.form.get("csrf_token", ""), session.get("csrf_token", "")):
            abort(400, "CSRF 校验失败，请刷新页面后重试")


def register_template_helpers(app: Flask) -> None:
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.template_filter("date")
    def format_date(value):
        if not value:
            return "—"
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).strftime("%Y-%m-%d")
        except ValueError:
            return value

    @app.template_filter("datetime")
    def format_datetime(value):
        if not value:
            return "—"
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(ZoneInfo(app.config["TIMEZONE"])).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return value

    @app.template_filter("days_left")
    def days_left(value):
        try:
            expiry = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            return (expiry - datetime.now(timezone.utc)).days
        except (TypeError, ValueError):
            return 0


def register_routes(app: Flask) -> None:
    app.before_request(validate_csrf)
    app.before_request(load_logged_in_user)

    @app.get("/icon.svg")
    def app_icon():
        return send_from_directory(Path(app.root_path) / "crt", "icon.svg", mimetype="image/svg+xml")

    @app.get("/login")
    def login():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        submitted_username = request.form.get("username", "").strip()
        user = db().execute("SELECT * FROM users WHERE username = ?", (submitted_username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], request.form.get("password", "")):
            write_log("login", "error", submitted_username or "未知用户", "登录失败", f"IP：{request.remote_addr or '未知'}")
            flash("用户名或密码错误", "error")
            return render_template("login.html"), 401
        write_log("login", "success", user["username"], "登录成功", f"IP：{request.remote_addr or '未知'}")
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        next_url = request.args.get("next", "")
        return redirect(next_url if next_url.startswith("/") and not next_url.startswith("//") else url_for("dashboard"))

    @app.post("/logout")
    @login_required
    def logout():
        write_log("login", "info", g.user["username"], "退出登录", f"IP：{request.remote_addr or '未知'}")
        session.clear()
        return redirect(url_for("login"))

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            user = db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
            old = request.form.get("old_password", "")
            new = request.form.get("new_password", "")
            if not check_password_hash(user["password_hash"], old):
                flash("当前密码不正确", "error")
            elif len(new) < 8:
                flash("新密码至少需要 8 个字符", "error")
            elif new != request.form.get("confirm_password"):
                flash("两次输入的新密码不一致", "error")
            else:
                db().execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new), user["id"]))
                db().commit()
                write_log("system", "success", user["username"], "修改个人密码")
                flash("密码已修改", "success")
                return redirect(url_for("dashboard"))
        return render_template("change_password.html")

    @app.get("/users")
    @admin_required
    def users():
        rows = db().execute("SELECT id, username, role FROM users ORDER BY username").fetchall()
        return render_template("users.html", users=rows)

    @app.route("/users/new", methods=["GET", "POST"])
    @admin_required
    def user_new():
        if request.method == "POST":
            try:
                save_user()
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                write_log("system", "success", g.user["username"], "新增用户", f"用户：{request.form['username'].strip()}；角色：{request.form['role']}")
                flash("用户已创建", "success")
                return redirect(url_for("users"))
        return render_template("user_form.html", user=None)

    @app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
    @admin_required
    def user_edit(user_id):
        user = db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user is None:
            abort(404)
        if request.method == "POST":
            try:
                save_user(user)
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                actor = g.user["username"]
                if user_id == session["user_id"]:
                    session["username"] = request.form["username"].strip()
                write_log("system", "success", actor, "修改用户", f"用户：{request.form['username'].strip()}；角色：{request.form['role']}")
                flash("用户信息已更新", "success")
                destination = "dashboard" if user_id == session["user_id"] and request.form["role"] == "user" else "users"
                return redirect(url_for(destination))
        return render_template("user_form.html", user=user)

    @app.post("/users/<int:user_id>/delete")
    @admin_required
    def user_delete(user_id):
        user = db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user is None:
            abort(404)
        if user_id == session["user_id"]:
            flash("不能删除当前登录用户", "error")
        elif user["role"] == "admin" and admin_count() == 1:
            flash("不能删除系统中最后一个管理员", "error")
        else:
            db().execute("DELETE FROM users WHERE id=?", (user_id,))
            db().commit()
            write_log("system", "success", g.user["username"], "删除用户", f"用户：{user['username']}")
            flash("用户已删除", "success")
        return redirect(url_for("users"))

    @app.get("/")
    @login_required
    def dashboard():
        conn = db()
        counts = {
            "certificates": conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0],
            "sites": conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0],
            "tasks": conn.execute("SELECT COUNT(*) FROM tasks WHERE enabled = 1").fetchone()[0],
        }
        certificates = conn.execute("SELECT * FROM certificates ORDER BY expires_at").fetchall()
        recent = conn.execute(
            """SELECT d.*, s.name site_name, c.name certificate_name
               FROM deployments d LEFT JOIN sites s ON s.id=d.site_id
               LEFT JOIN certificates c ON c.id=d.certificate_id
               ORDER BY d.id DESC LIMIT 8"""
        ).fetchall()
        return render_template("dashboard.html", counts=counts, certificates=certificates, recent=recent)

    @app.get("/help")
    @login_required
    def help_page():
        return render_template("help.html")

    @app.get("/logs")
    @login_required
    def logs():
        log_type = request.args.get("type", "all")
        if log_type not in {"all", "login", "site", "task"}:
            log_type = "all"
        start_value = request.args.get("start", "").strip()
        end_value = request.args.get("end", "").strip()
        conditions = []
        parameters = []
        if log_type != "all":
            conditions.append("category=?")
            parameters.append(log_type)
        try:
            start_time = parse_log_time(start_value, app.config["TIMEZONE"]) if start_value else None
            end_time = parse_log_time(end_value, app.config["TIMEZONE"]) if end_value else None
            if start_time and end_time and start_time > end_time:
                raise ValueError("开始时间不能晚于结束时间")
            if start_time:
                conditions.append("created_at>=?")
                parameters.append(start_time)
            if end_time:
                conditions.append("created_at<=?")
                parameters.append(end_time)
        except ValueError as exc:
            flash(str(exc), "error")
            start_value = end_value = ""
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        # shortcut: 每次最多展示 500 条，日志量明显增长后增加分页。
        rows = db().execute(f"SELECT * FROM audit_logs{where} ORDER BY created_at DESC, id DESC LIMIT 500", parameters).fetchall()
        return render_template(
            "logs.html",
            logs=rows,
            log_type=log_type,
            start_value=start_value,
            end_value=end_value,
            category_names={"login": "人员登录", "site": "站点部署", "task": "定时任务", "system": "系统"},
        )

    @app.get("/certificates")
    @login_required
    def certificates():
        rows = db().execute(
            """SELECT c.*, COUNT(s.id) site_count FROM certificates c
               LEFT JOIN sites s ON s.certificate_id=c.id GROUP BY c.id ORDER BY c.expires_at"""
        ).fetchall()
        return render_template("certificates.html", certificates=rows)

    @app.route("/certificates/new", methods=["GET", "POST"])
    @admin_required
    def certificate_new():
        if request.method == "POST":
            try:
                save_certificate()
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                flash("证书已上传并解析", "success")
                return redirect(url_for("certificates"))
        return render_template("certificate_form.html", certificate=None)

    @app.route("/certificates/<int:certificate_id>/edit", methods=["GET", "POST"])
    @admin_required
    def certificate_edit(certificate_id):
        certificate = get_or_404("certificates", certificate_id)
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            expires = request.form.get("expires_at", "").strip()
            if not name or not _valid_date(expires):
                flash("请填写证书名称和有效的到期日期", "error")
            else:
                db().execute(
                    "UPDATE certificates SET name=?, center=?, domains=?, expires_at=?, notes=? WHERE id=?",
                    (name, request.form.get("center", "").strip(), request.form.get("domains", "").strip(), expires, request.form.get("notes", "").strip(), certificate_id),
                )
                db().commit()
                flash("证书信息已更新", "success")
                return redirect(url_for("certificates"))
        return render_template("certificate_form.html", certificate=certificate)

    @app.post("/certificates/<int:certificate_id>/delete")
    @admin_required
    def certificate_delete(certificate_id):
        certificate = get_or_404("certificates", certificate_id)
        db().execute("DELETE FROM certificates WHERE id=?", (certificate_id,))
        db().commit()
        for filename in (certificate["cert_path"], certificate["key_path"]):
            try:
                Path(filename).unlink(missing_ok=True)
            except OSError:
                pass
        flash("证书已删除，原关联站点已解除绑定", "success")
        return redirect(url_for("certificates"))

    @app.get("/certificates/<int:certificate_id>/sites")
    @login_required
    def certificate_sites(certificate_id):
        certificate = get_or_404("certificates", certificate_id)
        sites = db().execute("SELECT * FROM sites WHERE certificate_id=? ORDER BY name", (certificate_id,)).fetchall()
        return render_template("certificate_sites.html", certificate=certificate, sites=sites)

    @app.get("/sites")
    @login_required
    def sites():
        rows = db().execute(
            "SELECT s.*, c.name certificate_name FROM sites s LEFT JOIN certificates c ON c.id=s.certificate_id ORDER BY s.name"
        ).fetchall()
        return render_template("sites.html", sites=rows, certificates=valid_certificates())

    @app.route("/sites/new", methods=["GET", "POST"])
    @admin_required
    def site_new():
        if request.method == "POST":
            try:
                save_site()
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                flash("站点已创建", "success")
                return redirect(url_for("sites"))
        return render_template("site_form.html", site=None, certificates=valid_certificates())

    @app.route("/sites/<int:site_id>/edit", methods=["GET", "POST"])
    @admin_required
    def site_edit(site_id):
        stored_site = get_or_404("sites", site_id)
        if request.method == "POST":
            try:
                save_site(stored_site)
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                flash("站点已更新", "success")
                return redirect(url_for("sites"))
        site = dict(stored_site)
        site["private_key"] = ""
        return render_template("site_form.html", site=site, certificates=valid_certificates())

    @app.post("/sites/set-certificate")
    @admin_required
    def sites_set_certificate():
        try:
            site_ids = list(dict.fromkeys(int(site_id) for site_id in request.form.getlist("site_ids")))
            certificate_id = int(request.form.get("certificate_id", ""))
        except ValueError:
            flash("站点或证书选择无效", "error")
            return redirect(url_for("sites"))
        if not site_ids:
            flash("请至少选择一个站点", "error")
            return redirect(url_for("sites"))
        certificate = db().execute("SELECT * FROM certificates WHERE id=?", (certificate_id,)).fetchone()
        if not certificate or not certificate_is_valid(certificate):
            flash("所选证书不存在或已经过期", "error")
            return redirect(url_for("sites"))
        placeholders = ",".join("?" for _ in site_ids)
        existing_ids = {row[0] for row in db().execute(f"SELECT id FROM sites WHERE id IN ({placeholders})", site_ids)}
        if existing_ids != set(site_ids):
            flash("部分所选站点不存在，请刷新页面后重试", "error")
            return redirect(url_for("sites"))
        db().execute(f"UPDATE sites SET certificate_id=? WHERE id IN ({placeholders})", [certificate_id, *site_ids])
        db().commit()
        write_log("system", "success", g.user["username"], "批量设置站点证书", f"证书：{certificate['name']}；站点数量：{len(site_ids)}")
        flash(f"已将证书“{certificate['name']}”应用到 {len(site_ids)} 个站点", "success")
        return redirect(url_for("sites"))

    @app.post("/sites/<int:site_id>/delete")
    @admin_required
    def site_delete(site_id):
        get_or_404("sites", site_id)
        conn = db()
        linked_tasks = conn.execute("SELECT task_id FROM task_sites WHERE site_id=?", (site_id,)).fetchall()
        for linked in linked_tasks:
            replacement = conn.execute(
                "SELECT site_id FROM task_sites WHERE task_id=? AND site_id<>? ORDER BY position LIMIT 1",
                (linked["task_id"], site_id),
            ).fetchone()
            if replacement:
                conn.execute("UPDATE tasks SET site_id=? WHERE id=?", (replacement["site_id"], linked["task_id"]))
        conn.execute("DELETE FROM sites WHERE id=?", (site_id,))
        conn.commit()
        sync_scheduler(app)
        flash("站点及其定时任务已删除", "success")
        return redirect(url_for("sites"))

    @app.post("/sites/<int:site_id>/deploy")
    @admin_required
    def site_deploy(site_id):
        get_or_404("sites", site_id)
        ok, output = deploy_site(app, site_id, actor=g.user["username"])
        flash(("部署成功：" if ok else "部署失败：") + output[-500:], "success" if ok else "error")
        return redirect(url_for("sites"))

    @app.get("/tasks")
    @login_required
    def tasks():
        rows = db().execute("SELECT * FROM tasks ORDER BY name").fetchall()
        task_rows = []
        for row in rows:
            item = dict(row)
            item["site_names"] = [site["name"] for site in get_task_sites(row["id"])]
            item["next_run_at"] = cron_next_times(item["cron"], app.config["TIMEZONE"])[0].isoformat() if item["enabled"] else None
            task_rows.append(item)
        return render_template("tasks.html", tasks=task_rows, timezone_name=app.config["TIMEZONE"])

    @app.get("/api/cron-next")
    @login_required
    def cron_next():
        expression = request.args.get("cron", "").strip()
        try:
            next_time = cron_next_times(expression, app.config["TIMEZONE"])[0]
        except (TypeError, ValueError):
            return jsonify(valid=False, message=CRON_HELP), 400
        return jsonify(
            valid=True,
            next_run=next_time.strftime("%Y-%m-%d %H:%M:%S"),
            timezone=app.config["TIMEZONE"],
        )

    @app.route("/tasks/new", methods=["GET", "POST"])
    @admin_required
    def task_new():
        if request.method == "POST":
            try:
                save_task()
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                sync_scheduler(app)
                flash("定时任务已创建", "success")
                return redirect(url_for("tasks"))
        available_sites, selected_sites = task_site_choices(request.form.getlist("site_ids"))
        return render_template("task_form.html", task=None, available_sites=available_sites, selected_sites=selected_sites, cron_help=CRON_HELP, timezone_name=app.config["TIMEZONE"])

    @app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
    @admin_required
    def task_edit(task_id):
        task = get_or_404("tasks", task_id)
        if request.method == "POST":
            try:
                save_task(task)
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                sync_scheduler(app)
                flash("定时任务已更新", "success")
                return redirect(url_for("tasks"))
        selected_ids = request.form.getlist("site_ids") if request.method == "POST" else [str(site["id"]) for site in get_task_sites(task_id)]
        available_sites, selected_sites = task_site_choices(selected_ids)
        return render_template("task_form.html", task=task, available_sites=available_sites, selected_sites=selected_sites, cron_help=CRON_HELP, timezone_name=app.config["TIMEZONE"])

    @app.post("/tasks/<int:task_id>/run")
    @admin_required
    def task_run(task_id):
        get_or_404("tasks", task_id)
        ok, output = run_task(app, task_id, actor=g.user["username"])
        flash(("任务执行成功：" if ok else "任务执行完成，但有站点失败：") + output[-500:], "success" if ok else "error")
        return redirect(url_for("tasks"))

    @app.post("/tasks/<int:task_id>/delete")
    @admin_required
    def task_delete(task_id):
        get_or_404("tasks", task_id)
        db().execute("DELETE FROM tasks WHERE id=?", (task_id,))
        db().commit()
        sync_scheduler(app)
        flash("定时任务已删除", "success")
        return redirect(url_for("tasks"))


def get_or_404(table: str, row_id: int):
    if table not in {"certificates", "sites", "tasks"}:
        abort(500)
    row = db().execute(f"SELECT * FROM {table} WHERE id=?", (row_id,)).fetchone()
    if row is None:
        abort(404)
    return row


def admin_count() -> int:
    return db().execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]


def save_user(existing=None) -> None:
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "")
    if not username or len(username) > 64:
        raise ValueError("用户名不能为空且不能超过 64 个字符")
    if role not in {"admin", "user"}:
        raise ValueError("请选择有效的用户角色")
    if not existing and len(password) < 8:
        raise ValueError("新用户密码至少需要 8 个字符")
    if password and len(password) < 8:
        raise ValueError("密码至少需要 8 个字符")
    if existing and existing["role"] == "admin" and role != "admin" and admin_count() == 1:
        raise ValueError("不能降级系统中最后一个管理员")
    conn = db()
    try:
        if existing:
            if password:
                conn.execute(
                    "UPDATE users SET username=?, password_hash=?, role=? WHERE id=?",
                    (username, generate_password_hash(password), role, existing["id"]),
                )
            else:
                conn.execute("UPDATE users SET username=?, role=? WHERE id=?", (username, role, existing["id"]))
        else:
            conn.execute(
                "INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role),
            )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ValueError("用户名已存在") from exc


def all_certificates():
    return db().execute("SELECT * FROM certificates ORDER BY name").fetchall()


def certificate_is_valid(certificate) -> bool:
    try:
        expires_at = datetime.fromisoformat(str(certificate["expires_at"]).replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return expires_at > datetime.now(timezone.utc)
    except (TypeError, ValueError):
        return False


def valid_certificates():
    return [certificate for certificate in all_certificates() if certificate_is_valid(certificate)]


def all_sites():
    return db().execute("SELECT * FROM sites ORDER BY name").fetchall()


def get_task_sites(task_id: int):
    return db().execute(
        """SELECT s.* FROM task_sites ts JOIN sites s ON s.id=ts.site_id
           WHERE ts.task_id=? ORDER BY ts.position""",
        (task_id,),
    ).fetchall()


def task_site_choices(selected_ids) -> tuple[list, list]:
    sites = all_sites()
    by_id = {str(site["id"]): site for site in sites}
    ordered_ids = list(dict.fromkeys(str(site_id) for site_id in selected_ids))
    selected = [by_id[site_id] for site_id in ordered_ids if site_id in by_id]
    selected_set = {site["id"] for site in selected}
    available = [site for site in sites if site["id"] not in selected_set]
    return available, selected


def _valid_date(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except (TypeError, ValueError):
        return False


def save_certificate() -> None:
    cert_file = request.files.get("cert_file")
    key_file = request.files.get("key_file")
    name = request.form.get("name", "").strip()
    if not name or not cert_file or not cert_file.filename or not key_file or not key_file.filename:
        raise ValueError("证书名称、证书文件和私钥文件均不能为空")
    if Path(cert_file.filename).suffix.lower() not in ALLOWED_CERT_SUFFIXES:
        raise ValueError("证书文件仅支持 .pem、.crt、.cer")
    if Path(key_file.filename).suffix.lower() not in ALLOWED_KEY_SUFFIXES:
        raise ValueError("私钥文件仅支持 .key、.pem")

    cert_bytes = cert_file.read()
    key_bytes = key_file.read()
    try:
        certificate = x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        try:
            certificate = x509.load_der_x509_certificate(cert_bytes)
        except ValueError as exc:
            raise ValueError("无法解析证书文件，请上传有效的 PEM/DER X.509 证书") from exc
    try:
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("无法解析私钥；当前仅支持未加密的 PEM 私钥") from exc
    cert_public = certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_public = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert_public != key_public:
        raise ValueError("证书与私钥不匹配")

    try:
        domains = ", ".join(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        names = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        domains = names[0].value if names else ""
    center = certificate.issuer.rfc4514_string()
    expiry = certificate.not_valid_after_utc.isoformat() if hasattr(certificate, "not_valid_after_utc") else certificate.not_valid_after.replace(tzinfo=timezone.utc).isoformat()

    token = uuid.uuid4().hex
    cert_name = f"{token}_{secure_filename(cert_file.filename)}"
    key_name = f"{token}_{secure_filename(key_file.filename)}"
    from flask import current_app

    cert_path = Path(current_app.config["UPLOAD_DIR"]) / cert_name
    key_path = Path(current_app.config["UPLOAD_DIR"]) / key_name
    cert_path.write_bytes(cert_bytes)
    key_path.write_bytes(key_bytes)
    try:
        key_path.chmod(0o600)
        db().execute(
            """INSERT INTO certificates
               (name, center, domains, expires_at, notes, cert_filename, key_filename, cert_path, key_path, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, center, domains, expiry, request.form.get("notes", "").strip(), cert_file.filename, key_file.filename, str(cert_path), str(key_path), now_iso()),
        )
        db().commit()
    except Exception:
        cert_path.unlink(missing_ok=True)
        key_path.unlink(missing_ok=True)
        raise


def save_site(existing=None) -> None:
    form = request.form
    required = [form.get(field, "").strip() for field in ("name", "host", "username", "script")]
    if not all(required):
        raise ValueError("站点名称、SSH 主机、用户名和部署脚本不能为空")
    try:
        port = int(form.get("port", "22"))
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError as exc:
        raise ValueError("SSH 端口必须在 1–65535 之间") from exc
    auth_type = form.get("auth_type")
    if auth_type not in {"password", "key"}:
        raise ValueError("请选择 SSH 登录方式")
    password = form.get("password", "")
    private_key = form.get("private_key", "").strip()
    if auth_type == "password" and not password and not (existing and existing["password_enc"]):
        raise ValueError("密码登录方式需要填写 SSH 密码")
    if auth_type == "key" and not private_key and not (existing and existing["private_key"]):
        raise ValueError("私钥登录方式需要填写 PEM 私钥")
    script = normalize_script(form["script"]).strip()
    error = validate_shell(script)
    if error:
        raise ValueError(f"Shell 语法错误：{error}")
    certificate_id = form.get("certificate_id") or None
    if certificate_id:
        certificate = db().execute("SELECT * FROM certificates WHERE id=?", (certificate_id,)).fetchone()
        if not certificate or not certificate_is_valid(certificate):
            raise ValueError("关联证书不存在或已经过期")
    password_enc = existing["password_enc"] if existing else ""
    if password:
        password_enc = encrypt_secret(password)
    private_key_enc = existing["private_key"] if existing else ""
    if private_key:
        private_key_enc = encrypt_secret(private_key)
    if existing:
        db().execute(
            """UPDATE sites SET name=?, domain=?, host=?, port=?, username=?, auth_type=?, password_enc=?,
               private_key=?, script=?, certificate_id=?, notes=? WHERE id=?""",
            (form["name"].strip(), form.get("domain", "").strip(), form["host"].strip(), port, form["username"].strip(), auth_type, password_enc, private_key_enc, script, certificate_id, form.get("notes", "").strip(), existing["id"]),
        )
    else:
        db().execute(
            """INSERT INTO sites
               (name, domain, host, port, username, auth_type, password_enc, private_key, script, certificate_id, notes, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (form["name"].strip(), form.get("domain", "").strip(), form["host"].strip(), port, form["username"].strip(), auth_type, password_enc, private_key_enc, script, certificate_id, form.get("notes", "").strip(), now_iso()),
        )
    db().commit()


def validate_shell(script: str) -> str:
    check_script = normalize_script(script)
    for placeholder, value in PLACEHOLDERS.items():
        check_script = check_script.replace(placeholder, shlex.quote(value))
    if re.search(r"{{[^}]+}}", check_script):
        return "包含不支持的模板变量，仅可使用 {{CERT_PEM}} 和 {{CERT_KEY}}"
    try:
        result = subprocess.run(["bash", "-n"], input=check_script, text=True, capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)
    return result.stderr.strip()


def save_task(existing=None) -> None:
    name = request.form.get("name", "").strip()
    cron = request.form.get("cron", "").strip()
    raw_site_ids = request.form.getlist("site_ids")
    try:
        site_ids = list(dict.fromkeys(int(site_id) for site_id in raw_site_ids if site_id))
    except ValueError as exc:
        raise ValueError("站点选择无效") from exc
    if not name or not cron or not site_ids:
        raise ValueError("任务名称、cron 表达式和至少一个站点不能为空")
    try:
        CronTrigger.from_crontab(cron)
    except ValueError as exc:
        raise ValueError(CRON_HELP) from exc
    placeholders = ",".join("?" for _ in site_ids)
    existing_site_ids = {row[0] for row in db().execute(f"SELECT id FROM sites WHERE id IN ({placeholders})", site_ids)}
    if existing_site_ids != set(site_ids):
        raise ValueError("所选站点不存在")
    values = (name, cron, site_ids[0], 1 if request.form.get("enabled") else 0, request.form.get("notes", "").strip())
    conn = db()
    if existing:
        conn.execute("UPDATE tasks SET name=?, cron=?, site_id=?, enabled=?, notes=? WHERE id=?", values + (existing["id"],))
        task_id = existing["id"]
    else:
        task_id = conn.execute(
            "INSERT INTO tasks(name, cron, site_id, enabled, notes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            values + (now_iso(),),
        ).lastrowid
    conn.execute("DELETE FROM task_sites WHERE task_id=?", (task_id,))
    conn.executemany(
        "INSERT INTO task_sites(task_id, site_id, position) VALUES (?, ?, ?)",
        [(task_id, site_id, position) for position, site_id in enumerate(site_ids)],
    )
    conn.commit()


def cron_next_times(expression: str, timezone_name: str = "Asia/Shanghai", count: int = 1, now: datetime | None = None) -> list[datetime]:
    tz = ZoneInfo(timezone_name)
    current = now.astimezone(tz) if now else datetime.now(tz)
    trigger = CronTrigger.from_crontab(expression, timezone=tz)
    result = []
    previous = None
    for _ in range(count):
        next_time = trigger.get_next_fire_time(previous, current)
        if next_time is None:
            break
        result.append(next_time)
        previous = next_time
        current = next_time
    if not result:
        raise ValueError("cron 表达式没有可执行时间")
    return result


def parse_log_time(value: str, timezone_name: str) -> str:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("请输入有效的日志查询时间") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=ZoneInfo(timezone_name))
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")


def sync_scheduler(app: Flask) -> None:
    scheduler = app.extensions.get("scheduler")
    if not scheduler:
        return
    for job in scheduler.get_jobs():
        if job.id.startswith("task-"):
            scheduler.remove_job(job.id)
    with app.app_context():
        tasks = db().execute("SELECT * FROM tasks WHERE enabled=1").fetchall()
        for task in tasks:
            scheduler.add_job(
                scheduled_deploy,
                CronTrigger.from_crontab(task["cron"], timezone=scheduler.timezone),
                args=[app, task["id"]],
                id=f"task-{task['id']}",
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )


def scheduled_deploy(app: Flask, task_id: int) -> None:
    run_task(app, task_id, actor="系统调度器")


def run_task(app: Flask, task_id: int, actor: str) -> tuple[bool, str]:
    with app.app_context():
        task = db().execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not task:
            return False, "任务不存在"
        sites = get_task_sites(task_id)
        if not sites:
            message = "任务没有关联任何站点"
            db().execute(
                "UPDATE tasks SET last_run_at=?, last_status='failed', last_output=? WHERE id=?",
                (now_iso(), message, task_id),
            )
            db().commit()
            write_log("task", "error", actor, f"定时任务执行：{task['name']}", message)
            return False, message

        results = []
        all_ok = True
        for site in sites:
            try:
                ok, message = deploy_site(app, site["id"], task_id, actor=actor, update_task=False)
            except Exception as exc:
                ok, message = False, f"未预期错误：{exc}"
                write_log("task", "error", actor, f"定时任务执行：{task['name']} → {site['name']}", message)
            all_ok = all_ok and ok
            results.append(f"[{'成功' if ok else '失败'}] {site['name']}：{message}")

        summary = "\n".join(results)[-10000:]
        db().execute(
            "UPDATE tasks SET last_run_at=?, last_status=?, last_output=? WHERE id=?",
            (now_iso(), "success" if all_ok else "failed", summary, task_id),
        )
        db().commit()
        write_log(
            "task",
            "success" if all_ok else "error",
            actor,
            f"定时任务汇总：{task['name']}",
            summary,
        )
        return all_ok, summary


def deploy_site(app: Flask, site_id: int, task_id: int | None = None, actor: str = "系统", update_task: bool = True) -> tuple[bool, str]:
    with app.app_context():
        site = db().execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
        if not site:
            return False, "站点不存在"
        certificate = db().execute("SELECT * FROM certificates WHERE id=?", (site["certificate_id"],)).fetchone() if site["certificate_id"] else None
        if not certificate:
            return _record_failure(site_id, None, task_id, "站点未关联证书", actor, update_task)
        deployment_id = db().execute(
            "INSERT INTO deployments(site_id, certificate_id, task_id, started_at, status) VALUES (?, ?, ?, ?, 'running')",
            (site_id, certificate["id"], task_id, now_iso()),
        ).lastrowid
        db().commit()

        client = paramiko.SSHClient()
        remote_dir = f"/tmp/cert-deployer-{uuid.uuid4().hex}"
        try:
            configure_ssh_client(client)
            connect_args = dict(hostname=site["host"], port=site["port"], username=site["username"], timeout=15, banner_timeout=15, auth_timeout=15)
            if site["auth_type"] == "password":
                try:
                    connect_args["password"] = decrypt_secret(site["password_enc"], app)
                except (InvalidToken, ValueError) as exc:
                    raise RuntimeError("SSH 密码无法解密，可能是 credentials.key 已变更") from exc
            else:
                connect_args["pkey"] = _load_private_key(decrypt_secret(site["private_key"], app))
            client.connect(**connect_args)
            sftp = client.open_sftp()
            sftp.mkdir(remote_dir)
            remote_cert = f"{remote_dir}/{secure_filename(certificate['cert_filename'])}"
            remote_key = f"{remote_dir}/{secure_filename(certificate['key_filename'])}"
            sftp.put(certificate["cert_path"], remote_cert)
            sftp.put(certificate["key_path"], remote_key)
            sftp.chmod(remote_key, 0o600)
            script = normalize_script(site["script"]).replace("{{CERT_PEM}}", shlex.quote(remote_cert)).replace("{{CERT_KEY}}", shlex.quote(remote_key))
            remote_script = f"{remote_dir}/deploy.sh"
            with sftp.file(remote_script, "w") as script_file:
                script_file.write(("set -e\n" + script + "\n").encode())
            sftp.chmod(remote_script, 0o700)
            sftp.close()

            message = execute_remote_script(client, remote_script)
            ok = True
        except Exception as exc:
            ok, message = False, str(exc)
        finally:
            try:
                client.exec_command(f"rm -rf -- {shlex.quote(remote_dir)}", timeout=10)
            except Exception:
                pass
            client.close()

        message = message[-10000:]
        db().execute(
            "UPDATE deployments SET finished_at=?, status=?, output=? WHERE id=?",
            (now_iso(), "success" if ok else "failed", message, deployment_id),
        )
        if task_id and update_task:
            db().execute(
                "UPDATE tasks SET last_run_at=?, last_status=?, last_output=? WHERE id=?",
                (now_iso(), "success" if ok else "failed", message, task_id),
            )
        db().commit()
        task = db().execute("SELECT name FROM tasks WHERE id=?", (task_id,)).fetchone() if task_id else None
        target_name = f"{task['name']} → {site['name']}" if task else site["name"]
        write_log(
            "task" if task_id else "site",
            "success" if ok else "error",
            actor,
            f"{'定时任务执行' if task_id else '站点部署'}：{target_name}",
            message,
            "deployment",
            deployment_id,
        )
        return ok, message


def _record_failure(site_id: int, certificate_id: int | None, task_id: int | None, message: str, actor: str, update_task: bool = True):
    deployment_id = db().execute(
        "INSERT INTO deployments(site_id, certificate_id, task_id, started_at, finished_at, status, output) VALUES (?, ?, ?, ?, ?, 'failed', ?)",
        (site_id, certificate_id, task_id, now_iso(), now_iso(), message),
    ).lastrowid
    if task_id and update_task:
        db().execute("UPDATE tasks SET last_run_at=?, last_status='failed', last_output=? WHERE id=?", (now_iso(), message, task_id))
    db().commit()
    site = db().execute("SELECT name FROM sites WHERE id=?", (site_id,)).fetchone()
    task = db().execute("SELECT name FROM tasks WHERE id=?", (task_id,)).fetchone() if task_id else None
    target_name = f"{task['name']} → {site['name'] if site else '未知站点'}" if task else site["name"] if site else "未知对象"
    write_log(
        "task" if task_id else "site",
        "error",
        actor,
        f"{'定时任务执行' if task_id else '站点部署'}：{target_name}",
        message,
        "deployment",
        deployment_id,
    )
    return False, message


def _load_private_key(value: str):
    key_types = [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]
    if hasattr(paramiko, "DSSKey"):
        key_types.append(paramiko.DSSKey)
    for key_type in key_types:
        try:
            import io

            return key_type.from_private_key(io.StringIO(value))
        except (paramiko.SSHException, ValueError):
            continue
    raise ValueError("无法解析 SSH 私钥（支持 RSA、Ed25519、ECDSA、DSS）")


def configure_ssh_client(client: paramiko.SSHClient) -> Path:
    known_hosts = Path(os.environ.get("SSH_KNOWN_HOSTS", "~/.ssh/known_hosts")).expanduser()
    parent_was_missing = not known_hosts.parent.exists()
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    if parent_was_missing:
        try:
            known_hosts.parent.chmod(0o700)
        except OSError:
            pass
    known_hosts.touch(exist_ok=True)
    try:
        known_hosts.chmod(0o600)
    except OSError:
        pass
    client.load_system_host_keys()
    client.load_host_keys(str(known_hosts))
    if "SSH_STRICT_HOST_KEYS" in os.environ:
        strict = os.environ["SSH_STRICT_HOST_KEYS"] == "1"
    elif "SSH_ALLOW_UNKNOWN_HOSTS" in os.environ:
        strict = os.environ["SSH_ALLOW_UNKNOWN_HOSTS"] != "1"
    else:
        strict = False
    client.set_missing_host_key_policy(paramiko.RejectPolicy() if strict else paramiko.AutoAddPolicy())
    return known_hosts


def execute_remote_script(client: paramiko.SSHClient, remote_script: str) -> str:
    stdin, stdout, stderr = client.exec_command(
        f"bash -e -- {shlex.quote(remote_script)}",
        timeout=120,
        get_pty=True,
    )
    stdin.channel.shutdown_write()
    output = (stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")).strip()
    exit_code = stdout.channel.recv_exit_status()
    if exit_code != 0:
        raise RuntimeError(f"脚本退出码 {exit_code}\n{output}")
    return output or "执行完成"


def normalize_script(script: str) -> str:
    return script.replace("\r\n", "\n").replace("\r", "\n")


def encrypt_secret(value: str) -> str:
    from flask import current_app

    return current_app.extensions["credential_cipher"].encrypt(value.encode()).decode()


def decrypt_secret(value: str, app: Flask | None = None) -> str:
    if not value:
        return ""
    if app is None:
        from flask import current_app

        cipher = current_app.extensions["credential_cipher"]
    else:
        cipher = app.extensions["credential_cipher"]
    return cipher.decrypt(value.encode()).decode()


app = create_app()


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "5000")), debug=False)
