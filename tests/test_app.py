import io
import os
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from zoneinfo import ZoneInfo

os.environ["DISABLE_SCHEDULER"] = "1"

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import create_app, cron_next_times, normalize_script, run_task, validate_shell, write_log


def certificate_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.example.com")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.example.com"), x509.DNSName("example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )


class AppTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "DATA_DIR": self.tmp.name})
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def csrf(self, path="/login"):
        response = self.client.get(path)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def login(self, username="libin", password="admin"):
        token = self.csrf()
        response = self.client.post("/login", data={"csrf_token": token, "username": username, "password": password})
        self.assertEqual(response.status_code, 302)

    def upload_certificate(self):
        cert, key = certificate_pair()
        token = self.csrf("/certificates/new")
        return self.client.post(
            "/certificates/new",
            data={
                "csrf_token": token,
                "name": "Example wildcard",
                "notes": "test",
                "cert_file": (io.BytesIO(cert), "example.pem"),
                "key_file": (io.BytesIO(key), "example.key"),
            },
            content_type="multipart/form-data",
        )

    def create_site(self, name, host="127.0.0.1", script="install -m 0644 {{CERT_PEM}} /tmp/default.pem"):
        token = self.csrf("/sites/new")
        return self.client.post(
            "/sites/new",
            data={
                "csrf_token": token,
                "name": name,
                "domain": "",
                "host": host,
                "port": "22",
                "username": "deploy",
                "auth_type": "password",
                "password": "secret",
                "certificate_id": "1",
                "script": script,
            },
        )

    def test_login_required_and_default_login(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        self.login()
        self.assertIn("运行概览", self.client.get("/").get_data(as_text=True))
        help_page = self.client.get("/help")
        self.assertEqual(help_page.status_code, 200)
        self.assertIn("https://github.com/liblinc-debug/autocert.git", help_page.get_data(as_text=True))
        self.assertIn("AutoCert v1.5", help_page.get_data(as_text=True))
        self.assertIn("Linux systemd 安装", help_page.get_data(as_text=True))

    def test_log_categories_and_time_filter(self):
        self.login()
        with self.app.app_context():
            write_log("site", "success", "libin", "site-marker", "site details")
            write_log("task", "error", "系统调度器", "task-marker", "task details")
        all_logs = self.client.get("/logs?type=all").get_data(as_text=True)
        self.assertIn("site-marker", all_logs)
        self.assertIn("task-marker", all_logs)
        site_logs = self.client.get("/logs?type=site").get_data(as_text=True)
        self.assertIn("site-marker", site_logs)
        self.assertNotIn("task-marker", site_logs)
        future_logs = self.client.get("/logs?type=all&start=2099-01-01T00:00").get_data(as_text=True)
        self.assertNotIn("site-marker", future_logs)
        self.assertIn("当前条件下没有日志记录", future_logs)

    def test_admin_can_manage_users_and_regular_user_is_read_only(self):
        self.login()
        self.assertIn("用户管理", self.client.get("/users").get_data(as_text=True))
        token = self.csrf("/users/new")
        response = self.client.post(
            "/users/new",
            data={"csrf_token": token, "username": "reader", "password": "readerpass", "role": "user"},
        )
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as current_session:
            current_session.clear()
        self.login("reader", "readerpass")
        certificate_page = self.client.get("/certificates")
        self.assertEqual(certificate_page.status_code, 200)
        self.assertNotIn("上传证书", certificate_page.get_data(as_text=True))
        self.assertEqual(self.client.get("/certificates/new").status_code, 403)
        self.assertEqual(self.client.get("/sites/new").status_code, 403)
        self.assertEqual(self.client.get("/tasks/new").status_code, 403)
        self.assertEqual(self.client.get("/users").status_code, 403)
        self.assertEqual(self.client.get("/logs").status_code, 200)
        token = self.csrf("/sites")
        self.assertEqual(
            self.client.post("/sites/set-certificate", data={"csrf_token": token, "site_ids": ["1"], "certificate_id": "1"}).status_code,
            403,
        )

    def test_last_admin_cannot_be_demoted(self):
        self.login()
        token = self.csrf("/users/1/edit")
        response = self.client.post(
            "/users/1/edit",
            data={"csrf_token": token, "username": "libin", "password": "", "role": "user"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("不能降级系统中最后一个管理员", response.get_data(as_text=True))

    def test_certificate_is_parsed_and_saved(self):
        self.login()
        response = self.upload_certificate()
        self.assertEqual(response.status_code, 302)
        page = self.client.get("/certificates").get_data(as_text=True)
        self.assertIn("Example wildcard", page)
        self.assertIn("*.example.com", page)

    def test_mismatched_private_key_is_rejected(self):
        self.login()
        cert, _key = certificate_pair()
        _other_cert, other_key = certificate_pair()
        token = self.csrf("/certificates/new")
        response = self.client.post(
            "/certificates/new",
            data={
                "csrf_token": token,
                "name": "bad",
                "cert_file": (io.BytesIO(cert), "bad.pem"),
                "key_file": (io.BytesIO(other_key), "bad.key"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("证书与私钥不匹配", response.get_data(as_text=True))

    def test_shell_validation(self):
        self.assertEqual(validate_shell("cp {{CERT_PEM}} /tmp/cert.pem\nnginx -t"), "")
        self.assertIn("不支持的模板变量", validate_shell("cp {{OTHER}} /tmp/file"))
        self.assertTrue(validate_shell("if true; then\necho broken"))
        self.assertEqual(normalize_script("cp a default.pem\r\ncp b default.key\r"), "cp a default.pem\ncp b default.key\n")

    def test_cron_next_time_uses_shanghai_timezone(self):
        now = datetime(2026, 11, 4, 17, 41, 30, tzinfo=ZoneInfo("Asia/Shanghai"))
        next_time = cron_next_times("42 17 * * *", now=now)[0]
        self.assertEqual(next_time.strftime("%Y-%m-%d %H:%M:%S %z"), "2026-11-04 17:42:00 +0800")

    def test_task_keeps_site_order_and_continues_after_failure(self):
        self.login()
        self.upload_certificate()
        self.assertEqual(self.create_site("Site A").status_code, 302)
        self.assertEqual(self.create_site("Site B").status_code, 302)
        token = self.csrf("/tasks/new")
        response = self.client.post(
            "/tasks/new",
            data={
                "csrf_token": token,
                "name": "ordered task",
                "cron": "0 2 * * *",
                "site_ids": ["2", "1"],
                "enabled": "on",
            },
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            from app import db

            ordered_ids = [row[0] for row in db().execute("SELECT site_id FROM task_sites WHERE task_id=1 ORDER BY position")]
            self.assertEqual(ordered_ids, [2, 1])
        with patch("app.deploy_site", side_effect=[(False, "first failed"), (True, "second ok")]) as mocked:
            ok, summary = run_task(self.app, 1, "libin")
        self.assertFalse(ok)
        self.assertEqual([call.args[1] for call in mocked.call_args_list], [2, 1])
        self.assertIn("[失败] Site B", summary)
        self.assertIn("[成功] Site A", summary)
        with self.app.app_context():
            from app import db

            task = db().execute("SELECT last_status FROM tasks WHERE id=1").fetchone()
            self.assertEqual(task["last_status"], "failed")
            log = db().execute("SELECT details FROM audit_logs WHERE message='定时任务汇总：ordered task'").fetchone()
            self.assertIn("first failed", log["details"])
        token = self.csrf("/sites")
        self.assertEqual(self.client.post("/sites/2/delete", data={"csrf_token": token}).status_code, 302)
        with self.app.app_context():
            from app import db

            task = db().execute("SELECT site_id FROM tasks WHERE id=1").fetchone()
            self.assertEqual(task["site_id"], 1)
            remaining = [row[0] for row in db().execute("SELECT site_id FROM task_sites WHERE task_id=1 ORDER BY position")]
            self.assertEqual(remaining, [1])

    def test_bulk_certificate_update_only_allows_unexpired_certificates(self):
        self.login()
        self.upload_certificate()
        self.create_site("Site A")
        self.create_site("Site B")
        with self.app.app_context():
            from app import db

            valid = db().execute("SELECT * FROM certificates WHERE id=1").fetchone()
            db().execute(
                """INSERT INTO certificates
                   (name, center, domains, expires_at, notes, cert_filename, key_filename, cert_path, key_path, created_at)
                   VALUES ('Expired certificate', ?, ?, '2020-01-01T00:00:00+00:00', '', ?, ?, ?, ?, ?)""",
                (valid["center"], valid["domains"], valid["cert_filename"], valid["key_filename"], valid["cert_path"], valid["key_path"], valid["created_at"]),
            )
            db().execute("UPDATE sites SET certificate_id=NULL")
            db().commit()
        sites_page = self.client.get("/sites").get_data(as_text=True)
        edit_page = self.client.get("/sites/1/edit").get_data(as_text=True)
        self.assertIn("Example wildcard", sites_page)
        self.assertNotIn("Expired certificate", sites_page)
        self.assertNotIn("Expired certificate", edit_page)
        token = self.csrf("/sites")
        response = self.client.post(
            "/sites/set-certificate",
            data={"csrf_token": token, "site_ids": ["1", "2"], "certificate_id": "1"},
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            from app import db

            assigned = [row[0] for row in db().execute("SELECT certificate_id FROM sites ORDER BY id")]
            self.assertEqual(assigned, [1, 1])
            db().execute("UPDATE sites SET certificate_id=NULL WHERE id=1")
            db().commit()
        token = self.csrf("/sites")
        self.client.post(
            "/sites/set-certificate",
            data={"csrf_token": token, "site_ids": ["1"], "certificate_id": "2"},
        )
        with self.app.app_context():
            from app import db

            self.assertIsNone(db().execute("SELECT certificate_id FROM sites WHERE id=1").fetchone()[0])

    def test_site_and_cron_validation(self):
        self.login()
        self.upload_certificate()
        response = self.create_site(
            "Open API",
            script="install -m 0644 {{CERT_PEM}} /tmp/default.pem\r\ninstall -m 0600 {{CERT_KEY}} /tmp/default.key\r\n",
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            from app import db

            stored = db().execute("SELECT password_enc, script FROM sites WHERE id=1").fetchone()
            self.assertNotIn("secret", stored["password_enc"])
            self.assertNotIn("\r", stored["script"])
        token = self.csrf("/tasks/new")
        response = self.client.post(
            "/tasks/new",
            data={"csrf_token": token, "name": "bad cron", "site_ids": ["1"], "cron": "not-a-cron", "enabled": "on"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("cron 表达式必须为 5 段", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
