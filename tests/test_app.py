import io
import os
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

os.environ["DISABLE_SCHEDULER"] = "1"

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app import create_app, cron_next_times, normalize_script, validate_shell, write_log


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

    def test_login_required_and_default_login(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        self.login()
        self.assertIn("运行概览", self.client.get("/").get_data(as_text=True))
        help_page = self.client.get("/help")
        self.assertEqual(help_page.status_code, 200)
        self.assertIn("https://github.com/liblinc-debug/autocert.git", help_page.get_data(as_text=True))
        self.assertIn("AutoCert v1.3", help_page.get_data(as_text=True))
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

    def test_site_and_cron_validation(self):
        self.login()
        self.upload_certificate()
        token = self.csrf("/sites/new")
        response = self.client.post(
            "/sites/new",
            data={
                "csrf_token": token,
                "name": "Open API",
                "domain": "openapi.example.com",
                "host": "127.0.0.1",
                "port": "22",
                "username": "deploy",
                "auth_type": "password",
                "password": "secret",
                "certificate_id": "1",
                "script": "install -m 0644 {{CERT_PEM}} /tmp/default.pem\r\ninstall -m 0600 {{CERT_KEY}} /tmp/default.key\r\n",
            },
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
            data={"csrf_token": token, "name": "bad cron", "site_id": "1", "cron": "not-a-cron", "enabled": "on"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("cron 表达式必须为 5 段", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
