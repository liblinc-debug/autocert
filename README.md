# 数字证书自动部署中心

一个面向内部运维的轻量 Web 工具，用于把证书上传、站点分发、Nginx 校验/重载和定时执行统一管理起来。它对应当前 `airsensor.top` 证书需要分别登录深信服宿主机、Docker 容器及阿里云服务器手工更新的场景。

## 功能

- 登录验证、用户改密和用户管理；首次账号为 `libin`，密码为 `admin`
- 管理员拥有全部功能权限，普通用户只能查看概览、证书、站点和定时任务
- 上传 X.509 证书和私钥，自动识别颁发机构、SAN 域名和到期时间
- 校验证书与私钥是否匹配，30 天内到期或已经过期时醒目标记
- 维护站点域名、SSH 地址、密码/私钥认证、关联证书和 Shell 部署脚本
- 部署时通过 SFTP 把证书传到目标服务器临时目录，再执行脚本并自动清理
- 使用 `bash -n` 校验脚本语法，支持在光标处插入证书和私钥路径变量
- 使用标准五段 cron 表达式定时部署，也可手动立即运行
- 最近部署状态记录，浅色/深色主题切换

## 快速开始

需要 Python 3.10+，应用服务器还需安装 `bash`。

```bash
chmod +x startup.sh
./startup.sh
```

浏览器访问 `http://服务器IP:5000`，使用 `libin / admin` 登录，然后在右上角立即修改初始密码。

脚本使用 Waitress WSGI 服务，默认监听 `0.0.0.0:5000`。可通过环境变量调整：

```bash
HOST=127.0.0.1 PORT=8080 ./startup.sh
```

应用数据保存在 `./data`：

- `cert_deployer.db`：业务数据
- `uploads/`：证书和私钥文件
- `app.secret`：登录会话密钥
- `credentials.key`：SSH 密码和私钥的加密密钥

请把整个 `data` 目录作为一组备份，并限制为仅应用运行用户可读。丢失 `credentials.key` 后，已经保存的 SSH 密码将无法解密。

## 配置站点脚本

脚本支持两个变量：

- `{{CERT_PEM}}`：部署时上传到远端临时目录的证书路径
- `{{CERT_KEY}}`：部署时上传到远端临时目录的私钥路径

例如，阿里云宿主机可使用：

```bash
install -m 0644 {{CERT_PEM}} /etc/nginx/cert/default.pem
install -m 0600 {{CERT_KEY}} /etc/nginx/cert/default.key
nginx -t
nginx -s reload
```

对于容器场景，建议脚本先复制到宿主机已挂载的共享证书目录，再进入容器校验和重载。例如：

```bash
install -m 0644 {{CERT_PEM}} /etst/share/prod/nginx/cert/current.pem
install -m 0600 {{CERT_KEY}} /etst/share/prod/nginx/cert/current.key
docker exec air-apps_app-nginx-app nginx -t
docker exec air-apps_app-nginx-app nginx -s reload
```

脚本以配置的 SSH 用户权限执行。需要 `sudo` 或 `docker` 权限时，应在目标服务器提前配置免交互的最小权限；脚本不要包含交互式命令。

## SSH 主机密钥

应用默认读取运行用户的 `~/.ssh/known_hosts` 并拒绝未知主机。首次连接前，建议由管理员核对指纹并加入 `known_hosts`。仅在受控内网且明确接受风险时，可临时允许未知主机：

```bash
SSH_ALLOW_UNKNOWN_HOSTS=1 ./startup.sh
```

## 定时任务

采用五段 cron：`分 时 日 月 星期`，时区默认为 `Asia/Shanghai`。例如每天凌晨 2 点：

```text
0 2 * * *
```

定时任务每次运行时使用站点当前关联的证书，因此更新证书关联后无需重建任务。

## 测试

```bash
.venv/bin/python -m unittest discover -s tests -v
```

测试覆盖登录、证书解析、证书/私钥匹配、Shell 语法和 cron 校验。

## 生产部署建议

- 将工具仅开放在管理网或 VPN 内，并在前置 Nginx 上启用 HTTPS。
- 首次登录后立即修改初始密码。
- 使用独立、低权限的 SSH 部署账号，只授予证书目录和 Nginx 重载所需权限。
- 仅运行一个应用进程；当前内置调度器保存在应用进程中，多进程会重复调度。
- 升级或迁移前完整备份 `data` 目录。

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
