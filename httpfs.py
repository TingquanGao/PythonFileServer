#!/usr/bin/env python3
"""
httpfs.py - 轻量级 HTTP 文件服务器
零第三方依赖，仅使用 Python 标准库

用法:
    python httpfs.py [-p PORT] [-d DIR] [-P PASSWORD] [-w WHITELIST] [-b BIND]
"""

import argparse
import hashlib
import ipaddress
import os
import secrets
import sys
import time
import urllib.parse
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, HTTPServer


# ── 全局 session 存储（token -> 过期时间） ────────────────────────────────────
SESSIONS: dict[str, float] = {}
SESSION_TTL = 86400  # 24小时

# ── 命令行参数（启动后填充） ──────────────────────────────────────────────────
CFG: argparse.Namespace | None = None
PASSWORD_HASH: str | None = None  # sha256(password)
WHITELIST: list = []  # ipaddress 对象列表


# ──────────────────────────────────────────────────────────────────────────────
# HTML 模板
# ──────────────────────────────────────────────────────────────────────────────

LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 - HTTP 文件服务器</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #f0f2f5; display: flex; align-items: center;
          justify-content: center; min-height: 100vh; }}
  .card {{ background: #fff; border-radius: 12px; padding: 40px;
           box-shadow: 0 4px 24px rgba(0,0,0,.1); width: 340px; }}
  h1 {{ font-size: 1.4rem; color: #1a1a2e; margin-bottom: 8px; }}
  p.sub {{ color: #666; font-size: .9rem; margin-bottom: 24px; }}
  .err {{ color: #e74c3c; font-size: .88rem; margin-bottom: 12px; }}
  input[type=password] {{
    width: 100%; padding: 10px 14px; border: 1px solid #ddd;
    border-radius: 8px; font-size: 1rem; outline: none;
    transition: border .2s;
  }}
  input[type=password]:focus {{ border-color: #4a90d9; }}
  button {{
    margin-top: 16px; width: 100%; padding: 11px;
    background: #4a90d9; color: #fff; border: none;
    border-radius: 8px; font-size: 1rem; cursor: pointer;
    transition: background .2s;
  }}
  button:hover {{ background: #357abf; }}
</style>
</head>
<body>
<div class="card">
  <h1>HTTP 文件服务器</h1>
  <p class="sub">请输入密码以继续访问</p>
  {error}
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="密码" autofocus required>
    <input type="hidden" name="next" value="{next}">
    <button type="submit">登 录</button>
  </form>
</div>
</body>
</html>
"""

DIR_HTML = """\
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} - HTTP 文件服务器</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #f0f2f5; color: #333; }}
  .container {{ max-width: 960px; margin: 32px auto; padding: 0 16px; }}
  h1 {{ font-size: 1.3rem; color: #1a1a2e; margin-bottom: 20px;
        word-break: break-all; }}
  .card {{ background: #fff; border-radius: 12px;
           box-shadow: 0 2px 12px rgba(0,0,0,.08); overflow: hidden; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #f7f8fa; padding: 10px 16px; text-align: left;
        font-size: .85rem; color: #888; font-weight: 600;
        border-bottom: 1px solid #eee; }}
  td {{ padding: 10px 16px; border-bottom: 1px solid #f0f0f0;
        font-size: .92rem; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f9fbff; }}
  td.name {{ max-width: 0; overflow: hidden; text-overflow: ellipsis;
             white-space: nowrap; }}
  td.size, td.mtime {{ white-space: nowrap; color: #888; text-align: right; }}
  a {{ color: #4a90d9; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .icon {{ margin-right: 6px; }}

  .upload-card {{ background: #fff; border-radius: 12px; margin-top: 20px;
                  box-shadow: 0 2px 12px rgba(0,0,0,.08); padding: 24px; }}
  .upload-card h2 {{ font-size: 1rem; color: #1a1a2e; margin-bottom: 16px; }}
  .drop-zone {{
    border: 2px dashed #c8d6e8; border-radius: 10px; padding: 32px;
    text-align: center; color: #888; cursor: pointer;
    transition: border-color .2s, background .2s;
    position: relative;
  }}
  .drop-zone.dragover {{ border-color: #4a90d9; background: #f0f7ff; }}
  .drop-zone input[type=file] {{
    position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%;
  }}
  .drop-zone p {{ pointer-events: none; }}
  .drop-zone .hint {{ font-size: .82rem; margin-top: 6px; }}
  #file-list {{ margin-top: 12px; font-size: .88rem; color: #555; }}
  button.upload-btn {{
    margin-top: 14px; padding: 9px 28px;
    background: #4a90d9; color: #fff; border: none;
    border-radius: 8px; font-size: .95rem; cursor: pointer;
  }}
  button.upload-btn:hover {{ background: #357abf; }}
  #progress {{ margin-top: 10px; font-size: .88rem; color: #4a90d9; }}

  .breadcrumb {{ font-size: .88rem; color: #888; margin-bottom: 14px; }}
  .breadcrumb a {{ color: #4a90d9; }}
  .msg {{ padding: 10px 16px; border-radius: 8px; margin-bottom: 16px;
          font-size: .9rem; }}
  .msg.ok {{ background: #eaffea; color: #27ae60; }}
  .msg.err {{ background: #fff0f0; color: #e74c3c; }}
</style>
</head>
<body>
<div class="container">
  <div class="breadcrumb">{breadcrumb}</div>
  <h1>&#128193; {title}</h1>
  {message}
  <div class="card">
    <table>
      <thead>
        <tr>
          <th style="width:60%">名称</th>
          <th style="width:15%">大小</th>
          <th style="width:25%">修改时间</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>

  <div class="upload-card">
    <h2>&#128228; 上传文件</h2>
    <form id="upload-form" method="POST" enctype="multipart/form-data"
          action="{upload_action}">
      <div class="drop-zone" id="drop-zone">
        <input type="file" name="files" multiple id="file-input">
        <p>&#128194; 点击选择文件，或将文件拖到此处</p>
        <p class="hint">支持多文件同时上传</p>
      </div>
      <div id="file-list"></div>
      <button type="submit" class="upload-btn">上 传</button>
      <div id="progress"></div>
    </form>
  </div>
</div>
<script>
const dz = document.getElementById('drop-zone');
const fi = document.getElementById('file-input');
const fl = document.getElementById('file-list');

fi.addEventListener('change', () => updateList(fi.files));
dz.addEventListener('dragover', e => {{ e.preventDefault(); dz.classList.add('dragover'); }});
dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
dz.addEventListener('drop', e => {{
  e.preventDefault(); dz.classList.remove('dragover');
  fi.files = e.dataTransfer.files;
  updateList(e.dataTransfer.files);
}});

function updateList(files) {{
  fl.innerHTML = Array.from(files).map(f =>
    `<div>&#128196; ${{f.name}} (${{fmtSize(f.size)}})</div>`).join('');
}}
function fmtSize(b) {{
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
  return (b/1073741824).toFixed(2) + ' GB';
}}
</script>
</body>
</html>
"""


# ──────────────────────────────────────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────────────────────────────────────

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def is_whitelisted(ip: str) -> bool:
    if not WHITELIST:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        for net in WHITELIST:
            if addr in net:
                return True
    except ValueError:
        pass
    return False


def check_session(cookie_header: str | None) -> bool:
    if not cookie_header:
        return False
    now = time.time()
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("session="):
            token = part[len("session="):]
            exp = SESSIONS.get(token)
            if exp and exp > now:
                return True
    return False


def make_session_token() -> str:
    token = secrets.token_hex(32)
    SESSIONS[token] = time.time() + SESSION_TTL
    return token


def format_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n/1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n/1024**2:.1f} MB"
    return f"{n/1024**3:.2f} GB"


def safe_path(base: str, rel: str) -> str | None:
    """将 URL 路径解析为文件系统绝对路径，如果逃出 base 则返回 None"""
    # 解码 URL 编码
    rel = urllib.parse.unquote(rel)
    # 规范化：去掉开头的 /
    rel = rel.lstrip("/")
    candidate = os.path.realpath(os.path.join(base, rel))
    base_real = os.path.realpath(base)
    if candidate == base_real or candidate.startswith(base_real + os.sep):
        return candidate
    return None


def build_breadcrumb(url_path: str) -> str:
    parts = [p for p in url_path.strip("/").split("/") if p]
    crumbs = ['<a href="/">&#127968; 根目录</a>']
    acc = ""
    for p in parts:
        acc += "/" + urllib.parse.quote(p)
        crumbs.append(f'<a href="{acc}">{p}</a>')
    return " / ".join(crumbs)


def parse_multipart(rfile, content_type: str, content_length: int):
    """解析 multipart/form-data，返回字段 dict 和文件列表"""
    # 读取全部数据（流式处理大文件时可改为分块）
    raw = rfile.read(content_length)
    # 构造符合 email 解析要求的头部
    header = f"Content-Type: {content_type}\r\n\r\n".encode()
    msg = BytesParser().parsebytes(header + raw)
    fields = {}
    files = []  # [(filename, data)]
    for part in msg.get_payload():
        cd = part.get("Content-Disposition", "")
        params = {}
        for item in cd.split(";"):
            item = item.strip()
            if "=" in item:
                k, v = item.split("=", 1)
                params[k.strip()] = v.strip().strip('"')
        name = params.get("name", "")
        filename = params.get("filename", "")
        payload = part.get_payload(decode=True) or b""
        if filename:
            files.append((filename, payload))
        else:
            fields[name] = payload.decode(errors="replace")
    return fields, files


# ──────────────────────────────────────────────────────────────────────────────
# HTTP 请求处理器
# ──────────────────────────────────────────────────────────────────────────────

class FileServerHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        ip = self.client_address[0]
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {ip} - {format % args}")

    # ── 认证检查 ────────────────────────────────────────────────────────────

    def need_auth(self) -> bool:
        """当前请求是否需要认证"""
        if PASSWORD_HASH is None:
            return False  # 无密码模式
        if is_whitelisted(self.client_address[0]):
            return False  # 白名单免密
        return True

    def is_authed(self) -> bool:
        """当前请求是否已通过认证（Cookie Session 或 HTTP Basic Auth）"""
        if not self.need_auth():
            return True
        if check_session(self.headers.get("Cookie")):
            return True
        return self._check_basic_auth()

    def _check_basic_auth(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.lower().startswith("basic "):
            return False
        import base64
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            _, password = decoded.split(":", 1)
            return sha256(password) == PASSWORD_HASH
        except Exception:
            return False

    def _require_basic_auth(self):
        """返回 401，触发浏览器/wget 弹出 Basic Auth 对话框"""
        body = b"401 Unauthorized"
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="httpfs"')
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── 响应辅助 ────────────────────────────────────────────────────────────

    def send_html(self, html: str, code: int = 200):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, code: int = 302):
        self.send_response(code)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ── GET ─────────────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        url_path = parsed.path

        # 登录页
        if url_path == "/login":
            if not self.need_auth():
                self.redirect("/")
                return
            self.send_html(LOGIN_HTML.format(error="", next="/"))
            return

        # 需要认证但未认证
        if not self.is_authed():
            # 携带了 Authorization 头说明是非浏览器客户端，返回 401
            if self.headers.get("Authorization"):
                self._require_basic_auth()
                return
            target = urllib.parse.quote(url_path, safe="")
            self.redirect(f"/login?next={target}")
            return

        # 正常文件/目录服务
        fspath = safe_path(CFG.dir, url_path)
        if fspath is None:
            self.send_error(403, "Forbidden")
            return

        if not os.path.exists(fspath):
            self.send_error(404, "Not Found")
            return

        if os.path.isdir(fspath):
            self._serve_dir(fspath, url_path, parsed.query)
        else:
            self._serve_file(fspath)

    def _serve_dir(self, fspath: str, url_path: str, query: str):
        # 提取消息提示（上传后跳转带参）
        qs = urllib.parse.parse_qs(query)
        msg = ""
        if "ok" in qs:
            names = ", ".join(qs["ok"])
            msg = f'<div class="msg ok">&#10003; 上传成功：{names}</div>'
        if "err" in qs:
            msg = f'<div class="msg err">&#10007; 上传失败：{qs["err"][0]}</div>'

        # 规范化 URL 路径（确保以 / 结尾）
        if not url_path.endswith("/"):
            self.redirect(url_path + "/")
            return

        try:
            def sort_key(name):
                full = os.path.join(fspath, name)
                is_hidden = name.startswith(".")
                is_file = not os.path.isdir(full)
                return (is_hidden, is_file, name.lower())

            names = sorted(os.listdir(fspath), key=sort_key)
        except PermissionError:
            self.send_error(403, "Permission Denied")
            return

        rows = ""
        # 返回上级目录
        if url_path != "/":
            parent = url_path.rstrip("/").rsplit("/", 1)[0] + "/"
            rows += (
                f'<tr><td class="name"><a href="{parent}">&#128281; ..</a></td>'
                f'<td class="size">-</td><td class="mtime">-</td></tr>\n'
            )

        for name in names:
            full = os.path.join(fspath, name)
            try:
                stat = os.stat(full)
            except OSError:
                # 损坏的符号链接或竞态删除，用 lstat 回退
                try:
                    stat = os.lstat(full)
                except OSError:
                    continue
            is_dir = os.path.isdir(full)
            icon = "&#128193;" if is_dir else "&#128196;"
            href = urllib.parse.quote(name, safe="") + ("/" if is_dir else "")
            size_str = "-" if is_dir else format_size(stat.st_size)
            mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime))
            rows += (
                f'<tr><td class="name"><span class="icon">{icon}</span>'
                f'<a href="{href}">{name}</a></td>'
                f'<td class="size">{size_str}</td>'
                f'<td class="mtime">{mtime}</td></tr>\n'
            )

        title = url_path if url_path != "/" else "根目录"
        upload_action = url_path  # POST 到当前目录

        html = DIR_HTML.format(
            title=title,
            breadcrumb=build_breadcrumb(url_path),
            rows=rows,
            message=msg,
            upload_action=upload_action,
        )
        self.send_html(html)

    def _serve_file(self, fspath: str):
        filename = os.path.basename(fspath)
        stat = os.stat(fspath)
        size = stat.st_size

        # 编码文件名（RFC 5987）
        try:
            filename.encode("ascii")
            cd = f'attachment; filename="{filename}"'
        except UnicodeEncodeError:
            encoded = urllib.parse.quote(filename)
            cd = f"attachment; filename*=UTF-8''{encoded}"

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", cd)
        self.send_header("Content-Length", str(size))
        self.end_headers()

        with open(fspath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)

    # ── POST ────────────────────────────────────────────────────────────────

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        url_path = parsed.path

        # 登录处理
        if url_path == "/login":
            self._handle_login()
            return

        # 需要认证但未认证
        if not self.is_authed():
            if self.headers.get("Authorization"):
                self._require_basic_auth()
                return
            self.redirect("/login")
            return

        # 文件上传
        self._handle_upload(url_path)

    def _handle_login(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode(errors="replace")
        params = urllib.parse.parse_qs(body)
        password = params.get("password", [""])[0]
        next_url = params.get("next", ["/"])[0] or "/"

        if sha256(password) == PASSWORD_HASH:
            token = make_session_token()
            self.send_response(302)
            self.send_header("Set-Cookie",
                             f"session={token}; Path=/; HttpOnly; SameSite=Lax")
            self.send_header("Location", next_url)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            error_html = '<p class="err">密码错误，请重试</p>'
            self.send_html(
                LOGIN_HTML.format(error=error_html, next=next_url),
                code=401,
            )

    def _handle_upload(self, url_path: str):
        content_type = self.headers.get("Content-Type", "")
        content_length = int(self.headers.get("Content-Length", 0))

        if "multipart/form-data" not in content_type:
            self.send_error(400, "Bad Request")
            return

        fspath = safe_path(CFG.dir, url_path)
        if fspath is None or not os.path.isdir(fspath):
            self.send_error(403, "Forbidden")
            return

        try:
            _, files = parse_multipart(self.rfile, content_type, content_length)
        except Exception as e:
            self.redirect(url_path + f"?err={urllib.parse.quote(str(e))}")
            return

        if not files:
            self.redirect(url_path + "?err=没有收到文件")
            return

        uploaded = []
        for filename, data in files:
            if not filename:
                continue
            # 安全：剥离路径，只保留文件名
            safe_name = os.path.basename(filename)
            if not safe_name:
                continue
            dest = os.path.join(fspath, safe_name)
            try:
                with open(dest, "wb") as f:
                    f.write(data)
                uploaded.append(safe_name)
            except OSError as e:
                self.redirect(url_path + f"?err={urllib.parse.quote(str(e))}")
                return

        ok_param = "&".join(f"ok={urllib.parse.quote(n)}" for n in uploaded)
        self.redirect(url_path + "?" + ok_param)


# ──────────────────────────────────────────────────────────────────────────────
# 入口
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="轻量级 HTTP 文件服务器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python httpfs.py                          # 在当前目录启动，无密码
  python httpfs.py -p 9000 -d /data         # 指定端口和目录
  python httpfs.py -P secret                # 设置访问密码
  python httpfs.py -P secret -w 127.0.0.1  # 密码+白名单免密
  python httpfs.py -w 192.168.1.0/24       # 内网免密，外网无密码也可（不推荐）
""",
    )
    parser.add_argument("-p", "--port", type=int, default=8080,
                        help="监听端口（默认 8080）")
    parser.add_argument("-d", "--dir", default=".",
                        help="服务目录（默认当前目录）")
    parser.add_argument("-P", "--password", default=None,
                        help="访问密码（不设则无需密码）")
    parser.add_argument("-w", "--whitelist", default=None,
                        help="白名单 IP/CIDR，逗号分隔（如 127.0.0.1,192.168.1.0/24）")
    parser.add_argument("-b", "--bind", default="0.0.0.0",
                        help="绑定地址（默认 0.0.0.0）")
    return parser.parse_args()


def main():
    global CFG, PASSWORD_HASH, WHITELIST

    CFG = parse_args()

    # 解析目录
    CFG.dir = os.path.realpath(CFG.dir)
    if not os.path.isdir(CFG.dir):
        print(f"错误：目录不存在：{CFG.dir}", file=sys.stderr)
        sys.exit(1)

    # 密码哈希
    if CFG.password:
        PASSWORD_HASH = sha256(CFG.password)

    # 白名单解析
    if CFG.whitelist:
        for item in CFG.whitelist.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                # 单 IP 也当作网络处理
                net = ipaddress.ip_network(item, strict=False)
                WHITELIST.append(net)
            except ValueError:
                print(f"警告：无效的白名单条目：{item}", file=sys.stderr)

    server = HTTPServer((CFG.bind, CFG.port), FileServerHandler)

    print(f"HTTP 文件服务器启动")
    print(f"  地址：http://{CFG.bind}:{CFG.port}")
    print(f"  目录：{CFG.dir}")
    print(f"  密码：{'已设置' if PASSWORD_HASH else '无'}")
    if WHITELIST:
        print(f"  白名单：{[str(n) for n in WHITELIST]}")
    print("按 Ctrl+C 停止服务\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务已停止")
        server.server_close()


if __name__ == "__main__":
    main()
