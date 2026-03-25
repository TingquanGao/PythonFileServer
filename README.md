# httpfs.py

轻量级 HTTP 文件服务器，单文件、零第三方依赖，方便在多台机器间通过浏览器上传/下载文件。

## 特性

- **零依赖**：仅使用 Python 3.10+ 标准库
- **目录浏览**：文件列表显示大小、修改时间，支持面包屑导航
- **文件上传**：支持多文件、拖拽上传
- **文件下载**：流式传输，支持大文件
- **密码保护**：浏览器走 Session Cookie 认证（有效期 24 小时），wget/curl 走 HTTP Basic Auth
- **IP 白名单**：支持单 IP 和 CIDR 网段，白名单内免密访问
- **路径安全**：防止路径遍历攻击
- **中文文件名**：正确处理 Content-Disposition 编码

## 用法

```bash
python httpfs.py [OPTIONS]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-p, --port` | `8080` | 监听端口 |
| `-d, --dir` | `.`（当前目录）| 服务目录 |
| `-P, --password` | 无 | 访问密码（不设则无需密码） |
| `-w, --whitelist` | 无 | 白名单 IP/CIDR，逗号分隔 |
| `-b, --bind` | `0.0.0.0` | 绑定地址 |

## 示例

```bash
# 最简启动：当前目录，无密码，8080 端口
python httpfs.py

# 指定端口和服务目录
python httpfs.py -p 9000 -d /data

# 设置访问密码
python httpfs.py -P mysecret

# 密码保护 + 本机免密
python httpfs.py -P mysecret -w 127.0.0.1

# 内网网段免密，外网需要密码
python httpfs.py -P mysecret -w 192.168.1.0/24,10.0.0.5

# 仅监听本机
python httpfs.py -b 127.0.0.1
```

## 命令行客户端访问（设置了密码时）

**wget**

```bash
wget --user=任意用户名 --password=mysecret http://HOST:PORT/文件名
```

**curl**

```bash
curl -u :mysecret http://HOST:PORT/文件名 -O
```

> 用户名字段不校验，填任意值即可；密码必须与 `-P` 参数一致。



- 密码以 SHA-256 哈希形式存储在内存中，不明文保留
- Session Token 使用 `secrets.token_hex(32)` 生成
- 所有请求路径经 `os.path.realpath` 规范化，防止 `../` 路径遍历
- 建议在局域网或受信任网络环境中使用，生产环境请在反向代理后运行

## 要求

- Python 3.10+
