#!/usr/bin/env python3
"""Buffer-ownership stress test.

Hammers the proxy with a mix of clients that misbehave at random points:
abort mid-head, abort mid-body upload, abort mid-response download, read
slowly, pipeline, send garbage. Meanwhile well-behaved clients verify that
every response they get is byte-exact. Run against a Debug or ReleaseSafe
build so the proxy's ownership assertions are live.

usage: stress.py HOST:PORT SECONDS [--tls]
"""
import hashlib, os, random, socket, ssl, sys, threading, time

host, port = sys.argv[1].rsplit(':', 1)
port = int(port)
duration = float(sys.argv[2]) if len(sys.argv) > 2 else 20
use_tls = '--tls' in sys.argv
tls_ctx = ssl.create_default_context()
tls_ctx.check_hostname = False
tls_ctx.verify_mode = ssl.CERT_NONE
deadline = time.time() + duration
BIG_MD5 = hashlib.md5(open('/srv/www/big.bin', 'rb').read()).hexdigest()
stats = {'ok': 0, 'bad': 0, 'aborted': 0, 'errors': 0}
lock = threading.Lock()

def bump(k):
    with lock: stats[k] += 1

def conn():
    s = socket.create_connection((host, port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if use_tls:
        s = tls_ctx.wrap_socket(s, server_hostname='a.test')
    return s

def read_response(f):
    status = f.readline()
    if not status: raise EOFError
    hdrs = {}
    while True:
        l = f.readline()
        if l in (b'\r\n', b''): break
        k, v = l.split(b':', 1); hdrs[k.strip().lower()] = v.strip()
    if b'content-length' in hdrs:
        body = f.read(int(hdrs[b'content-length']))
    elif hdrs.get(b'transfer-encoding') == b'chunked':
        body = b''
        while True:
            n = int(f.readline().split(b';')[0], 16)
            if n == 0:
                while f.readline() not in (b'\r\n', b''): pass
                break
            body += f.read(n); f.readline()
    else:
        body = f.read()
    return status, hdrs, body

def good_big():
    s = conn(); f = s.makefile('rb')
    s.sendall(b'GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n')
    st, h, body = read_response(f)
    bump('ok' if hashlib.md5(body).hexdigest() == BIG_MD5 else 'bad')
    s.close()

def good_echo_upload():
    s = conn(); f = s.makefile('rb')
    payload = os.urandom(random.randint(1, 300_000))
    s.sendall(b'POST /up HTTP/1.1\r\nHost: echo.local\r\nContent-Length: %d\r\n\r\n' % len(payload) + payload)
    st, h, body = read_response(f)
    bump('ok' if body.endswith(b'BODY:' + payload) else 'bad')
    s.close()

def good_pipeline():
    s = conn(); f = s.makefile('rb')
    n = random.randint(2, 20)
    s.sendall(b''.join(b'GET /p%d HTTP/1.1\r\nHost: echo.local\r\n\r\n' % i for i in range(n)))
    for i in range(n):
        st, h, body = read_response(f)
        if not body.startswith(b'GET /p%d ' % i): bump('bad'); s.close(); return
    bump('ok'); s.close()

def abort_mid_download():
    s = conn()
    s.sendall(b'GET /huge.bin HTTP/1.1\r\nHost: x\r\n\r\n')
    s.recv(random.randint(1, 2_000_000))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')  # RST
    s.close(); bump('aborted')

def abort_mid_upload():
    s = conn()
    s.sendall(b'POST /up HTTP/1.1\r\nHost: echo.local\r\nContent-Length: 1000000\r\n\r\n' + os.urandom(random.randint(0, 500_000)))
    s.close(); bump('aborted')

def abort_mid_head():
    s = conn()
    s.sendall(b'GET /something HTTP/1.1\r\nHost: x\r\nX-Long: ' + b'a' * random.randint(0, 20000))
    s.close(); bump('aborted')

def slow_reader():
    s = conn()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.sendall(b'GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n')
    got = 0
    while got < 300_000:
        d = s.recv(4096)
        if not d: break
        got += len(d); time.sleep(0.001)
    s.close(); bump('aborted')

def abort_mid_handshake():
    s = socket.create_connection((host, port), timeout=10)
    if use_tls:
        s.sendall(b'\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03' + os.urandom(random.randint(0, 200)))
    s.close(); bump('aborted')

def garbage():
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(os.urandom(random.randint(1, 5000)))
    try: s.recv(4096)
    except Exception: pass
    s.close(); bump('aborted')

def chunked_upload_bad():
    s = conn()
    s.sendall(b'POST /up HTTP/1.1\r\nHost: echo.local\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\nZZ\r\n')
    try: s.recv(4096)
    except Exception: pass
    s.close(); bump('aborted')

actions = [good_big, good_echo_upload, good_pipeline, abort_mid_download, abort_mid_upload,
           abort_mid_head, slow_reader, garbage, chunked_upload_bad, abort_mid_handshake]

def run():
    while time.time() < deadline:
        try: random.choice(actions)()
        except Exception: bump('errors')

threads = [threading.Thread(target=run) for _ in range(24)]
for t in threads: t.start()
for t in threads: t.join()
print(stats)
sys.exit(1 if stats['bad'] else 0)
