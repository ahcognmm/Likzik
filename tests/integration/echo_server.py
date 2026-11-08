import socket, threading, sys, time
def handle(c):
    f = c.makefile('rb')
    try:
        while True:
            line = f.readline()
            if not line: return
            headers = {}
            raw = [line]
            while True:
                h = f.readline(); raw.append(h)
                if h in (b'\r\n', b''): break
                k, v = h.split(b':', 1); headers[k.strip().lower()] = v.strip()
            body = b''
            if b'content-length' in headers:
                body = f.read(int(headers[b'content-length']))
            elif headers.get(b'transfer-encoding') == b'chunked':
                while True:
                    sz = int(f.readline().split(b';')[0], 16)
                    if sz == 0:
                        while f.readline() not in (b'\r\n', b''): pass
                        break
                    body += f.read(sz); f.readline()
            resp = b''.join(raw) + b'BODY:' + body
            if line.startswith(b'GET /sleep'):
                time.sleep(1)
            if b' /reset' in line:
                c.close(); return
            if line.startswith(b'GET /chunked'):
                c.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n')
            elif line.startswith(b'GET /close'):
                c.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose-delimited body')
                c.close(); return
            else:
                c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n' % len(resp) + resp)
    except Exception as e:
        pass
    finally:
        c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', int(sys.argv[1]))); s.listen(128)
while True:
    c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
