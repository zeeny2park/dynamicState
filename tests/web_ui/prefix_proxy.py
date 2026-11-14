"""A tiny reverse proxy that imitates the demo's nginx: it serves the app under ``/dynamicstate/`` (stripping the prefix,
like ``proxy_pass http://127.0.0.1:8081/;``) and, unless ``buffering=False``, BUFFERS every response completely before
sending it (nginx without ``proxy_buffering off``), so a Server-Sent Events stream reaches the browser only when the
server closes it.  Used by tests/test_web_ui_prefix.py (no browser) and tests/web_ui/e2e_real.py (browser).

In-process (a thread); ``with PrefixProxy(upstream_port) as proxy: proxy.base`` -> ``http://127.0.0.1:<port>/dynamicstate/``.
"""
import http.client
import http.server
import socketserver
import threading
import time
from typing import Dict, List

PREFIX = "/dynamicstate/"
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
        "transfer-encoding", "upgrade", "content-length"}


class PrefixProxy:
    def __init__(self, upstream_port: int, buffering: bool = True, timeout: float = 120.0, hold_events_s: float = 0.0):
        self.upstream_port = upstream_port
        self.buffering = buffering
        self.hold_events_s = hold_events_s   # an event stream is also held this long (a proxy whose buffer fills slowly)
        self.timeout = timeout
        self.log: List[Dict[str, object]] = []
        proxy = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _forward(self):
                if not (self.path == PREFIX[:-1] or self.path.startswith(PREFIX)):
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                path = "/" + self.path[len(PREFIX):] if self.path.startswith(PREFIX) else "/"
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else None
                headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP and k.lower() != "host"}
                headers["Host"] = f"127.0.0.1:{proxy.upstream_port}"
                if headers.get("Origin") == f"http://127.0.0.1:{proxy.port}":
                    del headers["Origin"]       # as the demo's nginx map does: its own public origin is blanked
                conn = http.client.HTTPConnection("127.0.0.1", proxy.upstream_port, timeout=proxy.timeout)
                try:
                    conn.request(self.command, path, body=body, headers=headers)
                    resp = conn.getresponse()
                    if proxy.buffering:
                        if proxy.hold_events_s and "/events" in path:
                            time.sleep(proxy.hold_events_s)
                        data = resp.read()                      # the whole response first, as a buffering proxy does
                        proxy.log.append({"method": self.command, "path": path, "status": resp.status, "bytes": len(data)})
                        self.send_response(resp.status)
                        for k, v in resp.getheaders():
                            if k.lower() not in _HOP:
                                self.send_header(k, v)
                        self.send_header("Content-Length", str(len(data)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        if self.command != "HEAD":
                            self.wfile.write(data)
                    else:
                        proxy.log.append({"method": self.command, "path": path, "status": resp.status, "bytes": None})
                        self.send_response(resp.status)
                        for k, v in resp.getheaders():
                            if k.lower() not in _HOP:
                                self.send_header(k, v)
                        self.send_header("Connection", "close")
                        self.end_headers()
                        while True:
                            chunk = resp.read1(65536) if hasattr(resp, "read1") else resp.read(65536)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
                    pass
                finally:
                    conn.close()
                    self.close_connection = True

            do_GET = do_POST = do_HEAD = _forward

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}{PREFIX}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    def __enter__(self) -> "PrefixProxy":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
