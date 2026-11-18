"""A stand-in Wazuh manager for the CPU test, so nothing leaves the runner.

- Port 1515 (TLS): answers the install script's enrollment request with a random key, so NixGuard's
  install script runs unmodified.
- Port 1514: accepts the agent's connection and discards what it receives.
"""
import os
import re
import socket
import ssl
import subprocess
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "fake.pem")
KEY = os.path.join(HERE, "fake.key")


def drain(conn):
    with conn:
        while conn.recv(65536):
            pass


def events():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 1514))
    server.listen(16)
    print("listening on 127.0.0.1:1514", flush=True)
    while True:
        conn, addr = server.accept()
        print("1514 connection from", addr, flush=True)
        threading.Thread(target=drain, args=(conn,), daemon=True).start()


def enrollment():
    if not os.path.exists(CERT):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=fake-manager", "-keyout", KEY, "-out", CERT],
                       check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 1515))
    server.listen(4)
    print("listening on 127.0.0.1:1515", flush=True)
    while True:
        raw, addr = server.accept()
        try:
            with ctx.wrap_socket(raw, server_side=True) as conn:
                request = conn.recv(4096).decode(errors="replace")
                print("1515 request:", request.strip()[:200], flush=True)
                match = re.search(r"A:'([^']+)'", request)
                name = match.group(1) if match else "ci-cpu-test"
                conn.sendall(f"OSSEC K:'001 {name} any {os.urandom(32).hex()}'\n".encode())
        except Exception as exc:  # keep serving
            print("1515 error:", exc, flush=True)


threading.Thread(target=enrollment, daemon=True).start()
events()
