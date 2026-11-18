"""Forwards 127.0.0.1:1514 and 127.0.0.1:1515 on the Mac to the test's own Wazuh manager, which runs in the
`manager` job of the same workflow and is reachable through a bore.pub tunnel. The agent's settings keep
pointing at 127.0.0.1, so NixGuard's install script runs unchanged.

usage: forward.py HOST EVENTS_PORT ENROLL_PORT"""
import socket
import sys
import threading

host, events_port, enroll_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def serve(local_port, remote_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", local_port))
    server.listen(16)
    print(f"127.0.0.1:{local_port} -> {host}:{remote_port}", flush=True)
    while True:
        client, _ = server.accept()
        try:
            upstream = socket.create_connection((host, remote_port), timeout=20)
            upstream.settimeout(None)
        except OSError as exc:
            print(f"{local_port}: upstream failed: {exc}", flush=True)
            client.close()
            continue
        threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()


threading.Thread(target=serve, args=(1515, enroll_port), daemon=True).start()
serve(1514, events_port)
