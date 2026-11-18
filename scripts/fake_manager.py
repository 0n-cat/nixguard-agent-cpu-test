"""A stand-in Wazuh manager for the CPU test: accepts the agent's connection on 127.0.0.1:1514
and discards whatever it receives. It never answers, so the agent keeps running as it would
while its manager is unreachable, and nothing leaves the runner."""
import socket
import threading


def drain(conn):
    with conn:
        while conn.recv(65536):
            pass


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 1514))
server.listen(16)
print("listening on 127.0.0.1:1514", flush=True)
while True:
    conn, addr = server.accept()
    print("connection from", addr, flush=True)
    threading.Thread(target=drain, args=(conn,), daemon=True).start()
