#!/usr/bin/env python3
"""Terminate TLS and forward the bytes to the plain OP.

The OIDF suite requires https discovery URLs. The OP itself stays on HTTP.
"""

import socket
import ssl
import sys
import threading


def pipe(source: socket.socket, dest: socket.socket) -> None:
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            dest.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (source, dest):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(conn: socket.socket, target_host: str, target_port: int) -> None:
    try:
        upstream = socket.create_connection((target_host, target_port))
    except OSError:
        conn.close()
        return
    left = threading.Thread(target=pipe, args=(conn, upstream), daemon=True)
    right = threading.Thread(target=pipe, args=(upstream, conn), daemon=True)
    left.start()
    right.start()
    left.join()
    right.join()
    conn.close()
    upstream.close()


def main() -> None:
    listen_host, listen_port, target_host, target_port, cert, key = sys.argv[1:7]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, int(listen_port)))
    server.listen(50)
    tls = context.wrap_socket(server, server_side=True)
    while True:
        try:
            conn, _ = tls.accept()
        except ssl.SSLError:
            continue
        threading.Thread(
            target=handle,
            args=(conn, target_host, int(target_port)),
            daemon=True,
        ).start()


if __name__ == "__main__":
    main()
