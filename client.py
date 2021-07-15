import logging
import socket
import threading
import time

logger = logging.getLogger("client")


def send(ip: str, port: int, message: str):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        while True:
            try:
                s.connect((ip, port))
                logger.info("connected to server successfully!")
                s.sendall(message.encode("ascii"))
                break
            except:
                time.sleep(1)
                logger.exception("waiting for server...")
