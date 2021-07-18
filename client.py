import logging
import socket
import threading
import time

from packet import *

logger = logging.getLogger("client")
cmd_sema = threading.Semaphore(0)
chat_input = ""


def send(ip: str, port: int, packet: Packet):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        while True:
            try:
                s.connect((ip, port))
                logger.info("connected to server successfully!")
                s.sendall(str(packet.__dict__).encode("ascii"))
                break
            except:
                time.sleep(1)
                logger.exception("waiting for server...")