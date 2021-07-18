import concurrent.futures
import logging
import socket
from typing import Callable, Any


class Server:
    def __init__(self, ip: str, port: str, handler: Callable[[socket.socket], Any], logger: logging.Logger):
        self.ip = ip
        self.port = int(port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger = logger
        self.handler = handler

    def listen(self):
        self.logger.info("server process started")
        self.logger.info(f"trying to start listening at {self.ip}:{self.port}")
        with self.sock as s:
            s.bind((self.ip, self.port))
            self.receive_clients()

    def receive_clients(self):
        self.sock.listen()
        self.logger.info("started listening...")
        with concurrent.futures.ThreadPoolExecutor() as thread_pool:
            while True:
                conn, addr = self.sock.accept()
                self.logger.info(f"accepted new client with address {addr}")
                thread_pool.submit(self.handler, conn)
