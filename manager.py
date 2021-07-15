import socket
import threading
import concurrent.futures
import socket
import logging
import constants

nodes_port = []
logger = logging.getLogger('manager')


class Server:
    def __init__(self, ip: str, port: str):
        self.ip = ip
        self.port = int(port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def listen(self):
        logger.info("server process started")
        logger.info(f"trying to start listening at {self.ip}:{self.port}")
        with self.sock as s:
            s.bind((self.ip, self.port))
            self.receive_clients()

    def receive_clients(self):
        self.sock.listen()
        logger.info("started listening...")
        with concurrent.futures.ThreadPoolExecutor() as thread_pool:
            while True:
                conn, addr = self.sock.accept()
                logger.info(f"accepted new client with address {addr}")
                thread_pool.submit(self.handle_client, conn)

    @staticmethod
    def handle_client(conn: socket.socket):
        logger.debug("handling new client")
        with conn:
            try:
                data = conn.recv(1024).decode("ascii")
                logger.debug(f"received message is:{data}")
                if not data:
                    return

                id, port = constants.CONNECT_REQUEST_REGEX.findall(data)
                nodes_port.append((id, port))
                parent_id, parent_port = get_parent(len(nodes_port) - 1)
                response = constants.CONNECT_ACCEPT.format(id_parent=parent_id, port_parent=parent_port)
                conn.sendall(response)

            except Exception as e:
                raise Exception(e)


def get_parent(num):
    return (num - 1) // 2


def get_left_child(num):
    return num * 2 + 1


def get_right_child(num):
    return num * 2 + 2


def main():
    pass


if __name__ == '__main__':
    main()
