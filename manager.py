import socket
import logging
import constants
from server import Server

import log

log.init()

nodes_port = []

logger = logging.getLogger('manager')


def get_parent(num):
    return (num - 1) // 2


def get_left_child(num):
    return num * 2 + 1


def get_right_child(num):
    return num * 2 + 2


ip = "127.0.0.1"
port = "8080"


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
            parent_id, parent_port = nodes_port[get_parent(len(nodes_port) - 1)]
            response = constants.CONNECT_ACCEPT.format(id_parent=parent_id, port_parent=parent_port)
            conn.sendall(response)

        except Exception as e:
            raise Exception(e)


def main():
    manager = Server(ip, port,handle_client,logger)
    manager.listen()


if __name__ == '__main__':
    main()
