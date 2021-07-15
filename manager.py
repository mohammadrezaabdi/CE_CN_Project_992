import socket
import logging
import constants as consts
from server import Server

import log

log.init()

nodes_port = []

logger = logging.getLogger("manager")


def get_parent(num):
    return (num - 1) // 2


def get_left_child(num):
    return num * 2 + 1


def get_right_child(num):
    return num * 2 + 2


def handle_client(conn: socket.socket):
    logger.debug("handling new client")
    with conn:
        try:
            data = conn.recv(consts.BUFFER_SIZE).decode("ascii")
            logger.debug(f"received message is:{data}")
            if not data:
                return

            [(id, port)] = consts.CONNECT_REQUEST_REGEX.findall(data)
            nodes_port.append((id, port))
            if len(nodes_port) == 1:
                parent_id, parent_port = -1, -1
            else:
                parent_id, parent_port = nodes_port[get_parent(len(nodes_port) - 1)]
            response = consts.CONNECT_ACCEPT.format(
                id_parent=parent_id, port_parent=parent_port
            )
            logger.debug(f"parent_id={parent_id}, parent_port={parent_port}")
            conn.sendall(response.encode("ascii"))

        except Exception as e:
            raise Exception(e)


def main():
    manager = Server(consts.MANAGER_IP, consts.MANAGER_PORT, handle_client, logger)
    manager.listen()


if __name__ == "__main__":
    main()
