import socket
import logging
import constants as consts
from server import Server
from packet import Packet, PacketType
import log
import ast

log.init()

nodes_port = []

logger = logging.getLogger("manager")


def get_parent(num):
    return (num - 1) // 2


def handle_client(conn: socket.socket):
    logger.debug("handling new client")
    with conn:
        try:
            data = conn.recv(consts.BUFFER_SIZE).decode("ascii")
            if not data:
                return

            # Packets are sent as dictionary string. we convert them back to python strings using ast.literal_eval.
            data = ast.literal_eval(data)
            logger.debug(f"received message is:{data}")
            packet = Packet(**data)
            if packet.p_type == PacketType.CONNECTION_REQUEST:
                [(id, port)] = consts.CONNECT_REQUEST_REGEX.findall(packet.data)
                parent_id, parent_port = -1, -1
                if nodes_port:
                    parent_id, parent_port = nodes_port[get_parent(len(nodes_port))]

                logger.debug(f"parent_id = {parent_id}, parent_port = {parent_port}")

                nodes_port.append((id, port))
                response = consts.CONNECT_ACCEPT.format(
                    id_parent=parent_id, port_parent=parent_port
                )
                send_packet = Packet(
                    p_type=PacketType.CONNECTION_RESPONSE.value,
                    src_id=-1,
                    dest_id=id,
                    data=response,
                )
                conn.sendall(str(send_packet.__dict__).encode("ascii"))

        except Exception as e:
            raise e


def main():
    manager = Server(consts.MANAGER_IP, consts.MANAGER_PORT, handle_client, logger)
    manager.listen()


if __name__ == "__main__":
    main()
