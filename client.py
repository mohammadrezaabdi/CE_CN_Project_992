import log
import ast
import threading
import constants as consts
from packet import *
from node import Node

log.init()


def network_init(id, port) -> Packet:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((consts.DEFAULT_IP, consts.MANAGER_PORT))

        request = consts.CONNECT_REQUEST.format(id=id, port=port)
        p = Packet(
            p_type=PacketType.CONNECTION_REQUEST.value,
            src_id=id,
            dest_id=-1,
            data=request,
        )
        packet_dict = str(p.__dict__)
        s.sendall(packet_dict.encode("ascii"))

        response = s.recv(consts.BUFFER_SIZE).decode("ascii")
        response = ast.literal_eval(response)
        return Packet(**response)


def family_meeting(my_id: int, my_port: int, pid: int, pport: int):
    if pid == consts.ROOT_PARENT_ID:
        return
    p = Packet(PacketType.CONNECTION_REQUEST.value, my_id, pid, str(my_port))
    p.send(consts.DEFAULT_IP, pport)


def main():
    cmd = input()
    try:
        [(id, port)] = consts.CONNECT_REGEX.findall(cmd)
    except Exception as e:
        [(id)] = consts.CONNECT_PORT_LESS_REGEX.findall(cmd)
        port = 10000 + int(id) * 10

    p = network_init(id, port)
    [(pid, pport)] = consts.CONNECT_ACCEPT_REGEX.findall(p.data)
    node = Node(int(id), int(port))
    if int(pid) == -1 and int(pport) == -1:
        node.parent = (consts.ROOT_PARENT_ID, consts.ROOT_PARENT_PORT)
    else:
        node.set_parent(pid, pport)

    family_meeting(node.id, node.port, int(node.parent[0]), int(node.parent[1]))

    t = threading.Thread(target=node.handle_user_commands)
    t.start()

    node.server_socket.listen()


if __name__ == "__main__":
    main()
