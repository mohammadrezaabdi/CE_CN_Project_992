from enum import IntEnum
import client
import constants as consts
from packet import Packet, PacketType


class ChatState(IntEnum):
    INACTIVE = 0
    PENDING = 1
    ACTIVE = 2
    DISABLE = 3


class Chat:
    def __init__(self):
        self.state: ChatState = ChatState.INACTIVE
        self.self: tuple[int, str] = tuple()
        self.owner: tuple[int, str] = tuple()
        self.chat_list: dict[int, str] = {}
        self.port_list: dict[int, int] = {}

    def set_chat(self, state: ChatState, yourself: tuple[int, str], owner: tuple[int, str], chat_list: dict[int, str],
                 port_list: dict[int, int]):
        self.state = state
        self.self = yourself
        self.owner = owner
        self.chat_list = chat_list
        self.port_list = port_list
        self.chat_list[yourself[0]] = yourself[1]
        self.chat_list[owner[0]] = owner[1]

    def init_chat(self, owner_name: str, id_port_list: list[tuple[int, int]]):
        self.set_chat(ChatState.ACTIVE, (id_port_list[0][0], owner_name), (id_port_list[0][0], owner_name),
                      {id_port[0]: "" for id_port in id_port_list}, dict(id_port_list))
        self.send_to_chat_list(consts.REQ_FOR_CHAT.format(name=owner_name, ids=(
            ", ".join(map(str, [elem[0] for elem in id_port_list]))).strip()))

    def start_chat(self, owner_name: str, your_id: int, id_port_list: list[tuple[int, int]]):
        self.set_chat(ChatState.PENDING, (your_id, ""), (id_port_list[0][0], owner_name),
                      {id_port[0]: "" for id_port in id_port_list}, dict(id_port_list))

        while True:
            print(consts.ASK_JOIN_CHAT.format(chat_name=owner_name, id=id_port_list[0][0]))
            client.cmd_sema.acquire()
            is_join = client.chat_input
            if consts.YES_REGEX.match(is_join):
                print(consts.CHOOSE_NAME_MSG)
                client.cmd_sema.acquire()
                name = client.chat_input
                self.self = (your_id, name)
                self.chat_list[your_id] = name
                self.state = ChatState.ACTIVE
                self.send_to_chat_list(consts.SET_NAME.format(id=your_id, chat_name=name))
                return
            elif consts.NO_REGEX.match(is_join):
                self.clear_chat()
                return

    def send_to_chat_list(self, data: str, is_broadcast: bool = True):
        if self.state == ChatState.INACTIVE:
            return
        for id, name in self.chat_list.items():
            if int(id) == self.self[0] or (not is_broadcast and name == ""):
                continue
            p = Packet(PacketType.MESSAGE.value, self.self[0], id, data)
            client.send(consts.DEFAULT_IP, self.port_list[id], p)

    def clear_chat(self):
        self.state = ChatState.INACTIVE
        self.owner = tuple()
        self.self = tuple()
        self.chat_list.clear()
        self.port_list.clear()

    def is_in_your_chat(self, p: Packet, when_start: bool = False):
        return int(p.src_id) in self.chat_list.keys() and (when_start or self.chat_list[int(p.src_id)] != "")
