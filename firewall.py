from dataclasses import dataclass
from enum import Enum
import constants as consts
from packet import PacketType


class FWAction(Enum):
    ACCEPT = 0
    DROP = 1


@dataclass
class FWRule:
    def __init__(self, src=consts.SEND_ALL, dst=consts.SEND_ALL, p_type=PacketType.ALL,
                 action: FWAction = FWAction.DROP , direction="" , is_chat = False):
        self.src = src
        self.dst = dst
        self.p_type = p_type
        self.action = action
        self.direction = direction
