from dataclasses import dataclass

import constants as consts
from firewall import FWRule, FWAction
from packet import Packet, PacketType


@dataclass
class IdRoute:
    def __init__(self, dest: int, next_hop: tuple[int, int], state: FWAction = FWAction.ACCEPT):
        self.dest = dest
        self.next_hop = next_hop
        self.state = state


class IdTable:
    def __init__(self, id: int):
        self.default_gateway: tuple[int, int] = tuple()  # default gateway is actully a gateway to parent.
        self.routing_table: list[IdRoute] = []
        self.known_hosts: set[int] = set()
        self.fw_rules: list[FWRule] = []
        self.id = id

    def get_next_hop(self, dest_id: int, src_id=consts.SEND_ALL):
        if dest_id not in self.known_hosts:
            if src_id != self.id:
                return self.default_gateway
            return consts.NEXT_HOP_NOT_FOUND
        results = [route for route in self.routing_table if route.dest == dest_id and route.state == FWAction.ACCEPT]
        if results:
            return results[0].next_hop
        return self.default_gateway

    def add_entry(self, dest_id: int, next_hop: tuple[int, int]):
        results = [route.next_hop for route in self.routing_table if route.dest == dest_id]
        if next_hop in results:
            # This exception should never happen. It is here just as a safety check.
            raise Exception("there is a loop")
        self.routing_table.append(IdRoute(dest_id, next_hop))
        self.known_hosts.add(dest_id)

    def set_state(self, dest_id: int, state: FWAction):
        for route in self.routing_table:
            if route.dest == dest_id:
                route.state = state

    def fw_allows(self, p: Packet) -> bool:
        src = p.src_id
        dst = p.dest_id
        p_type = p.p_type
        rules = []
        # the & are for handling * in rules
        for rule in self.fw_rules:
            if rule.direction == "FORWARD" and (
                    rule.src == self.id or (rule.src == consts.SEND_ALL and p.src_id == self.id)) or (
                    rule.dst == self.id or (rule.dst == consts.SEND_ALL and p.dest_id == self.id)):
                continue

            if (rule.src == consts.SEND_ALL or rule.src == src) and (
                    rule.dst == consts.SEND_ALL or rule.dst == dst) and (
                    rule.p_type == PacketType.ALL or rule.p_type == p_type):
                rules.append(rule)
        if rules:
            return (True, False)[rules[-1].action == FWAction.DROP]
        return True
