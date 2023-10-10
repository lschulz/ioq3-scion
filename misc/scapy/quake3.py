# Copyright (C) 2023 Lars-Christian Schulz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
Scapy protocol definition for ioQuake3
"""

from typing import Iterable, Optional, Tuple

from scapy.fields import ConditionalField, Field, LEIntField, LEShortField, StrField
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_bottom_up, bind_layers
from scapy.volatile import RandChoice


class StrEnumField(StrField):
    __slots__ = ["enum"]

    def __init__(self, name, default, enum: Iterable[bytes]):
        Field.__init__(self, name, default)
        self.enum = sorted(list(enum), key=lambda x: len(x), reverse=True)

    def getfield(self, pkt: Optional[Packet], s: bytes) -> Tuple[bytes, bytes]:
        for choice in self.enum:
            if s.startswith(choice):
                return s[len(choice):], s[:len(choice)]
        else:
            return "", s

    def randval(self):
        return RandChoice(*self.enum)


class IoQuake3(Packet):

    name = "ioQuake3"

    connectionless_commands = {
        # Server to Master
        b"heartbeat": "S2M",
        # Client to Master
        b"getservers": "C2M",
        b"getserversExt": "C2M",
        # Master to Client
        b"getserversResponse": "M2C",
        b"getserversExtResponse": "M2C",
        # Client to Server
        b"getstatus": "C2S",
        b"getinfo": "C2S",
        b"getchallenge": "C2S",
        b"connect": "C2S",
        b"ipAuthorize": "C2S",
        b"rcon": "C2S",
        b"disconnet": "C2S",
        # Server to Client
        b"challengeResponse": "S2C",
        b"connectResponse": "S2C",
        b"infoResponse": "S2C",
        b"statusResponse": "S2C",
        b"echo": "S2C",
        b"keyAuthorize": "S2C",
        b"motd": "S2C",
        b"print": "S2C"
    }

    FRAGMENT_BIT = 1 << 31
    MASTER_PORT = 27950
    SERVER_PORT = 27960

    fields_desc = [
        LEIntField("seq", default=0xffffffff),
        ConditionalField(
            StrEnumField("cmd", default=b"getstatus", enum=connectionless_commands.keys()),
            lambda pkt: pkt.seq == 0xffffffff
        ),
        ConditionalField(
            LEShortField("qport", default=0),
            lambda pkt: pkt.seq != 0xffffffff and pkt.guess_direction() == "C2S"
        ),
        ConditionalField(
            LEIntField("checksum", default=0),
            lambda pkt: pkt.seq != 0xffffffff
        ),
        ConditionalField(
            LEShortField("frag_start", default=0),
            lambda pkt: pkt.is_fragment()
        ),
        ConditionalField(
            LEShortField("frag_len", default=0),
            lambda pkt: pkt.is_fragment()
        )
    ]

    def is_fragment(self) -> bool:
        """Check whether the packet belongs to a fragmented message"""
        return self.seq != 0xffffffff and (self.seq & self.FRAGMENT_BIT) != 0

    def guess_direction(self) -> str:
        """Guess message direction"""
        has_udp = isinstance(self.underlayer, UDP)
        if self.seq == 0xffffffff:
            if self.cmd == b"getinfo":
                if has_udp and self.underlayer.sport == self.MASTER_PORT:
                    return "M2S"
                else:
                    return "C2S"
            elif self.cmd == b"infoResponse":
                if has_udp and self.underlayer.dport == self.MASTER_PORT:
                    return "S2M"
                else:
                    return "C2M"
            else:
                return self.connectionless_commands.get(self.cmd, "unknown")
        elif has_udp:
            if self.underlayer.dport == self.SERVER_PORT:
                return "C2S"
            else:
                return "S2C"
        else:
            return "unknown"

    def mysummary(self) -> str:
        if self.seq != None and self.seq == 0xffffffff:
            return f"{self.name} {self.guess_direction()} {self.cmd.decode('ascii')}"
        else:
            summary = f"{self.name} {self.guess_direction()} seq={self.seq & ~self.FRAGMENT_BIT}"
            if self.is_fragment():
                summary += f" frag_start={self.frag_len} frag_len={self.frag_start}"
            return summary


bind_layers(UDP, IoQuake3, dport=IoQuake3.SERVER_PORT)
bind_bottom_up(UDP, IoQuake3, sport=IoQuake3.SERVER_PORT)
bind_bottom_up(UDP, IoQuake3, sport=IoQuake3.MASTER_PORT)
bind_bottom_up(UDP, IoQuake3, dport=IoQuake3.MASTER_PORT)
