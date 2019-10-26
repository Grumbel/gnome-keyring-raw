# gnome-keyring-raw - Inspect raw Gnome keyring files
# Copyright (C) 2019 Ingo Ruhnke <grumbel@gmail.com>
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import struct

from typing import Optional


class BinaryReader:

    def __init__(self, fin) -> None:
        self._fin = fin

    def expect_bytes(self, data: bytes) -> None:
        result = self.read_bytes(len(data))
        if result != data:
            pos = self._fin.tell() - len(result)
            raise Exception(f"invalid bytes at position position {pos:02x}, expected {data}")

    def read_bytes(self, size: int) -> bytes:
        data = self._fin.read(size)
        if len(data) != size:
            pos = self._fin.tell() - len(data)
            raise Exception(f"not enough bytes read at position {pos:02x}, expected {size}")
        return data

    def read_guint32(self) -> bytes:
        data = self.read_bytes(4)
        return struct.unpack(">I", data)[0]

    def read_guint32s(self, size: int):
        return [self.read_guint32() for _ in range(size)]

    def read_time_t(self) -> bytes:
        data = self.read_bytes(8)
        return struct.unpack(">Q", data)[0]

    def read_string(self) -> Optional[str]:
        """strings: uint32 + bytes, no padding, NULL is encoded as 0xffffffff"""
        length = self.read_guint32()
        if length == 0xffffffff:
            return None
        else:
            data = self.read_bytes(length)
            return data.decode('utf-8')


# EOF #
