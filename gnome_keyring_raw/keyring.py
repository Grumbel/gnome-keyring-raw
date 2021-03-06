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


from typing import List, Dict, Any, Optional, Union


class ACL:

    def __init__(self) -> None:
        self.types_allowed: int
        self.display_name: Optional[str]
        self.pathname: Optional[str]


class Attribute:

    def __init__(self) -> None:
        self.name: str
        self.value: Union[int, str]
        self.hash: Union[int, str]


class Item:

    def __init__(self) -> None:
        self.id: int
        self.type: int

        self.name: Optional[str]
        self.secret: Optional[str]

        self.ctime: int
        self.mtime: int

        self.attrs: List[Attribute] = []
        self.acls: List[ACL] = []

    def getattr(self, name: str) -> Optional[Attribute]:
        for attr in self.attrs:
            if attr.name == name:
                return attr
        return None


class Keyring:

    def __init__(self) -> None:
        self.version: bytes
        self.crypto_algo: int
        self.hash_algo: int

        self.name: Optional[str]
        self.ctime: int
        self.mtime: int

        self.flags: int
        self.lock_timeout: int
        self.hash_iterations: int
        self.salt: bytes

        self.items: List[Item] = []

    def serialize(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": list(self.version),
            "ctime": self.ctime,
            "mtime": self.mtime,
            "items": [
                {
                    "name": item.name,
                    "secret": item.secret,
                    "attributes": [
                        {
                            "name": attr.name,
                            "value": attr.value,
                            # "hash": attr.hash,
                        }
                        for attr in item.attrs
                    ],
                    "acls": [
                        {
                            "types_allowed": acl.types_allowed,
                            "display_name": acl.display_name,
                            "pathname": acl.pathname,
                        }
                        for acl in item.acls
                    ]
                }
                for item in self.items
            ]
        }


# EOF #
