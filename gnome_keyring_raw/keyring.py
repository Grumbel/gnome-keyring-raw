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
        pass


class Attribute:

    def __init__(self) -> None:
        self.name: str
        self.value: Union[int, str]


class Item:

    def __init__(self) -> None:
        self.attrs: List[Attribute] = []

    def getattr(self, name: str) -> Optional[Attribute]:
        for attr in self.attrs:
            if attr.name == name:
                return attr
        return None


class Keyring:

    def __init__(self) -> None:
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
                    ]
                }
                for item in self.items
            ]
        }


# EOF #
