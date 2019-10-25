#!/usr/bin/env python3

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


import argparse
import getpass
import sys

from typing import List

from gnome_keyring_raw.parser import Parser
from gnome_keyring_raw.keyring import Keyring


def keyring_pretty_print(keyring: Keyring) -> None:
    print(f"   name: {keyring.name}")
    print(f"version: {keyring.version[0]}.{keyring.version[1]}")
    print(f"  ctime: {keyring.ctime}")
    print(f"  mtime: {keyring.mtime}")
    for item in keyring.items:
        print(f"        name: {item.name}")
        print(f"      secret: {item.secret}")
        print(f"  attributes:")
        for attr in item.attrs:
            print(f"             name: {attr.name}")
            print(f"             hash: {attr.hash}")
            print(f"            value: {attr.value}")
            print()
        print()


def parse_args(args: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect raw Gnome keyring files")
    parser.add_argument("-p", "--password", metavar="STRING", default=None,
                        help="Password used to decrypt the file(s)")
    parser.add_argument("FILE", nargs="+", help="Gnome keyring file to read")
    return parser.parse_args(args)


def main(argv: List[str]):
    args = parse_args(argv[1:])

    if args.password is None:
        password = getpass.getpass().encode("utf-8")
    else:
        password = args.password.encode("utf-8")

    for filename in args.FILE:
        with open(filename, "rb") as fin:
            parser = Parser(fin, password)
            keyring = parser.parse()

            keyring_pretty_print(keyring)


def main_entrypoint():
    main(sys.argv)


if __name__ == "__main__":
    main_entrypoint()


# EOF #
