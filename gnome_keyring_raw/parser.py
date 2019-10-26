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


import io

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5

from gnome_keyring_raw.binary_reader import BinaryReader
from gnome_keyring_raw.keyring import Keyring, Item, Attribute, ACL


def guint32_hash(x: int) -> int:
    # the file format documentation uses:
    # 0xdeadbeef ^ x ^ (x>>16 | x & 0xffff << 16)
    # but the code uses a different algorithm,
    # see compat_hash_value_as_uint32() in
    # gnome-keyring-3.34.0/pkcs11/secret-store/gkm-secret-fields.c:
    return 0x18273645 ^ x ^ (x << 16 | x >> 16)


class Parser:

    def __init__(self, fin, password):
        self._reader = BinaryReader(fin)
        self._password = password

    def parse(self) -> Keyring:
        r = self._reader

        r.expect_bytes(b"GnomeKeyring\n\r\0\n")

        keyring = Keyring()
        keyring.version = r.read_bytes(2)
        keyring.crypto_algo = r.read_bytes(1)[0]
        keyring.hash_algo = r.read_bytes(1)[0]

        if keyring.crypto_algo != 0:  # assume AES128
            raise Exception("unknown crypto algo")

        if keyring.hash_algo != 0:  # assume SHA256
            raise Exception("unknown hash algo")

        keyring.name = r.read_string_or_null()
        keyring.ctime = r.read_time_t()
        keyring.mtime = r.read_time_t()

        keyring.flags = r.read_guint32()
        keyring.lock_timeout = r.read_guint32()
        keyring.hash_iterations = r.read_guint32()
        keyring.salt = r.read_bytes(8)
        _ = r.read_guint32s(4)  # reserved

        num_items = r.read_guint32()
        for _ in range(num_items):
            item = Item()
            item.id = r.read_guint32()
            item.type = r.read_guint32()

            num_attributes = r.read_guint32()
            for _ in range(num_attributes):
                attribute = Attribute()
                attribute.name = r.read_string_or_null()
                value_type = r.read_guint32()
                if value_type == 0:
                    attribute.hash = r.read_string_or_null()
                elif value_type == 1:
                    attribute.hash = r.read_guint32()
                else:
                    raise Exception("unknown attribute type")
                item.attrs.append(attribute)
            keyring.items.append(item)

        num_encrypted_bytes = r.read_guint32()
        encrypted_bytes = r.read_bytes(num_encrypted_bytes)

        digest = b''
        digests = b''
        for _ in range(1):
            sha256 = SHA256.new(data=digest)
            sha256.update(self._password)
            sha256.update(keyring.salt)

            for _ in range(1, keyring.hash_iterations):
                sha256 = SHA256.new(data=sha256.digest())

            digest = sha256.digest()
            digests += digest

        key = digests[0:16]
        iv = digests[16:16 + 16]
        aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted = aes.decrypt(encrypted_bytes)

        b_r = io.BytesIO(decrypted)
        enc_r = BinaryReader(b_r)

        # verify decryption
        encrypted_hash = enc_r.read_bytes(16)
        actual_hash = MD5.new(decrypted[16:]).digest()
        if encrypted_hash != actual_hash:
            raise Exception("hash mismatching, decryption failed")

        for i in range(num_items):
            item = keyring.items[i]
            item.name = enc_r.read_string_or_null()
            item.secret = enc_r.read_string_or_null()
            item.ctime = enc_r.read_time_t()
            item.mtime = enc_r.read_time_t()

            _ = enc_r.read_string_or_null()  # reserved
            _ = enc_r.read_guint32s(4)  # reserved

            num_attributes = enc_r.read_guint32()
            for j in range(num_attributes):
                attribute = item.attrs[j]

                name = enc_r.read_string_or_null()
                if name != attribute.name:
                    raise Exception("attribute name mismatch")

                value_type = enc_r.read_guint32()
                if value_type == 0:
                    attribute.value = enc_r.read_string()

                    # check hash
                    actual_hash = MD5.new(attribute.value.encode("utf-8")).hexdigest()
                    if actual_hash != attribute.hash:
                        Exception(f"hash mismatch, expected {attribute.hash} got {actual_hash}")
                elif value_type == 1:
                    attribute.value = enc_r.read_guint32()
                    if actual_hash != attribute.hash:
                        Exception(f"hash mismatch, expected {attribute.hash} got {actual_hash}")
                else:
                    raise Exception("unknown attribute value type")

            acl_len = enc_r.read_guint32()
            for _ in range(acl_len):
                acl = ACL()
                acl.types_allowed = enc_r.read_guint32()
                acl.display_name = enc_r.read_string_or_null()
                acl.pathname = enc_r.read_string_or_null()
                _ = enc_r.read_string_or_null()  # reserved
                _ = enc_r.read_guint32()  # reserved
                item.acls.append(acl)
                # zero padding

        return keyring


# EOF #
