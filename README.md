Gnome-Keyring-Raw
=================

A Python program to inspect the content of Gnome's binary keyring
files as can be found in `~/.gnome2/keyrings/login.keyring`. No DBus
or Gnome libraries are need, the file is directly inspected with just
plain Python. The `pycrypto` library is used to handle the decryption.

A similar C program can be found in the `gnome-keyring` source at
`pkcs11/secret-store/dump-keyring0-format.c`.

Usage
-----

The program can be executed directly in the source tree with:

    python3 -m gnome_keyring_raw ~/.gnome2/keyrings/login.keyring
