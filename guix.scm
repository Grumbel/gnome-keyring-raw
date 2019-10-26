;; gnome-keyring-raw - Inspect raw Gnome keyring files
;; Copyright (C) 2019 Ingo Ruhnke <grumbel@gmail.com>
;;
;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

(use-modules (guix packages)
             (guix gexp)
             (guix git-download)
             (guix build-system python)
             (guix licenses)
             (gnu packages python)
             (gnu packages python-crypto)
             (gnu packages python-xyz))

(define %source-dir (dirname (current-filename)))

(define-public gnome-keyring-raw
  (package
    (name "gnome-keyring-raw")
    (version "0.1.0")
    (source
     (local-file %source-dir
                 #:recursive? #t
                 #:select? (git-predicate %source-dir)))
    (build-system python-build-system)
    (inputs
     `(("python-pyyaml" ,python-pyyaml)
       ("python-pycrypto" ,python-pycrypto)))
    (home-page "https://gitlab.com/grumbel/gnome-keyring-raw")
    (synopsis "Dump Gnome's binary keyrings into text format")
    (description "A Python program to inspect the content of Gnome's binary keyring
files as can be found in `~/.gnome2/keyrings/login.keyring`.  No DBus
or Gnome libraries are need, the file is directly inspected with just
plain Python.  The `pycrypto` library is used to handle the decryption.")
    (license gpl3+)))

gnome-keyring-raw

;; EOF ;;
