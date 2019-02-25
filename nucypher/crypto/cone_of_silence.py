"""
This file is part of nucypher.

nucypher is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

nucypher is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import os

from twisted.protocols.basic import LineReceiver


class Keyring:
    """
    A Keyring provides an interface to en/decrypt and de/serialize a
    CryptoPowerSet to/from the filesystem.
    """

    class Locked(Exception):
        """
        Exception class for when you access the Keyring in a locked state.
        """
        pass

    def __init__(self, keyring_file: str):
        self.is_unlocked = False
        self.__power_set = None

        with open(keyring_file, 'rb') as f:
            self.keyring_data = json.loads(f.read())

    def unlock(self, passphrase: str):
        """
        Unlocks the Keyring and caches the derived key, if key is not cached.
        """
        pass

    def lock(self, power_set):
        """
        Locks the Keyring.
        """
        pass

    @property
    def as_power_set(self):
        if not self.is_unlocked:
            raise Keyring.Locked("The Keyring is currently locked, call Keyring.unlock first.")
        return self.__power_set


class ConeOfSilence(LineReceiver):
    """
    A compartment (like a SCIF) to perform sensitive cryptographic operations.
    """

    encoding = 'utf-8'

    def __init__(self, keyring_root):
        self.unlocked_keyrings = dict()
        self.keyrings = dict()
        for keyring_file in os.listdir(keyring_root):
            new_keyring = Keyring(keyring_file)
            self.keyrings[new_keyring.id] = new_keyring

    def lineReceived(self, line):
        pass
