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
from umbral.keys import UmbralPrivateKey, derive_key_from_password,

from nucypher.config.keyring import _derive_wrapping_key_from_key_material
from nucypher.crypto.powers import DelegatingPower


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

    class Unlocked(Exception):
        """
        Exception class for when the Keyring is already in an unlocked state.
        """
        pass

    class NoPowerSet(Exception):
        """
        Exception class for the case when the Keyring has no powers yet.
        """
        pass

    class NoKeyringFile(Exception):
        """
        Exception class for the case when there is no Keyring file yet.
        """
        pass

    def __init__(self, keyring_file: str = None,
                 power_set: 'CryptoPowerSet' = None):
        if not (bool(keyring_file) ^ bool(power_set)):
            raise ValueError("You must pass either a keyring_file or a power_set.")

        self.__derived_key = None
        self.keyring_data = None

        if keyring_file:
            self.is_unlocked = False
            self._keyring_file = keyring_file

        if power_set:
            self.is_unlocked = True
            self.__power_set = power_set

    def __serialize_power_set(self, encrypt=True):
        """
        Serializes the powers in a CryptoPowerSet.
        The de/serialization methods in Keyring assume security by default.
        In this case, the serializer defaults to encrypting the powers when
        called.
        """
        if not self.__power_set:
            raise Keyring.NoPowerSet("There is no CryptoPowerSet to serialize yet.")
        if not self.is_unlocked:
            raise Keyring.Locked("You can't serialize the CryptoPowerSet when the Keyring is locked.")

        powers_data = dict()
        for power_class, power_instance in self.__power_set._power_ups.items():
            power_type = power_class.__name__

            if power_class == DelegatingPower:
                key_data = power_instance.__umbral_keying_material
            else:
                key_data = bytes(power_instance.keypair.private_key)
            powers_data[power_type] = key_data
        return powers_data

    def __deserialize_keyring_file(self, decrypt=False):
        """
        Deserializes the Keyring file from the filesystem.
        The de/serialization methods in Keyring assume security by default.
        In this case, the deserializer defaults to not decrypting the powers
        when called.
        """
        if not self._keyring_file:
            raise Keyring.NoKeyringFile("There is no Keyring file to deserialize yet.")
        if not self.is_unlocked:
            raise Keyring.Locked("You cannot deserialize the Keyring file when the Keyring is locked.")

        if not self.keyring_data:
            try:
                with open(self._keyring_file, 'rb') as f:
                    self.keyring_data = json.loads(f.read())
            except FileNotFoundError:
                raise FileNotFoundError(f"Keyring file {self._keyring_file} doesn't exist")

        if decrypt:
            keys = self.keyring_data['keys']
            for key in keys:
                wrapping_key = _derive_wrapping_key_from_key_material(
                                                salt=key['wrapping_salt'],
                                                key_material=self.__derived_key)
                if key['power_up'] == 'DelegatingPower':
                    key = 
                key = UmbralPrivateKey.from_bytes(key['key_data'],
                                                  wrapping_key=wrapping_key)


    def unlock(self, password: str):
        """
        Unlocks and decrypts the Keyring and caches the derived key
        if the key is not cached.
        """
        if self.is_unlocked:
            raise Keyring.Unlocked("The Keyring is already unlocked.")

        # Deserialize the keyring file w/o decrypting first to get salts
        self.__deserialize_keyring_file(decrypt=False)
        self.__derived_key = derive_key_from_password(
                                    password=password.encode(),
                                    salt=self.keyring_data['master_salt'])
        pass

    def lock(self):
        """
        Locks the Keyring.
        """
        if not self.is_unlocked:
            raise Keyring.Locked("The Keyring is already locked.")
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
