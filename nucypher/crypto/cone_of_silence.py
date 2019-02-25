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


from twisted.protocols.basic import LineReceiver


class ConeOfSilence(LineReceiver):
    """
    A compartment (like a SCIF) to perform sensitive cryptographic operations.
    """

    encoding = 'utf-8'

    def __init__(self, keyring_root):
        pass

    def lineReceived(self, line):
        pass
