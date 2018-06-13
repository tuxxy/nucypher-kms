from nucypher.crypto.constants import PUBLIC_KEY_LENGTH, CAPSULE_LENGTH
from bytestring_splitter import BytestringSplitter
from umbral.keys import UmbralPublicKey
from umbral.pre import Capsule

from nucypher.config import UMBRAL_PARAMS


key_splitter = BytestringSplitter((UmbralPublicKey, PUBLIC_KEY_LENGTH,
                    {'params': UMBRAL_PARAMS}))
capsule_splitter = BytestringSplitter((Capsule, CAPSULE_LENGTH,
                    {'params': UMBRAL_PARAMS}))
