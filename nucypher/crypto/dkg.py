# A very basic implementation of Pederson's DKG as described in the FROST
# paper from Chelsea Komlo and Ian Goldberg.
# https://eprint.iacr.org/2020/852.pdf (See section 5.1 for the description)
#
# This variant of Pederson's DKG has the added requirements that each
# participant prove knowledge of their secret value commitments to avoid rogue
# key attacks, and additionally requires aborting when misbehavior is detected.
#
# Note that the zero knowledge proofs for the secret value commitments is
# required to ensure safety when t >= n/2.
#
# For a practical secure implementation, the protocol should not be re-run
# endlessly on abort.
from typing import List, Tuple, Union

from bytestring_splitter import BytestringSplitter, VariableLengthBytestring
from umbral.config import default_params
from umbral.curvebn import CurveBN
from umbral.point import Point
from umbral.random_oracles import hash_to_curvebn, ExtendedKeccak
from umbral.utils import lambda_coeff, poly_eval


class SchnorrProof:
    """
    A zero-knowledge Schnorr Proof of Knowledge.
    """
    def __init__(self, sigma: CurveBN, public_comm: CurveBN):
        self.sigma = sigma
        self.public_comm = public_comm

    def __eq__(self, other):
        return self.sigma == other.sigma and self.public_comm == other.public_comm

    @classmethod
    def prove_knowledge(cls, secret: CurveBN, *public_data):
        """
        Generates a Schnorr zero-knowledge proof of the provided secret
        with the given data.
        """
        g = Point.get_generator_from_curve()
        k = CurveBN.gen_rand()
        public_comm = hash_to_curvebn(*public_data, bytes(secret * g), bytes(k * g),
                                      params=default_params(),
                                      hash_class=ExtendedKeccak)
        sigma = k + (secret * public_comm)
        return SchnorrProof(sigma, public_comm)

    def verify(self, witness: Point, *public_data):
        """
        Attempts to verify the Schnorr PoK.
        """
        g = Point.get_generator_from_curve()

        k_prime = (self.sigma * g) - (self.public_comm * witness)
        sigma_prime = hash_to_curvebn(*public_data, bytes(witness), bytes(k_prime),
                                      params=default_params(),
                                      hash_class=ExtendedKeccak)
        # TODO: Exceptions
        if not self.public_comm == sigma_prime:
            raise Exception("Schnorr proof is invalid!")
        return True

    def to_bytes(self):
        return self.sigma.to_bytes() + self.public_comm.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes):
        splitter = BytestringSplitter((CurveBN, 32), (CurveBN, 32))
        components = splitter(data)
        return SchnorrProof(components[0], components[1])


class DKGShare:
    """
    A share from a Pederson DKG ceremony.
    """
    def __init__(self, share: CurveBN, index: CurveBN):
        self.share = share
        self.index = index

    def __eq__(self, other):
        return self.share == other.share and self.index == other.index

    @classmethod
    def from_bytes(cls, data: bytes):
        splitter = BytestringSplitter((CurveBN, 32), (CurveBN, 32))
        components = splitter(data)
        return DKGShare(components[0], components[1])

    def to_bytes(self):
        return self.share.to_bytes() + self.index.to_bytes()

    def verify(self, poly_comm: 'Polynomial'):
        """
        Verifies that a share is the result of an evaluation of the provided
        polynomial commitment.
        """
        g = Point.get_generator_from_curve()
        comm_share = poly_comm.evaluate(self.index)
        if not comm_share.share == self.share * g:
            raise Exception("The polynomial commitment is invalid for this share.")
        return True


class Polynomial:
    """
    A simple polynomial that can be used privately or publicly as a commitment.
    """
    def __init__(self, coeffs: List[Union[CurveBN, Point]], secret=True):
        self.coeffs = coeffs
        self.secret = secret

    def __len__(self):
        return len(self.coeffs)

    def __eq__(self, other):
        return self.coeffs == other.coeffs

    @classmethod
    def gen_rand(cls, degree: int, secret=True):
        """
        Generates a random Polynomial of the specified degree.
        """
        coeffs = [CurveBN.gen_rand() for _ in range(degree)]
        return Polynomial(coeffs, secret=secret)

    @classmethod
    def from_bytes(cls, data: bytes, secret=True):
        coeffs_bytes = VariableLengthBytestring.dispense(data)
        if secret:
            coeffs = [CurveBN.from_bytes(coeff) for coeff in coeffs_bytes]
        else:
            coeffs = [Point.from_bytes(coeff) for coeff in coeffs_bytes]
        return Polynomial(coeffs, secret=secret)

    def to_bytes(self):
        coeffs_bytes = [coeff.to_bytes() for coeff in self.coeffs]
        return bytes(VariableLengthBytestring.bundle(coeffs_bytes))

    def commitment(self):
        """
        Returns a non-secret polynomial commitment.
        """
        g = Point.get_generator_from_curve()
        pub_coeffs = [a_i * g for a_i in self.coeffs]
        return Polynomial(pub_coeffs, secret=False)

    def evaluate(self, index: CurveBN = None):
        """
        Evaluates the polynomial with the given index. If None is provided,
        this function will generate one at random.
        """
        if not index:
            index = CurveBN.gen_rand()
        share = poly_eval(self.coeffs, index)
        return DKGShare(share, index)


def gen_pederson_shares(t: int, n: int, ceremony_id: bytes):
    """
    Implements Round 1 of Pederson's DKG.

    Takes as input an integer `t` as a threshold for secret recovery, and
    an integer `n` for the total number of shares to generate.
    Additionally, a `ceremony_id` is given as a bytestring which identifies
    this particular DKG round in the network.

    On output, this function returns a tuple containing a tuple of the share
    commitments and the corresponding proof of the secret, and a list of shares
    to distribute.
    """
    g = Point.get_generator_from_curve() # The secp256k1 basepoint.

    # We begin by sampling a polynomial of degree `t`. Note that that the
    # first term of the polynomial will be the secret. We also generate a 
    # commitment of the polynomial by raising each coefficient by the 
    # basepoint of the curve.
    secret_polynomial = Polynomial.gen_rand(t)
    poly_comm = secret_polynomial.commitment()

    # Then we prove knowledge of the secret using a Schnorr proof to prevent
    # rogue-key attacks.
    comm_proof = SchnorrProof.prove_knowledge(secret_polynomial.coeffs[0],
                                              ceremony_id)

    # Finally, we generate `n` shares of the secret to distribute.
    shares = [secret_polynomial.evaluate() for _ in range(n)]
    return (poly_comm, comm_proof, shares)


def verify_pederson_commitment(poly_comm: 'Polynomial',
                               comm_proof: 'SchnorrProof',
                               ceremony_id: bytes):
    """
    Implements the verification step in Round 1 of Pederson's DKG protocol.

    This simply verifies the zero knowlege proof of the secret term using a
    Schnorr sigma protocol.
    """
    return comm_proof.verify(poly_comm.coeffs[0], ceremony_id)

def verify_pederson_share(share: 'DKGShare', poly_comm: 'Polynomial'):
    """
    Implements the verification step in Round 2 of Pederson's DKG protocol.

    This simply checks that the received share matches the product output from
    the polynomial commitment.
    """
    return share.verify(poly_comm)
