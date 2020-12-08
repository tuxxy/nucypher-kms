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
from typing import List, Tuple

from umbral.config import default_params
from umbral.curvebn import CurveBN
from umbral.point import Point
from umbral.random_oracles import hash_to_curvebn, ExtendedKeccak
from umbral.utils import lambda_coeff, poly_eval


def gen_pederson_shares(t: int, n: int, ceremony_id: bytes) -> Tuple[Tuple[List, Tuple], List]:
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
    # first term of the polynomial will be the secret, denoted as a_0.
    coeffs = [CurveBN.gen_rand() for _ in range(t)]

    # Then we prove knowledge of the secret a_0 using a Schnorr proof.
    # Schnorr proofs are of the form `k + a_0 \cdot c_i`, where `k` is a nonce
    # generated uniformly at random, and `c_i` is the public-coin commitment.
    k = CurveBN.gen_rand() 
    a_0 = coeffs[0]
    coin_items = (ceremony_id, bytes(a_0 * g), bytes(k * g))
    public_comm = hash_to_curvebn(*coin_items, params=default_params(),
                                  hash_class=ExtendedKeccak)
    proof_sigma = (k + (a_0 * public_comm), public_comm)

    # Next, we commit to the secret sharing polynomial by embedding the terms
    # into the elliptic curve group.
    share_comm = [a_i * g for a_i in coeffs]

    # Finally, we generate `n` shares of the secret to distribute.
    shares = list()
    for _ in range(n):
        idx = CurveBN.gen_rand()
        shares.append((poly_eval(coeffs, idx), idx))
    return ((share_comm, proof_sigma), shares)


def verify_pederson_commitment(comm: Tuple[List, Tuple], ceremony_id: bytes):
    """
    Implements the verification step in Round 1 of Pederson's DKG protocol.

    This simply verifies the zero knowlege proof of the secret term using a
    Schnorr sigma protocol.
    """
    g = Point.get_generator_from_curve() # The secp256k1 basepoint.
    share_comm, proof_sigma = comm

    # Compute the public coin and compare it to the proof
    coin_items = (ceremony_id, bytes(share_comm[0]),
                  bytes((proof_sigma[0] * g) - (proof_sigma[1] * share_comm[0])))
    sigma_prime = hash_to_curvebn(*coin_items, params=default_params(),
                                  hash_class=ExtendedKeccak)
    
    # TODO: Implement errors
    if not proof_sigma[1] == sigma_prime:
        raise Exception("Proof is invalid - aborting.")
    return True


def verify_pederson_share(share: Tuple[CurveBN, CurveBN], comm: Tuple[List, Tuple]):
    """
    Implements the verification step in Round 2 of Pederson's DKG protocol.

    This simply checks that the received share matches the product output from
    the polynomial commitment.
    """
    g = Point.get_generator_from_curve() # The secp256k1 basepoint.

    # Evaluate the polynomial commitment with the index of the received share.
    share_prime = poly_eval(comm[0], share[1])

    # TODO: Implement errors
    if not share[0] * g == share_prime:
        raise Exception("Commitment is invalid - aborting.")
    return True
