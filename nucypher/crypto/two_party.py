from typing import Union

from umbral.curvebn import CurveBN
from umbral.point import Point
from umbral.utils import lambda_coeff

from nucypher.crypto.utils import derive_curvebn_shared_secret


class TwoPartyElement:
    """
    TwoPartyElement wraps a pyUmbral CurveBN or Point that has been split using
    a modified variant of two-of-two Shamir Secret Sharing to enable the
    deterministic generation of both a share and index value for one party.

    Uniquely, the Shamir Secret Sharing algorithm has been modified to enable
    precise selection of the value of the fragmented share and the index.
    This must be done with great caution and care - the chosen value for the
    share must be random!

    A brief description of the modified scheme follows:
    A two-of-two Shamir Secret Share is the evaluation of a single degree
    polynomial:
    ```
    Z = S + R*x
    ```
    Where `Z` is the resulting share, `S` is the secret to split, `R` is a
    random coefficient, and `x` is the index to evaluate the polynomial with.

    We modify the scheme by solving for `R` as follows:
    ```
    R = (Z - S) / x
    ```
    This enables the share dealer to pick both `Z` and `x` for one of the shares.
    The dealing party can then evaluate the resulting polynomial with the `R`
    value like normal for a random `x` for the second share.

    Alternatively, if the dealer wishes to additionally pick the share value for
    the second share, they can re-use the previously computed `R` value, pick
    another `Z`, and solve for `x`:
    ```
    x = (Z - S) / R
    ```
    The resulting `x` value is the index for the share value of `Z`.

    Though not performed here, this technique to solve for `x` can extend up
    to degree-five polynomials using general formulas to solve for `x`.
    """
    def __init__(self, share: Union[CurveBN, Point], index: CurveBN):
        self.share = share
        self.index = index

    def reassemble_with(self, other: 'TwoPartyElement') -> Union[CurveBN, Point]:
        """
        Re-assembles a two-party split secret given the other share and returns
        the resulting CurveBN.
        """
        lambda_1 = lambda_coeff(self.index, [self.index, other.index])
        lambda_2 = lambda_coeff(other.index, [self.index, other.index])
        return (lambda_1 * self.share) + (lambda_2 * other.share)

    @classmethod
    def split_curvebn(cls, secret: CurveBN, chosen_share: CurveBN, chosen_index: CurveBN):
        """
        The classmethod `split_curvebn` takes three parameters:
        `secret` - The secret to split via modified two-of-two secret sharing.
        `chosen_share` - The chosen value for one of the split shares.
            *WARNING* This value MUST be random for security!
        `chosen_index` - The chosen value for the index of one of the split shares.

        This classmethod will return a `TwoPartyScalar` composed from the
        non-deterministic pieces of the secret sharing scheme.

        TODO: Allow for the selection of `Z` in the "non-deterministic" share.
        """
        # Compute the coefficient for the secret sharing polynomial with the
        # equation: R = (Z - S) / x
        r_coeff = (chosen_share - secret) * (~chosen_index)

        # Compute Z = S + R*x using the previously computed coefficient with
        # the equation: Z = S + R*x, with a random `x`.
        # Note that this is the non-deterministic share.
        x_rand_index = CurveBN.gen_rand()
        z_share = secret + (r_coeff * x_rand_index)
        return cls(z_share, x_rand_index)

    @classmethod
    def from_shared_secret(cls, priv_key: CurveBN, sharing_point: Point,
                           indexing_point: Point, params: 'UmbralParameters'):
        """
        Returns a deterministic TwoPartyScalar through shared secrets.

        It's basically magic! ;)
        """
        share_value = derive_curvebn_shared_secret(priv_key, sharing_point, params)
        index_value = derive_curvebn_shared_secret(priv_key, indexing_point, params)
        return cls(share_value, index_value)
