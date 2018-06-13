from nucypher.config.utils import check_config_runtime
from umbral.config import default_params

check_config_runtime()

UMBRAL_PARAMS = default_params()
