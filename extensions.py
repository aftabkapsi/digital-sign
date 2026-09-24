import os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


RATE_LIMIT_STORAGE_URI = os.getenv(
    "RATELIMIT_STORAGE_URI",
    "memory://"
)


limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=RATE_LIMIT_STORAGE_URI
)