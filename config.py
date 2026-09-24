import os
from dotenv import load_dotenv

load_dotenv()


def get_required_env(name):
    value = os.getenv(name)

    if not value:
        raise RuntimeError(
            f"Required environment variable '{name}' is missing."
        )

    return value


class Config:

    SECRET_KEY = get_required_env("SECRET_KEY")

    SQLALCHEMY_DATABASE_URI = get_required_env(
        "DATABASE_URL"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    PRIVATE_KEY_ENCRYPTION_KEY = get_required_env(
        "PRIVATE_KEY_ENCRYPTION_KEY"
    )

    MAX_CONTENT_LENGTH = 10 * 1024 * 1024

    UPLOAD_FOLDER = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "storage",
        "uploads"
    )

    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Local development is HTTP.
    # Change to True when deployed behind HTTPS.
    SESSION_COOKIE_SECURE = False