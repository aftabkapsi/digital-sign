import hashlib
import os
import uuid
import zipfile

from werkzeug.utils import secure_filename


ALLOWED_EXTENSIONS = {
    "pdf",
    "txt",
    "doc",
    "docx",
    "png",
    "jpg",
    "jpeg",
    "zip"
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

MAX_USER_STORAGE = 100 * 1024 * 1024  # 100 MB

def allowed_file(filename):
    if not filename or "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in ALLOWED_EXTENSIONS


def validate_filename(filename):
    """
    Check whether the original filename is acceptable.
    """

    if not filename:
        return False

    safe_name = secure_filename(filename)

    if not safe_name:
        return False

    if len(safe_name) > 255:
        return False

    return True


def validate_file_content(file_path, filename):
    """
    Perform basic file-signature validation.

    This does not replace antivirus scanning.
    """

    extension = filename.rsplit(".", 1)[1].lower()

    try:
        file_size = os.path.getsize(file_path)

        # Reject empty files
        if file_size == 0:
            return False

        # Enforce maximum file size
        if file_size > MAX_FILE_SIZE:
            return False

        with open(file_path, "rb") as file:
            header = file.read(16)

        # PDF
        if extension == "pdf":
            return header.startswith(b"%PDF-")

        # PNG
        if extension == "png":
            return header.startswith(
                b"\x89PNG\r\n\x1a\n"
            )

        # JPEG
        if extension in {"jpg", "jpeg"}:
            return header.startswith(b"\xff\xd8\xff")

        # Old Microsoft Word .doc
        if extension == "doc":
            return header.startswith(
                b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
            )

        # DOCX
        if extension == "docx":
            if not zipfile.is_zipfile(file_path):
                return False

            with zipfile.ZipFile(file_path, "r") as archive:
                names = archive.namelist()

                return (
                    "[Content_Types].xml" in names
                    and "word/document.xml" in names
                )

        # ZIP
        if extension == "zip":
            return zipfile.is_zipfile(file_path)

        # TXT
        if extension == "txt":
            return True

        return False

    except (OSError, zipfile.BadZipFile):
        return False


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(8192)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def generate_stored_filename(original_filename):
    safe_name = secure_filename(original_filename)

    extension = ""

    if "." in safe_name:
        extension = "." + safe_name.rsplit(".", 1)[1].lower()

    unique_name = f"{uuid.uuid4().hex}{extension}"

    return unique_name