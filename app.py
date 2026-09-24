from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file
)

from sqlalchemy import text
from flask_login import login_required, current_user
from flask_wtf.csrf import CSRFProtect

import os

from config import Config
from auth import auth, login_manager

from extensions import limiter

from file_utils import (
    allowed_file,
    validate_filename,
    validate_file_content,
    calculate_sha256,
    generate_stored_filename,
    MAX_USER_STORAGE
)

from crypto import (
    decrypt_private_key,
    sign_hash,
    verify_signature
)

from certificate import generate_certificate

from models import (
    db,
    User,
    File,
    Signature,
    VerificationLog
)

from flask_migrate import Migrate


# --------------------------------------------------
# Flask application
# --------------------------------------------------

app = Flask(__name__)
app.config.from_object(Config)


# --------------------------------------------------
# Security extensions
# --------------------------------------------------

csrf = CSRFProtect(app)

limiter.init_app(app)


@app.after_request
def add_security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "SAMEORIGIN"

    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    response.headers["Permissions-Policy"] = (
        "camera=(self), microphone=(self), geolocation=()"
    )

    return response


# --------------------------------------------------
# Database
# --------------------------------------------------

db.init_app(app)
migrate = Migrate(app, db)


# --------------------------------------------------
# Login system
# --------------------------------------------------

login_manager.init_app(app)


# --------------------------------------------------
# Authentication routes
# --------------------------------------------------

app.register_blueprint(auth)


# --------------------------------------------------
# Home
# --------------------------------------------------

@app.route("/")
def home():
    return redirect(url_for("auth.login"))


# --------------------------------------------------
# Database test
# --------------------------------------------------

@app.route("/db-test")
def db_test():

    try:

        db.session.execute(
            text("SELECT 1")
        )

        return "PostgreSQL connection successful!"

    except Exception as e:

        return f"Database connection failed: {e}"


# --------------------------------------------------
# Dashboard
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    recent_signatures = (
        Signature.query
        .filter_by(user_id=current_user.id)
        .order_by(Signature.created_at.desc())
        .limit(10)
        .all()
    )

    return render_template(
        "dashboard.html",
        current_user=current_user,
        recent_signatures=recent_signatures
    )


# --------------------------------------------------
# Sign document
# --------------------------------------------------

@app.route("/sign", methods=["GET", "POST"])
@login_required
@limiter.limit("20 per hour")
def sign_file():

    if request.method == "POST":

        uploaded_file = request.files.get("file")

        # Check file exists
        if not uploaded_file or uploaded_file.filename == "":
            flash(
                "Please select a file.",
                "error"
            )

            return redirect(
                url_for("sign_file")
            )

        original_filename = uploaded_file.filename

        # Validate filename
        if not validate_filename(
            original_filename
        ):
            flash(
                "Invalid filename.",
                "error"
            )

            return redirect(
                url_for("sign_file")
            )

        # Validate extension
        if not allowed_file(
            original_filename
        ):
            flash(
                "This file type is not allowed.",
                "error"
            )

            return redirect(
                url_for("sign_file")
            )

        # Check user's total storage usage
        current_storage = db.session.query(
            db.func.coalesce(
                db.func.sum(File.file_size),
                0
            )
        ).filter(
            File.user_id == current_user.id
        ).scalar()

        current_storage = int(current_storage or 0)

        if uploaded_file.content_length:
            incoming_size = uploaded_file.content_length
        else:
            uploaded_file.stream.seek(0, os.SEEK_END)
            incoming_size = uploaded_file.stream.tell()
            uploaded_file.stream.seek(0)

        if current_storage + incoming_size > MAX_USER_STORAGE:
            flash(
                "This upload would exceed your 100 MB storage limit.",
                "error"
            )
            return redirect(url_for("sign_file"))

        # Generate safe unique filename
        stored_filename = generate_stored_filename(
            original_filename
        )

        upload_folder = app.config[
            "UPLOAD_FOLDER"
        ]

        os.makedirs(
            upload_folder,
            exist_ok=True
        )

        file_path = os.path.join(
            upload_folder,
            stored_filename
        )

        # Save uploaded file
        uploaded_file.save(file_path)

        try:

            # Validate actual file content
            if not validate_file_content(
                file_path,
                original_filename
            ):

                flash(
                    "The uploaded file is invalid or does not match its file type.",
                    "error"
                )

                return redirect(
                    url_for("sign_file")
                )

            # Calculate SHA-256
            file_hash = calculate_sha256(
                file_path
            )

            # Decrypt user's private key
            encrypted_private_key = (
                current_user.encrypted_private_key.encode(
                    "utf-8"
                )
            )

            private_key = decrypt_private_key(
                encrypted_private_key
            )

            # Create Ed25519 signature
            signature_value = sign_hash(
                private_key,
                file_hash
            )

            # Store file information
            file_record = File(
                user_id=current_user.id,
                original_filename=original_filename,
                stored_filename=stored_filename,
                file_hash=file_hash,
                file_size=os.path.getsize(file_path),
                file_type=uploaded_file.mimetype
            )

            db.session.add(file_record)

            db.session.flush()

            # Store digital signature
            signature_record = Signature(
                file_id=file_record.id,
                user_id=current_user.id,
                signature=signature_value,
                algorithm="Ed25519"
            )

            db.session.add(signature_record)

            db.session.commit()

            return render_template(
                "sign_result.html",
                file=file_record,
                signature=signature_record
            )

        except Exception:

            # Roll back database changes
            db.session.rollback()

            # Remove uploaded file if signing fails
            if os.path.exists(file_path):
                os.remove(file_path)

            flash(
                "Something went wrong while creating the digital signature.",
                "error"
            )

            return redirect(
                url_for("sign_file")
            )
        
    return render_template(
        "sign.html"
    )


# --------------------------------------------------
# Verify document
# --------------------------------------------------

@app.route("/verify", methods=["GET", "POST"])
@login_required
@limiter.limit("30 per hour")
def verify_file():

    if request.method == "POST":

        uploaded_file = request.files.get(
            "file"
        )

        signature_value = request.form.get(
            "signature",
            ""
        ).strip()

        # Check file
        if not uploaded_file or uploaded_file.filename == "":
            flash(
                "Please select a file.",
                "error"
            )

            return redirect(
                url_for("verify_file")
            )

        # Check signature
        if not signature_value:
            flash(
                "Please provide the digital signature.",
                "error"
            )

            return redirect(
                url_for("verify_file")
            )

        original_filename = uploaded_file.filename

        # Validate filename
        if not validate_filename(
            original_filename
        ):
            flash(
                "Invalid filename.",
                "error"
            )

            return redirect(
                url_for("verify_file")
            )

        # Validate extension
        if not allowed_file(
            original_filename
        ):
            flash(
                "This file type is not allowed.",
                "error"
            )

            return redirect(
                url_for("verify_file")
            )

        # Create temporary filename
        temp_filename = generate_stored_filename(
            original_filename
        )

        upload_folder = app.config[
            "UPLOAD_FOLDER"
        ]

        os.makedirs(
            upload_folder,
            exist_ok=True
        )

        temp_path = os.path.join(
            upload_folder,
            temp_filename
        )

        # Save temporary file
        uploaded_file.save(
            temp_path
        )

        try:

            # Validate actual file content
            if not validate_file_content(
                temp_path,
                original_filename
            ):

                flash(
                    "The uploaded file is invalid or does not match its file type.",
                    "error"
                )

                return redirect(
                    url_for("verify_file")
                )

            # Calculate current SHA-256
            current_hash = calculate_sha256(
                temp_path
            )

            # Find active signature
            signature_record = (
                Signature.query
                .filter_by(
                    signature=signature_value,
                    status="active"
                )
                .first()
            )

            if not signature_record:
                return render_template(
                    "verify_result.html",
                    valid=False,
                    message="Signature not found or is no longer active.",
                    current_hash=current_hash
                )

            # Get original file
            original_file = db.session.get(
                File,
                signature_record.file_id
            )

            if not original_file:
                return render_template(
                    "verify_result.html",
                    valid=False,
                    message="Original file record could not be found.",
                    current_hash=current_hash
                )

            # Make sure the signature belongs to the file owner
            if signature_record.user_id != original_file.user_id:
                return render_template(
                    "verify_result.html",
                    valid=False,
                    message="Signature ownership validation failed.",
                    current_hash=current_hash
                )

            # Get signing user
            signing_user = db.session.get(
                User,
                signature_record.user_id
            )

            if not signing_user or not signing_user.is_active:
                return render_template(
                    "verify_result.html",
                    valid=False,
                    message="The signing account is inactive.",
                    current_hash=current_hash
                )

            # Verify Ed25519 signature
            valid = verify_signature(
                signing_user.public_key,
                current_hash,
                signature_value
            )

            # Compare hashes
            hash_matches = (
                original_file.file_hash == current_hash
            )

            verification_result = (
                valid and hash_matches
            )

            # Store verification log
            log = VerificationLog(
                signature_id=signature_record.id,
                verifier_id=current_user.id,
                verification_result=verification_result,
                verifier_ip=request.remote_addr,
                verifier_agent=request.user_agent.string
            )

            db.session.add(log)

            db.session.commit()

            return render_template(
                "verify_result.html",
                valid=verification_result,
                message=(
                    "Signature is valid and file integrity is verified."
                    if verification_result
                    else
                    "Signature verification failed or the file was modified."
                ),
                current_hash=current_hash,
                original_hash=original_file.file_hash
            )

        finally:

            # Always remove temporary verification file
            if os.path.exists(temp_path):
                os.remove(temp_path)

    return render_template(
        "verify.html"
    )


# --------------------------------------------------
# About
# --------------------------------------------------

@app.route("/about")
def about():

    return render_template(
        "about.html"
    )

# --------------------------------------------------
# Revoke signature
# --------------------------------------------------

@app.route(
    "/signature/<int:signature_id>/revoke",
    methods=["POST"]
)
@login_required
@limiter.limit("20 per hour")
def revoke_signature(signature_id):

    signature_record = (
        Signature.query
        .filter_by(
            id=signature_id,
            user_id=current_user.id
        )
        .first()
    )

    if not signature_record:
        flash(
            "Signature not found.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    if signature_record.status != "active":
        flash(
            "This signature has already been revoked.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    signature_record.status = "revoked"

    db.session.commit()

    flash(
        "Digital signature has been revoked.",
        "success"
    )

    return redirect(
        url_for("dashboard")
    )

# --------------------------------------------------
# Download certificate
# --------------------------------------------------

@app.route(
    "/certificate/<int:signature_id>"
)
@login_required
def download_certificate(
    signature_id
):

    signature_record = (
        Signature.query
        .filter_by(
            id=signature_id,
            user_id=current_user.id
        )
        .first_or_404()
    )

    file_record = db.session.get(
        File,
        signature_record.file_id
    )

    if not file_record:
        return "File record not found.", 404

    pdf = generate_certificate(
        file_record,
        signature_record,
        current_user.username
    )

    return send_file(
        pdf,
        as_attachment=True,
        download_name=(
            f"SIG-{signature_record.id:06d}"
            "-certificate.pdf"
        ),
        mimetype="application/pdf"
    )


# --------------------------------------------------
# Run application
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        debug=False
    )