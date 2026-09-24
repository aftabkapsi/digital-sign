import re

from flask import (
    Blueprint,
    request,
    redirect,
    url_for,
    render_template,
    flash
)

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from models import db, User
from crypto import generate_key_pair, encrypt_private_key
from extensions import limiter


auth = Blueprint("auth", __name__)

login_manager = LoginManager()
login_manager.login_view = "auth.login"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def validate_password(password):
    """
    Require a reasonably strong password.
    """

    if len(password) < 10:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"\d", password):
        return False

    if not re.search(r"[^A-Za-z0-9]", password):
        return False

    return True


@limiter.limit("5 per hour")
@auth.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("auth.register"))

        if len(username) > 50:
            flash("Username must be 50 characters or fewer.", "error")
            return redirect(url_for("auth.register"))

        if len(email) > 120:
            flash("Email address is too long.", "error")
            return redirect(url_for("auth.register"))

        if not validate_password(password):
            flash(
                "Password must be at least 10 characters and include "
                "uppercase, lowercase, number, and special character.",
                "error"
            )
            return redirect(url_for("auth.register"))

        existing_user = User.query.filter(
            (User.username == username) |
            (User.email == email)
        ).first()

        if existing_user:
            flash(
                "Username or email already exists.",
                "error"
            )
            return redirect(url_for("auth.register"))

        # Generate Ed25519 key pair
        private_key, public_key = generate_key_pair()

        # Encrypt private key before storing it
        encrypted_private_key = encrypt_private_key(private_key)

        # Hash password
        password_hash = generate_password_hash(password)

        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            public_key=public_key.hex(),
            encrypted_private_key=encrypted_private_key.decode()
        )

        db.session.add(user)
        db.session.commit()

        flash(
            "Registration successful. You can now log in.",
            "success"
        )

        return redirect(url_for("auth.login"))

    return render_template("register.html")


@limiter.limit("5 per minute")
@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(
            user.password_hash,
            password
        ):
            flash(
                "Invalid email or password.",
                "error"
            )
            return redirect(url_for("auth.login"))

        if not user.is_active:
            flash(
                "This account is inactive.",
                "error"
            )
            return redirect(url_for("auth.login"))

        login_user(user)

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@auth.route("/logout", methods=["POST"])
@login_required
def logout():

    logout_user()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(url_for("auth.login"))