from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import UniqueConstraint


db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    public_key = db.Column(
        db.Text,
        nullable=False
    )

    encrypted_private_key = db.Column(
        db.Text,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    is_active = db.Column(
        db.Boolean,
        default=True,
        nullable=False
    )


class File(db.Model):
    __tablename__ = "files"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    original_filename = db.Column(
        db.String(255),
        nullable=False
    )

    stored_filename = db.Column(
        db.String(255),
        unique=True,
        nullable=False
    )

    file_hash = db.Column(
        db.String(64),
        nullable=False,
        index=True
    )

    file_size = db.Column(
        db.BigInteger,
        nullable=False
    )

    file_type = db.Column(
        db.String(100)
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    user = db.relationship(
        "User",
        backref="files"
    )


class Signature(db.Model):
    __tablename__ = "signatures"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    file_id = db.Column(
        db.Integer,
        db.ForeignKey("files.id"),
        nullable=False,
        index=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    signature = db.Column(
        db.Text,
        nullable=False,
        unique=True
    )

    algorithm = db.Column(
        db.String(50),
        nullable=False,
        default="Ed25519"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    status = db.Column(
        db.String(20),
        default="active",
        nullable=False,
        index=True
    )

    file = db.relationship(
        "File",
        backref="signature"
    )

    user = db.relationship(
        "User",
        backref="signatures"
    )


class VerificationLog(db.Model):
    __tablename__ = "verification_logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    signature_id = db.Column(
        db.Integer,
        db.ForeignKey("signatures.id"),
        nullable=False,
        index=True
    )

    verifier_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True,
        index=True
    )

    verification_result = db.Column(
        db.Boolean,
        nullable=False
    )

    verifier_ip = db.Column(
        db.String(45)
    )

    verifier_agent = db.Column(
        db.Text
    )

    verification_time = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    signature_record = db.relationship(
        "Signature",
        backref="verification_logs"
    )

    verifier = db.relationship(
        "User",
        foreign_keys=[verifier_id]
    )