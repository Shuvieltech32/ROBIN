"""Authentication support for ROBIN Phase 8."""

import json
import os
from dataclasses import dataclass
from typing import Dict, Optional

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash


USERS_FILE = "data/users.json"


@dataclass
class User(UserMixin):
    """Authenticated ROBIN user."""

    id: str
    username: str
    password_hash: str
    role: str = "VIEWER"
    active: bool = True

    @property
    def is_active(self) -> bool:
        return self.active


def load_users() -> Dict[str, Dict[str, str]]:
    """Load users from the local users file."""

    if not os.path.exists(USERS_FILE):
        return {}

    try:
        with open(USERS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}

    return data

def count_active_admins() -> int:
    """Return the number of enabled ADMIN accounts."""

    users = load_users()

    return sum(
        1
        for user in users.values()
        if user.get("active", True)
        and user.get("role", "VIEWER").upper() == "ADMIN"
    )

def save_users(users: Dict[str, Dict[str, str]]) -> None:
    """Save users safely to disk."""

    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)

    temporary_file = f"{USERS_FILE}.tmp"

    with open(temporary_file, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=2)

    os.replace(temporary_file, USERS_FILE)


def get_user_by_id(user_id: str) -> Optional[User]:
    """Return a user matching the supplied ID."""

    users = load_users()

    for username, data in users.items():
        if str(data.get("id")) != str(user_id):
            continue

        return User(
            id=str(data.get("id")),
            username=username,
            password_hash=str(data.get("password_hash", "")),
            role=str(data.get("role", "VIEWER")).upper(),
            active=bool(data.get("active", True)),
        )

    return None


def get_user_by_username(username: str) -> Optional[User]:
    """Return a user matching the supplied username."""

    users = load_users()
    normalized_username = username.strip().lower()

    data = users.get(normalized_username)

    if not isinstance(data, dict):
        return None

    return User(
        id=str(data.get("id")),
        username=normalized_username,
        password_hash=str(data.get("password_hash", "")),
        role=str(data.get("role", "VIEWER")).upper(),
        active=bool(data.get("active", True)),
    )


def verify_user(username: str, password: str) -> Optional[User]:
    """Verify a username and password."""

    user = get_user_by_username(username)

    if user is None or not user.is_active:
        return None

    if not check_password_hash(user.password_hash, password):
        return None

    return user


def create_user(
    username: str,
    password: str,
    role: str = "VIEWER",
) -> User:
    """Create and save a new ROBIN user."""

    users = load_users()
    normalized_username = username.strip().lower()

    if not normalized_username:
        raise ValueError("Username cannot be empty.")

    if len(password) < 12:
        raise ValueError(
            "Password must contain at least 12 characters."
        )

    if normalized_username in users:
        raise ValueError("That username already exists.")

    user_id = str(len(users) + 1)

    users[normalized_username] = {
        "id": user_id,
        "password_hash": generate_password_hash(password),
        "role": role.strip().upper(),
        "active": True,
    }

    save_users(users)

    return get_user_by_username(normalized_username)


def update_password(username: str, new_password: str) -> None:
    """Update the password for an existing ROBIN user."""

    users = load_users()
    normalized_username = username.strip().lower()

    if normalized_username not in users:
        raise ValueError("User does not exist.")

    if len(new_password) < 12:
        raise ValueError(
            "Password must contain at least 12 characters."
        )

    users[normalized_username]["password_has"] = (
        generate_password_hash(new_password)
    )

    save_users(users)

def list_users():
    """Return all ROBIN users without exposing password hashes."""

    users = load_users()
    safe_users = []

    for username, data in users.items():
        safe_users.append(
            {
                "id": data.get("id"),
                "username": username,
                "role": data.get("role", "VIEWER"),
                "active": data.get("active", True),
            }
        )

    return sorted(
        safe_users,
        key=lambda user: user["username"],
    )


def set_user_active(
    username: str, 
    active: bool,
    acting_username: str | None = None,
) -> None:
    """Enable or disable an ROBIN user safely."""

    users = load_users()
    normalized_username = username.strip().lower()

    normalized_actor = (
        acting_username.strip().lower()
        if acting_username
        else None
    )

    if normalized_username not in users:
        raise ValueError("User does not exist.")

    if (
        not active
        and normalized_actor == normalized_username
    ):
        raise ValueError(
            "You cannot disable your own account."
        )

    target = users[normalized_username]

    if (
        not active
        and target.get("active", True)
        and target.get("role", "VIEWER").upper() == "ADMIN"
        and count_active_admins() <= 1
    ):
        raise ValueError(
            "The last active administrator cannot be disabled."
        )

    target["active"] = bool(active)
    save_users(users)


def change_user_role(
    username: str, 
    new_role: str,
) -> None:
    """Change a role without removing the final administrator."""

    allowed_roles = {"ADMIN", "ANALYST", "VIEWER"}
    normalized_username = username.strip().lower()
    normalized_role = new_role.strip().upper()

    if normalized_role not in allowed_roles:
        raise ValueError("Invalid role.")

    users = load_users()

    if normalized_username not in users:
        raise ValueError("User does not exist.")

    target = users[normalized_username]
    old_role = target.get("role", "VIEWER").upper()

    if (
        old_role == "ADMIN"
        and normalized_role != "ADMIN"
        and target.get("active", True)
        and count_active_admins() <= 1
    ):
        raise ValueError(
            "The last active administrator cannot be demoted."
        )

    target["role"] = normalized_role
    save_users(users)
