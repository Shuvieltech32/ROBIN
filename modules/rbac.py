from functools import wraps

from flask import abort
from flask_login import current_user, login_required


def role_required(*allowed_roles):
    """
    Restrict a Flask route to one or more ROBIN roles.

    Example:
        @role_required("ADMIN", "ANALYST")
    """

    normalized_roles = {
        role.strip().upper()
        for role in allowed_roles
    }

    def decorator(view_function):
        @wraps(view_function)
        @login_required
        def wrapped_view(*args, **kwargs):
            user_role = str(
                getattr(current_user, "role", "")
            ).strip().upper()

            if user_role not in normalized_roles:
                abort(403)

            return view_function(*args, **kwargs)

        return wrapped_view

    return decorator
