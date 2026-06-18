from __future__ import annotations


def mongodb_configuration_error(uri: str) -> str | None:
    """Return a user-facing MongoDB configuration error, if any."""
    value = uri.strip()
    if not value:
        return (
            "MongoDB Atlas is not configured. Set mongodb_uri in "
            "dashboard/.streamlit/secrets.toml."
        )
    if not value.startswith(("mongodb+srv://", "mongodb://")):
        return "MongoDB URI must use mongodb+srv:// or mongodb://."
    return None
