def normalize_public_label(value: str) -> str:
    """Return a normalized public label without handling secrets or credentials."""
    return value.strip().lower()
