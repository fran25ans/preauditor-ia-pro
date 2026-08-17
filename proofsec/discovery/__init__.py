"""Application discovery engines for ProofSec."""

from .spring import discover_spring_boot

__all__ = ["discover_spring_boot"]
