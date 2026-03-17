"""
Rust-specific threat modeling functions for security analysis.

This module provides specialized threat modeling functions for Rust code,
covering general Rust security, KMS, web applications, ECDSA, general cryptography,
TSS (Threshold Signature Schemes), and MPC (Multi-Party Computation).
"""

from .rust_threats import (
    rust_general_threats,
    rust_kms_threats,
    rust_web_threats,
    rust_ecdsa_threats,
    rust_general_crypto_threats,
    rust_tss_threats,
    rust_mpc_threats
)

__all__ = [
    'rust_general_threats',
    'rust_kms_threats',
    'rust_web_threats',
    'rust_ecdsa_threats',
    'rust_general_crypto_threats',
    'rust_tss_threats',
    'rust_mpc_threats',
]

