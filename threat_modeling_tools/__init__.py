"""
Comprehensive threat modeling toolkit organized by framework, language, and expertise area.

This package provides threat modeling functions organized into logical categories:

- Blockchain: Smart contracts, DeFi protocols, and blockchain infrastructure
- Programming Languages: Language-specific security concerns
- Frameworks: Framework-specific vulnerabilities
- Cryptography: Cryptographic implementations and protocols
- Web Security: OWASP Top 10, API security, and web application threats
- Infrastructure: Container, cloud, and DevOps security threats
- AI/ML: Adversarial attacks, model poisoning, and ML security threats
- IoT/Mobile: IoT devices, mobile applications, and embedded systems threats
- Network/Data: Network protocols, data privacy, and communication security threats
- Incident Response: Digital forensics, incident handling, and security operations threats
"""

# Blockchain threat modeling
from .blockchain.defi_threats import (
    defi_protocol_threats,
    amm_specific_threats,
    lending_protocol_threats,
    borrowing_security_threats,
    liquidation_mechanism_threats,
    collateral_management_threats,
    interest_rate_model_threats
)

from .blockchain.solidity_threats import (
    solidity_general_threats,
    solidity_assembly_threats,
    solidity_logical_threats,
    solidity_defi_threats,
    solidity_token_threats,
    solidity_crypto_threats,
    solidity_correctness_threats,
    solidity_funds_loss_threats,
    solidity_upgrade_threats,
    solidity_oracle_threats,
    solidity_reentrancy_threats,
    solidity_access_control_threats,
    solidity_gas_dos_threats,
    solidity_frontrunning_mev_threats,
    solidity_flash_loan_threats,
    solidity_governance_threats,
    solidity_lending_threats,
    solidity_amm_threats,
    solidity_staking_threats,
    solidity_nft_threats,
    solidity_bridge_threats,
    solidity_timestamp_block_threats,
    solidity_dust_liquidation_threats,
    solidity_chain_compatibility_threats,
    solidity_error_handling_threats,
    solidity_slippage_protection_threats,
    solidity_fee_calculation_threats,
    solidity_residual_refund_threats,
    solidity_settlement_griefing_threats,
    solidity_external_call_return_threats,
    solidity_money_market_threats,
    solidity_cross_chain_gas_threats,
    solidity_debt_reporting_threats
)

from .blockchain.l2_threats import (
    l2_rollup_threats,
    l2_bridge_threats,
    l2_scaling_threats
)

from .blockchain.l1_threats import (
    l1_consensus_threats,
    l1_chain_split_threats,
    l1_protocol_threats
)

from .blockchain.solana_threats import (
    solana_general_threats,
    solana_account_threats,
    solana_program_threats
)

from .blockchain.substrate_threats import (
    substrate_general_threats,
    substrate_pallet_threats,
    substrate_runtime_threats
)

from .blockchain.near_threats import (
    near_general_threats,
    near_contract_threats,
    near_account_threats
)

from .blockchain.cosmos_threats import (
    cosmos_general_threats,
    tendermint_threats,
    ibc_threats,
    cosmos_sdk_threats
)

from .blockchain.avalanche_threats import (
    avalanche_general_threats,
    avalanche_subnet_threats
)

from .blockchain.move_threats import (
    move_general_threats,
    move_resource_safety_threats,
    move_access_control_threats,
    move_object_threats,
    move_token_threats,
    move_nft_threats,
    move_defi_threats,
    move_global_storage_threats,
    move_parallelization_threats,
    move_cryptography_threats,
    move_upgrade_threats,
    move_multi_agent_threats,
    move_resource_account_threats
)

from .blockchain.ripple_threats import (
    ripple_general_threats,
    ripple_payment_threats,
    ripple_trustline_threats,
    ripple_escrow_threats,
    ripple_payment_channel_threats,
    ripple_account_security_threats,
    ripple_offer_threats,
    ripple_transaction_validation_threats,
    ripple_amendment_threats
)

# Programming language threat modeling
from .programming_languages.python_threats import (
    python_general_threats,
    python_web_threats,
    python_data_threats
)

from .programming_languages.scala_threats import (
    scala_general_threats
)

from .programming_languages.cpp_threats import (
    cpp_general_threats,
    cpp_memory_threats,
    cpp_concurrency_threats
)

from .programming_languages.c_threats import (
    c_general_threats,
    c_memory_threats
)

from .programming_languages.rust_threats import (
    rust_general_threats
)

from .programming_languages.java_threats import (
    java_general_threats
)

from .programming_languages.javascript_threats import (
    javascript_general_threats
)

from .programming_languages.typescript_threats import (
    typescript_general_threats,
    typescript_web3_wallet_threats,
    typescript_sdk_threats
)

from .programming_languages.go_threats import (
    go_general_threats,
    go_graphql_threats,
    go_p2p_threats,
    go_ethereum_threats,
    go_http_threats,
    go_database_threats,
    go_cryptography_threats,
    go_concurrency_threats
)

from .programming_languages.php_threats import (
    php_general_threats
)

# Framework threat modeling
from .frameworks.nextjs_threats import (
    nextjs_general_threats,
    nextjs_api_threats,
    nextjs_component_threats
)

from .frameworks.django_threats import (
    django_general_threats,
    django_orm_threats
)

from .frameworks.react_native_threats import (
    react_native_general_threats
)

from .frameworks.express_threats import (
    express_general_threats
)

from .frameworks.fastapi_threats import (
    fastapi_general_threats
)

from .frameworks.springboot_threats import (
    springboot_general_threats
)

from .frameworks.rails_threats import (
    rails_general_threats
)

from .frameworks.nestjs_threats import (
    nestjs_general_threats,
    nestjs_controller_threats,
    nestjs_service_threats,
    nestjs_guard_threats
)

# Cryptography threat modeling
from .cryptography.general_cryptography_threats import (
    general_cryptography_threats,
    random_number_generation_threats,
    key_management_threats
)

from .cryptography.aes_threats import (
    aes_implementation_threats,
    aes_key_management_threats,
    aes_padding_threats
)

from .cryptography.shamir_threats import (
    shamir_scheme_threats,
    shamir_threshold_threats,
    shamir_share_management_threats
)

from .cryptography.mpc_threats import (
    mpc_protocol_threats,
    mpc_threshold_threats,
    mpc_party_threats
)

from .cryptography.ecdsa_threats import (
    ecdsa_implementation_threats,
    ecdsa_nonce_threats,
    ecdsa_curve_threats
)

from .cryptography.hash_threats import (
    hash_function_threats,
    password_hashing_threats,
    hash_collision_threats
)

from .cryptography.rsa_threats import (
    rsa_implementation_threats,
    rsa_key_management_threats,
    rsa_padding_threats
)

from .cryptography.protocol_threats import (
    ssl_tls_threats,
    handshake_threats,
    protocol_downgrade_threats
)

from .cryptography.javacard_threats import (
    javacard_applet_threats,
    javacard_apdu_threats,
    javacard_secure_channel_threats
)

# Web security threat modeling
from .web_security.owasp_threats import (
    owasp_top10_threats,
    api_security_threats,
    xss_security_threats,
    csrf_security_threats,
    sql_injection_threats,
    session_security_threats,
    authentication_authorization_threats,
    file_upload_security_threats
)

# Infrastructure threat modeling
from .infrastructure.container_threats import (
    container_security_threats,
    cloud_security_threats
)

from .infrastructure.cdk_threats import (
    cdk_general_threats,
    cdk_iam_threats,
    cdk_network_threats,
    cdk_storage_threats,
    cdk_lambda_threats
)

# AI/ML threat modeling
from .ai_ml.adversarial_threats import (
    adversarial_attack_threats,
    model_poisoning_threats
)

# IoT and Mobile threat modeling
from .iot_mobile.iot_threats import (
    iot_security_threats,
    mobile_security_threats
)

# Network and Data threat modeling
from .network_data.network_threats import (
    network_security_threats,
    data_privacy_threats
)

# Rust threat modeling
from .rust.rust_threats import (
    rust_general_threats,
    rust_kms_threats,
    rust_web_threats,
    rust_ecdsa_threats,
    rust_general_crypto_threats,
    rust_tss_threats,
    rust_mpc_threats
)



__all__ = [
    # Blockchain Threats
    'defi_protocol_threats',
    'amm_specific_threats',
    'lending_protocol_threats',
    'borrowing_security_threats',
    'liquidation_mechanism_threats',
    'collateral_management_threats',
    'interest_rate_model_threats',
    'solidity_general_threats',
    'solidity_assembly_threats',
    'solidity_logical_threats',
    'solidity_defi_threats',
    'solidity_token_threats',
    'solidity_crypto_threats',
    'solidity_correctness_threats',
    'solidity_funds_loss_threats',
    'solidity_upgrade_threats',
    'solidity_oracle_threats',
    'solidity_reentrancy_threats',
    'solidity_access_control_threats',
    'solidity_gas_dos_threats',
    'solidity_frontrunning_mev_threats',
    'solidity_flash_loan_threats',
    'solidity_governance_threats',
    'solidity_lending_threats',
    'solidity_amm_threats',
    'solidity_staking_threats',
    'solidity_nft_threats',
    'solidity_bridge_threats',
    'solidity_timestamp_block_threats',
    'solidity_dust_liquidation_threats',
    'solidity_chain_compatibility_threats',
    'solidity_error_handling_threats',
    'solidity_slippage_protection_threats',
    'solidity_fee_calculation_threats',
    'solidity_residual_refund_threats',
    'solidity_settlement_griefing_threats',
    'solidity_external_call_return_threats',
    'solidity_money_market_threats',
    'solidity_cross_chain_gas_threats',
    'solidity_debt_reporting_threats',
    'l2_rollup_threats',
    'l2_bridge_threats',
    'l2_scaling_threats',
    'l1_consensus_threats',
    'l1_chain_split_threats',
    'l1_protocol_threats',
    'solana_general_threats',
    'solana_account_threats',
    'solana_program_threats',
    'substrate_general_threats',
    'substrate_pallet_threats',
    'substrate_runtime_threats',
    'near_general_threats',
    'near_contract_threats',
    'near_account_threats',
    'cosmos_general_threats',
    'tendermint_threats',
    'ibc_threats',
    'cosmos_sdk_threats',
    'avalanche_general_threats',
    'avalanche_subnet_threats',
    'move_general_threats',
    'move_resource_safety_threats',
    'move_access_control_threats',
    'move_object_threats',
    'move_token_threats',
    'move_nft_threats',
    'move_defi_threats',
    'move_global_storage_threats',
    'move_parallelization_threats',
    'move_cryptography_threats',
    'move_upgrade_threats',
    'move_multi_agent_threats',
    'move_resource_account_threats',
    'ripple_general_threats',
    'ripple_payment_threats',
    'ripple_trustline_threats',
    'ripple_escrow_threats',
    'ripple_payment_channel_threats',
    'ripple_account_security_threats',
    'ripple_offer_threats',
    'ripple_transaction_validation_threats',
    'ripple_amendment_threats',
    
    # Programming Language Threats
    'python_general_threats',
    'python_web_threats',
    'python_data_threats',
    'cpp_general_threats',
    'cpp_memory_threats',
    'cpp_concurrency_threats',
    'c_general_threats',
    'c_memory_threats',
    'rust_general_threats',
    'java_general_threats',
    'javascript_general_threats',
    'typescript_general_threats',
    'typescript_web3_wallet_threats',
    'typescript_sdk_threats',
    'go_general_threats',
    'go_graphql_threats',
    'go_p2p_threats',
    'go_ethereum_threats',
    'go_http_threats',
    'go_database_threats',
    'go_cryptography_threats',
    'go_concurrency_threats',
    'php_general_threats',
    'scala_general_threats',
    
    # Framework Threats
    'nextjs_general_threats',
    'nextjs_api_threats',
    'nextjs_component_threats',
    'django_general_threats',
    'django_orm_threats',
    'react_native_general_threats',
    'express_general_threats',
    'fastapi_general_threats',
    'springboot_general_threats',
    'rails_general_threats',
    'nestjs_general_threats',
    'nestjs_controller_threats',
    'nestjs_service_threats',
    'nestjs_guard_threats',
    
    # Cryptography Threats
    'general_cryptography_threats',
    'random_number_generation_threats',
    'key_management_threats',
    'aes_implementation_threats',
    'aes_key_management_threats',
    'aes_padding_threats',
    'shamir_scheme_threats',
    'shamir_threshold_threats',
    'shamir_share_management_threats',
    'mpc_protocol_threats',
    'mpc_threshold_threats',
    'mpc_party_threats',
    'ecdsa_implementation_threats',
    'ecdsa_nonce_threats',
    'ecdsa_curve_threats',
    'hash_function_threats',
    'password_hashing_threats',
    'hash_collision_threats',
    'rsa_implementation_threats',
    'rsa_key_management_threats',
    'rsa_padding_threats',
    'ssl_tls_threats',
    'handshake_threats',
    'protocol_downgrade_threats',
    'javacard_applet_threats',
    'javacard_apdu_threats',
    'javacard_secure_channel_threats',
    
    # Web Security Threats
    'owasp_top10_threats',
    'api_security_threats',
    'xss_security_threats',
    'csrf_security_threats',
    'sql_injection_threats',
    'session_security_threats',
    'authentication_authorization_threats',
    'file_upload_security_threats',
    
    # Infrastructure Threats
    'container_security_threats',
    'cloud_security_threats',
    'cdk_general_threats',
    'cdk_iam_threats',
    'cdk_network_threats',
    'cdk_storage_threats',
    'cdk_lambda_threats',
    
    # AI/ML Threats
    'adversarial_attack_threats',
    'model_poisoning_threats',
    
    # IoT and Mobile Threats
    'iot_security_threats',
    'mobile_security_threats',
    
    # Network and Data Threats
    'network_security_threats',
    'data_privacy_threats',
    
    # Rust Threats
    'rust_general_threats',
    'rust_kms_threats',
    'rust_web_threats',
    'rust_ecdsa_threats',
    'rust_general_crypto_threats',
    'rust_tss_threats',
    'rust_mpc_threats',

]