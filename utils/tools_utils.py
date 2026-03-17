from threat_modeling_tools import *
import inspect
from typing import Dict, List, Any

def list_tools():
    """Get list of threat modeling tools"""
    tools = []
    globals_imports = globals()

    for name, value in globals_imports.items():
        if '_threats' in name:
            tools.append(name)
    tools = list(set(tools))
    tools.sort()
    return tools

def get_tool_category(tool_name: str) -> str:
    """Map tool name to logical category based on tool structure"""
    tool_lower = tool_name.lower()
    
    # Blockchain category
    if (tool_lower.startswith('solidity_') or 
        tool_lower.startswith('defi_') or 
        tool_lower.startswith('amm_') or
        tool_lower.startswith('l1_') or 
        tool_lower.startswith('l2_') or 
        tool_lower.startswith('solana_') or 
        tool_lower.startswith('substrate_') or 
        tool_lower.startswith('near_') or 
        tool_lower.startswith('cosmos_') or 
        tool_lower.startswith('avalanche_') or
        tool_lower.startswith('tendermint_') or
        tool_lower.startswith('ibc_')):
        return 'Blockchain'
    
    # Programming Languages category
    if (tool_lower.startswith('python_') or 
        tool_lower.startswith('scala_') or 
        tool_lower.startswith('cpp_') or 
        (tool_lower.startswith('c_') and not tool_lower.startswith('cdk_') and not tool_lower.startswith('cosmos_')) or 
        tool_lower.startswith('rust_') or 
        tool_lower.startswith('javascript_') or  # Check before java_ to avoid matching
        tool_lower.startswith('java_') or 
        tool_lower.startswith('typescript_') or 
        tool_lower.startswith('go_') or 
        tool_lower.startswith('php_')):
        return 'Programming Languages'
    
    # Frameworks category
    if (tool_lower.startswith('nextjs_') or 
        tool_lower.startswith('django_') or 
        tool_lower.startswith('react_native_') or 
        tool_lower.startswith('express_') or 
        tool_lower.startswith('fastapi_') or 
        tool_lower.startswith('springboot_') or 
        tool_lower.startswith('rails_') or 
        tool_lower.startswith('nestjs_')):
        return 'Frameworks'
    
    # Cryptography category
    if (tool_lower.startswith('general_cryptography_') or 
        tool_lower.startswith('random_number_generation_') or 
        tool_lower.startswith('key_management_') or
        tool_lower.startswith('aes_') or 
        tool_lower.startswith('shamir_') or 
        tool_lower.startswith('mpc_') or 
        tool_lower.startswith('ecdsa_') or 
        tool_lower.startswith('hash_') or 
        tool_lower.startswith('rsa_') or 
        tool_lower.startswith('ssl_') or 
        tool_lower.startswith('tls_') or
        tool_lower.startswith('handshake_') or
        tool_lower.startswith('protocol_') or
        tool_lower.startswith('javacard_')):
        return 'Cryptography'
    
    # Web Security category
    if (tool_lower.startswith('owasp_') or 
        tool_lower.startswith('api_security_') or 
        tool_lower.startswith('xss_') or 
        tool_lower.startswith('csrf_') or 
        tool_lower.startswith('sql_') or 
        tool_lower.startswith('session_') or 
        tool_lower.startswith('authentication_') or 
        tool_lower.startswith('file_upload_')):
        return 'Web Security'
    
    # Infrastructure category
    if (tool_lower.startswith('container_') or 
        tool_lower.startswith('cloud_') or 
        tool_lower.startswith('cdk_')):
        return 'Infrastructure'
    
    # AI/ML category
    if (tool_lower.startswith('adversarial_') or 
        tool_lower.startswith('model_poisoning_')):
        return 'AI/ML'
    
    # IoT/Mobile category
    if (tool_lower.startswith('iot_') or 
        tool_lower.startswith('mobile_')):
        return 'IoT/Mobile'
    
    # Network/Data category
    if (tool_lower.startswith('network_') or 
        tool_lower.startswith('data_privacy_')):
        return 'Network/Data'
    
    # Default fallback
    return 'Other'

def get_tool_metadata(tool_name: str) -> Dict[str, Any]:
    """Get metadata for a specific threat modeling tool"""
    try:
        globals_imports = globals()
        if tool_name not in globals_imports:
            return {}
        
        tool_func = globals_imports[tool_name]
        
        # Get function signature and docstring
        sig = inspect.signature(tool_func)
        docstring = inspect.getdoc(tool_func) or ""
        
        # Use improved categorization
        category = get_tool_category(tool_name)
        
        # Extract subcategory
        parts = tool_name.split('_')
        if len(parts) > 1:
            subcategory = '_'.join(parts[1:-1]).replace('_', ' ').title()
        else:
            subcategory = 'General'
        
        # Get parameter information
        params = []
        for param_name, param in sig.parameters.items():
            if hasattr(param.annotation, '__metadata__'):
                # Extract description from Annotated type
                description = param.annotation.__metadata__[0] if param.annotation.__metadata__ else ""
            else:
                description = str(param.annotation) if param.annotation != inspect.Parameter.empty else ""
            
            params.append({
                'name': param_name,
                'type': str(param.annotation) if param.annotation != inspect.Parameter.empty else "Any",
                'description': description,
                'required': param.default == inspect.Parameter.empty
            })
        
        return {
            'name': tool_name,
            'display_name': ' '.join(word.capitalize() for word in tool_name.replace('_', ' ').split()),
            'category': category,
            'subcategory': subcategory,
            'description': docstring.split('\n')[0] if docstring else f"Security analysis tool for {tool_name.replace('_', ' ').lower()} threats and vulnerabilities.",
            'full_docstring': docstring,
            'parameters': params,
            'is_async': inspect.iscoroutinefunction(tool_func),
            'module': tool_func.__module__ if hasattr(tool_func, '__module__') else 'unknown'
        }
    except Exception as e:
        return {
            'name': tool_name,
            'display_name': ' '.join(word.capitalize() for word in tool_name.replace('_', ' ').split()),
            'category': 'Unknown',
            'subcategory': 'General',
            'description': f"Security analysis tool for {tool_name.replace('_', ' ').lower()} threats and vulnerabilities.",
            'error': str(e)
        }

def get_all_tools_metadata() -> List[Dict[str, Any]]:
    """Get metadata for all threat modeling tools"""
    tools = list_tools()
    return [get_tool_metadata(tool) for tool in tools]

def get_tools_by_category() -> Dict[str, List[Dict[str, Any]]]:
    """Get tools organized by category"""
    tools_metadata = get_all_tools_metadata()
    categorized = {}
    
    for tool in tools_metadata:
        category = tool.get('category', 'Other')
        if category not in categorized:
            categorized[category] = []
        categorized[category].append(tool)
    
    return categorized


