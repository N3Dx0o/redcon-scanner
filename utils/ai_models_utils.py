
import os
import re
import requests
from functools import lru_cache
from typing import List, Dict, Any, Optional
from db.models import AIModel

AI_KEYS_MAPPING = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "xai": "XAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "larprouter": "LARPROUTER_API_KEY",
}


def init_models_env(models: list[AIModel]):
    """
    Initialize environment variables for AI models.
    For Ollama models, sets OLLAMA_API_BASE if OLLAMA_BASE_URL is configured.
    """
    for model in models:
        vendor = model.vendor.lower()
        # Ollama doesn't require an API key, but we should set the base URL if configured
        if vendor == 'ollama':
            # Set OLLAMA_API_BASE for LiteLLM if OLLAMA_BASE_URL is set in environment
            ollama_base_url = os.getenv('OLLAMA_BASE_URL', os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434/'))
            os.environ['OLLAMA_API_BASE'] = ollama_base_url
            continue
        if vendor not in AI_KEYS_MAPPING:
            raise ValueError(f"Unsupported vendor: {vendor}")
        os.environ[AI_KEYS_MAPPING[vendor]] = model.api_key


def get_supported_vendors():
    return list(AI_KEYS_MAPPING.keys())


def format_model_name_for_litellm(model) -> str:
    """
    Format model name for LiteLLM API calls.
    
    Args:
        model: AIModel instance with vendor and model_name attributes
        
    Returns:
        Formatted model name string for LiteLLM (e.g., 'ollama/llama2', 'openai/gpt-4')
    """
    vendor = model.vendor.lower() if hasattr(model.vendor, 'lower') else str(model.vendor).lower()
    model_name = model.model_name
    
    # Special handling for vendors that need specific formatting
    if vendor == 'larprouter':
        return f"openai/{model_name}?api_base={LARPROUTER_BASE_URL}"
    if vendor == 'gemini':
        return f"gemini/{model_name}"
    elif vendor == 'ollama':
        return f"ollama/{model_name}?api_base={os.getenv('OLLAMA_API_BASE')}"
    else:
        # Default format: vendor/model_name
        return f"{vendor}/{model_name}"


def fetch_litellm_models() -> Optional[Dict[str, Any]]:
    """Fetch model data from LiteLLM repository"""
    try:
        response = requests.get(
            "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json",
            timeout=100
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[WARNING] Failed to fetch LiteLLM model data: {e}")
        return None


def validate_api_key(vendor: str, api_key: str) -> bool:
    """Validate API key format and basic structure without making expensive API calls"""
    try:
        # Basic API key validation by vendor
        if vendor == 'larprouter':
            return api_key.startswith('lrsk-') and 20 <= len(api_key) <= 200
        if vendor == 'openai':
            # OpenAI keys start with 'sk-' and are typically 48+ characters
            return api_key.startswith('sk-') and len(api_key) >= 48
        
        elif vendor == 'anthropic':
            # Anthropic keys start with 'sk-ant-' and are typically 50+ characters
            return api_key.startswith('sk-ant-') and len(api_key) >= 50
        
        elif vendor == 'gemini':
            # Google API keys are typically 39 characters and alphanumeric
            return len(api_key) == 39 and api_key.replace('-', '').replace('_', '').isalnum()
        
        elif vendor == 'xai':
            # xAI keys typically start with 'xai-' and are 40+ characters
            return api_key.startswith('xai-') and len(api_key) >= 40
        
        elif vendor == 'deepseek':
            # DeepSeek keys are typically 40+ characters and alphanumeric
            return len(api_key) >= 40 and api_key.replace('-', '').replace('_', '').isalnum()
        
        else:
            # For unknown vendors, just check if key is not empty and reasonable length
            return len(api_key) >= 20 and len(api_key) <= 200
            
    except Exception as e:
        print(f"[ERROR] API key validation failed for vendor {vendor}: {str(e)}")
        return False


def filter_suitable_models_for_vendor(models_data: Dict[str, Any], vendor: str, api_key: str) -> List[Dict[str, Any]]:
    """Filter models suitable for security analysis for a specific vendor"""
    suitable_models = []
    
    # Define vendor mapping
    vendor_mapping = {
        'openai': 'openai',
        'anthropic': 'anthropic', 
        'google': 'gemini',
        'gemini': 'gemini',
        'xai': 'xai',
        'deepseek': 'deepseek',
        'bedrock': 'anthropic',  # AWS Bedrock Anthropic models
        'bedrock_converse': 'anthropic',  # AWS Bedrock Anthropic models
    }
    
    # Map our vendor names to LiteLLM provider names
    provider_mapping = {
        'openai': 'openai',
        'anthropic': 'anthropic',
        'gemini': 'google',  # Gemini uses 'google' as provider in LiteLLM
        'xai': 'xai',
        'deepseek': 'deepseek',
    }
    
    target_provider = provider_mapping.get(vendor)
    if not target_provider:
        return []
    
    for model_key, model_data in models_data.items():
        # Skip the sample_spec entry
        if model_key == 'sample_spec':
            continue
        
        # Check if this model belongs to our target vendor
        litellm_provider = model_data.get('litellm_provider')
        if litellm_provider not in vendor_mapping:
            continue
        
        mapped_vendor = vendor_mapping.get(litellm_provider)
        if mapped_vendor != vendor:
            continue
            
        # Filter criteria for security analysis
        if not (
            model_data.get('mode') == 'chat' and
            model_data.get('supports_function_calling', False) and
            model_data.get('max_input_tokens', 0) >= 100000 and  # Large context window
            litellm_provider == target_provider
        ):
            continue
        
        # Extract model name (remove vendor prefix if present)
        model_name = model_key
        if '/' in model_key:
            model_name = model_key.split('/', 1)[1]
        elif '.' in model_key:
            # For models like "anthropic.claude-3-5-sonnet-20241022-v1:0"
            parts = model_key.split('.')
            if len(parts) > 1:
                model_name = '.'.join(parts[1:])
        
        # Skip models that contain date patterns in their names
        date_pattern = re.compile(r'\d{4}-\d{2}-\d{2}|\d{8}|\d{6}|\d{4}')
        if date_pattern.search(model_name):
            continue
        
        if len(model_name) == 1:
            continue
        
        if '-preview' in model_name:
            continue
        
        if '-nano' in model_name:
            continue
        
        if '-mini' in model_name:
            continue
        
        if '-flash' in model_name:
            continue
        if '-exp-' in model_name:
            continue
        if '-audio-' in model_name:
            continue
        
        suitable_models.append({
            'model_name': model_name,
            'vendor': vendor,
            'api_key': api_key,
            'max_tokens': model_data.get('max_input_tokens', 0),
            'supports_function_calling': model_data.get('supports_function_calling', False),
            'supports_vision': model_data.get('supports_vision', False),
            'supports_reasoning': model_data.get('supports_reasoning', False),
            'cost_per_token': model_data.get('input_cost_per_token', 0),
        })
    
    # Sort by max_tokens descending, then by cost ascending
    suitable_models.sort(key=lambda x: (-x['max_tokens'], x['cost_per_token']))
    
    return suitable_models


def discover_ollama_models(ollama_base_url: str = "http://192.168.1.10:11434/") -> Optional[List[str]]:
    """
    Discover available Ollama models by querying the local Ollama API.
    Returns a list of model names, or None if Ollama is not available.
    """
    try:
        response = requests.get(
            f"{ollama_base_url}/api/tags",
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        
        # Extract model names from the response
        models = []
        if 'models' in data:
            for model_info in data['models']:
                model_name = model_info.get('name', '')
                if model_name:
                    models.append(model_name)
        
        return models if models else None
        
    except requests.exceptions.RequestException as e:
        # Ollama is not running or not accessible
        return None
    except Exception as e:
        print(f"[WARNING] Error discovering Ollama models: {e}")
        return None


def discover_and_add_ollama_models(orm, session, ollama_base_url: str = "http://192.168.1.10:11434/") -> Dict[str, Any]:
    """
    Discover and add all available Ollama models to the database.
    Returns a dict with 'successful_models' and 'failed_models' lists.
    """
    # Discover available models
    model_names = discover_ollama_models(ollama_base_url)
    
    if not model_names:
        return {
            'successful_models': [],
            'failed_models': [],
            'error': 'Ollama is not running or no models are available'
        }
    
    # Ollama doesn't require an API key, use empty string
    vendor = 'ollama'
    api_key = ''  # Ollama doesn't use API keys for local instances
    
    # Add models to database (skip if already exists)
    successful_models = []
    failed_models = []
    
    for model_name in model_names:
        existing = session.query(AIModel).filter_by(
            model_name=model_name,
            vendor=vendor
        ).first()
        
        if not existing:
            try:
                basic_model_data = {
                    'model_name': model_name,
                    'vendor': vendor,
                    'api_key': api_key
                }
                orm.create(session, AIModel, **basic_model_data)
                successful_models.append(model_name)
            except Exception as e:
                print(f"[ERROR] Failed to create Ollama model {model_name}: {e}")
                failed_models.append(model_name)
        else:
            # Model already exists, skip
            successful_models.append(model_name)
    
    return {
        'successful_models': successful_models,
        'failed_models': failed_models,
        'error': None
    }


def discover_and_add_models_for_vendor(orm, session, vendor: str, api_key: str, owner_id=None) -> Dict[str, Any]:
    """
    Discover and add all suitable models for a given vendor and API key.
    Returns a dict with 'successful_models' and 'failed_models' lists.
    """
    # Validate API key format first
    if not validate_api_key(vendor, api_key):
        return {
            'successful_models': [],
            'failed_models': [],
            'error': f'Invalid API key format for vendor {vendor}'
        }
    
    if vendor == 'larprouter':
        return discover_larprouter_models(orm, session, api_key, owner_id)

    # Temporarily set the API key in environment for filtering
    env_var = AI_KEYS_MAPPING.get(vendor)
    if not env_var:
        return {
            'successful_models': [],
            'failed_models': [],
            'error': f'Unsupported vendor: {vendor}'
        }
    
    original_key = os.environ.get(env_var)
    os.environ[env_var] = api_key
    
    try:
        # Fetch models from LiteLLM
        models_data = fetch_litellm_models()
        if not models_data:
            return {
                'successful_models': [],
                'failed_models': [],
                'error': 'Failed to fetch model data from LiteLLM'
            }
        
        # Filter suitable models for this vendor
        suitable_models = filter_suitable_models_for_vendor(models_data, vendor, api_key)
        
        if not suitable_models:
            return {
                'successful_models': [],
                'failed_models': [],
                'error': f'No suitable models found for vendor {vendor}'
            }
        
        # Add models to database (skip if already exists)
        successful_models = []
        failed_models = []
        
        for model_data in suitable_models:
            existing = session.query(AIModel).filter_by(
                model_name=model_data['model_name'],
                vendor=model_data['vendor'],
                api_key=model_data['api_key']
            ).first()
            
            if not existing:
                try:
                    basic_model_data = {
                        'model_name': model_data['model_name'],
                        'vendor': model_data['vendor'],
                        'api_key': model_data['api_key']
                    }
                    orm.create(session, AIModel, **basic_model_data)
                    successful_models.append(model_data['model_name'])
                except Exception as e:
                    print(f"[ERROR] Failed to create model {model_data['model_name']}: {e}")
                    failed_models.append(model_data['model_name'])
            else:
                # Update API key if model already exists
                existing.api_key = api_key
                orm.update(session, existing)
                successful_models.append(model_data['model_name'])
        
        return {
            'successful_models': successful_models,
            'failed_models': failed_models,
            'error': None
        }
    
    finally:
        # Restore original API key
        if original_key:
            os.environ[env_var] = original_key
        else:
            os.environ.pop(env_var, None)




LARPROUTER_BASE_URL = "https://larprouter.com/v1"


def model_completion_options(model):
    """Keep gateway credentials scoped to the individual request."""
    if model.vendor.lower() == "larprouter":
        catalog = load_larprouter_catalog(model.api_key)
        entry = next((item for item in catalog if item.get("id") == model.model_name), None)
        if not entry or "pricing" not in entry:
            raise ValueError("LarpRouter did not publish pricing for this model; refresh the model list.")
        pricing = entry["pricing"]
        return {
            "model": f"openai/{model.model_name}",
            "api_base": LARPROUTER_BASE_URL,
            "api_key": model.api_key,
            "extra_headers": {"User-Agent": "REDCON-HAWK/1.0"},
            "timeout": 90,
            "num_retries": 2,
            "input_cost_per_token": float(pricing["input_per_1m_usd"]) / 1_000_000,
            "output_cost_per_token": float(pricing["output_per_1m_usd"]) / 1_000_000,
        }
    return {"model": format_model_name_for_litellm(model)}


async def create_model_agent(model, generator, configuration, **kwargs):
    """Apply per-agent gateway settings without overriding another provider's key."""
    from nerve.runtime.agent import Agent
    agent = await Agent.create(generator, configuration, **kwargs)
    if model.vendor.lower() == "larprouter":
        options = model_completion_options(model)
        options.pop("model")
        options.pop("api_base")
        agent.generation_engine.generator_params.update(options)
    return agent


def discover_larprouter_models(orm, session, api_key, owner_id=None):
    """Discover the key's live catalog, including Flash models."""
    result = {"successful_models": [], "failed_models": [], "error": None}
    try:
        load_larprouter_catalog.cache_clear()
        catalog = load_larprouter_catalog(api_key)
        for item in catalog:
            if item.get("kind", "chat") != "chat" or not item.get("id"):
                continue
            name = item["id"]
            existing = session.query(AIModel).filter_by(
                vendor="larprouter", model_name=name, owner_id=owner_id,
            ).first()
            if existing:
                existing.api_key = api_key
            else:
                session.add(AIModel(model_name=name, vendor="larprouter", api_key=api_key, owner_id=owner_id))
            result["successful_models"].append(name)
        if not result["successful_models"]:
            result["error"] = "LarpRouter returned no chat models for this key."
        session.flush()
    except requests.RequestException:
        result["error"] = "Could not reach LarpRouter. Please try again shortly."
    except (ValueError, TypeError, KeyError):
        result["error"] = "LarpRouter returned an invalid catalog or rejected the key. Check your account and retry."
    return result


@lru_cache(maxsize=32)
def load_larprouter_catalog(api_key):
    """Cache public model metadata per key for this process; never persist secrets."""
    response = requests.get(
        LARPROUTER_BASE_URL + "/models",
        headers={"Authorization": "Bearer " + api_key, "User-Agent": "REDCON-HAWK/1.0"},
        timeout=20,
    )
    if response.status_code != 200:
        raise ValueError(f"LarpRouter model discovery failed (HTTP {response.status_code}).")
    catalog = response.json().get("data")
    if not isinstance(catalog, list) or not all(isinstance(item, dict) for item in catalog):
        raise ValueError("Invalid model catalog")
    return catalog
