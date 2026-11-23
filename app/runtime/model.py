"""Create the shared chat model from explicit runtime settings."""
from app.runtime.config import ConfigurationError, Settings


def create_model(settings: Settings):
    if not settings.model_name:
        raise ConfigurationError("Set VULNFORGE_MODEL before running model-backed agents.")
    from langchain_openai import ChatOpenAI
    options = {
        "model": settings.model_name,
        "temperature": 0,
        "timeout": 60,
        "max_retries": 0,
    }
    if settings.model_base_url:
        options["base_url"] = settings.model_base_url
    if settings.model_api_key:
        options["api_key"] = settings.model_api_key
    return ChatOpenAI(**options)
