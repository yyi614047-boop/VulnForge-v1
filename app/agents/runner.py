"""Small shared wrapper for schema-validated model calls."""
from typing import TypeVar

from pydantic import BaseModel


ResultT = TypeVar("ResultT", bound=BaseModel)


class AgentRunner:
    def __init__(self, model):
        self._model = model

    def run(self, *, agent_name: str, instructions: str, input_text: str,
            result_schema: type[ResultT]) -> ResultT:
        structured_model = self._model.with_structured_output(result_schema)
        result = structured_model.invoke([
            ("system", f"You are the VulnForge {agent_name}. {instructions}"),
            ("human", input_text),
        ])
        if isinstance(result, result_schema):
            return result
        return result_schema.model_validate(result)

    def run_text(self, *, agent_name: str, instructions: str,
                 input_content: str | list[dict]) -> str:
        result = self._model.invoke([
            ("system", f"You are the VulnForge {agent_name}. {instructions}"),
            ("human", input_content),
        ])
        content = getattr(result, "content", result)
        if not isinstance(content, str) or not content.strip():
            raise ValueError(f"{agent_name} must return non-empty text.")
        return content.strip()
