"""Small shared wrapper for schema-validated model calls."""
import json
from typing import TypeVar

from pydantic import BaseModel


ResultT = TypeVar("ResultT", bound=BaseModel)


class AgentRunner:
    def __init__(self, model):
        self._model = model

    def run(self, *, agent_name: str, instructions: str, input_text: str,
            result_schema: type[ResultT]) -> ResultT:
        structured_model = self._model.with_structured_output(result_schema)
        messages = [
            ("system", f"You are the VulnForge {agent_name}. {instructions}"),
            ("human", input_text),
        ]
        try:
            result = structured_model.invoke(messages)
        except Exception as exc:
            message = str(exc).casefold()
            if "response_format" not in message or "unavailable" not in message:
                raise
            structured_model = self._model.with_structured_output(
                result_schema, method="function_calling"
            )
            try:
                result = structured_model.invoke(messages)
            except Exception as fallback_exc:
                fallback_message = str(fallback_exc).casefold()
                if "tool_choice" not in fallback_message or "not support" not in fallback_message:
                    raise
                structured_model = self._model.with_structured_output(
                    result_schema, method="json_mode"
                )
                schema_json = json.dumps(
                    result_schema.model_json_schema(), ensure_ascii=False
                )
                json_messages = [
                    ("system", messages[0][1] + "\n\n"
                     "Return only a valid JSON object that follows this exact schema. "
                     "Do not add fields or use an alternative schema.\n" + schema_json),
                    messages[1],
                ]
                result = structured_model.invoke(json_messages)
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
