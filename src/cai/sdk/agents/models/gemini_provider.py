from __future__ import annotations

import os
from .interface import Model, ModelProvider

# You may need to install google-generativeai: pip install google-generativeai
import google.generativeai as genai
from openai.types.responses.response_output_message import ResponseOutputMessage
from openai.types.responses.response_output_text import ResponseOutputText
from ..usage import Usage

DEFAULT_MODEL: str = "gemini-1.5-pro"

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

class GeminiChatCompletionsModel(Model):
    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.client = genai.GenerativeModel(self.model)

    async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs, tracing):
        import asyncio
        loop = asyncio.get_event_loop()
        prompt = system_instructions or ""
        if isinstance(input, list):
            prompt += "\n" + "\n".join(str(i) for i in input)
        else:
            prompt += "\n" + str(input)
        def call_gemini():
            response = self.client.generate_content(prompt)
            # Extract text from Gemini response
            text = ""
            if hasattr(response, 'candidates') and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'content') and hasattr(candidate.content, 'parts') and candidate.content.parts:
                    text = candidate.content.parts[0].text
            return text
        text = await loop.run_in_executor(None, call_gemini)
        # Build output as a list of ResponseOutputMessage with a ResponseOutputText
        output = [
            ResponseOutputMessage(
                content=[ResponseOutputText(text=text, type="output_text", annotations=[])],
                role="assistant"
            )
        ]
        from ..items import ModelResponse
        usage = Usage()  # Minimal usage, can be improved with token counting
        return ModelResponse(output=output, usage=usage, referenceable_id=None)

    def stream_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs, tracing):
        import asyncio
        async def _stream():
            resp = await self.get_response(system_instructions, input, model_settings, tools, output_schema, handoffs, tracing)
            yield resp
        return _stream()

class GeminiProvider(ModelProvider):
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")

    def get_model(self, model_name: str | None) -> Model:
        if model_name is None:
            model_name = DEFAULT_MODEL
        return GeminiChatCompletionsModel(model=model_name, api_key=self.api_key) 