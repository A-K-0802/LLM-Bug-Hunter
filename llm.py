import os
from pathlib import Path

import dotenv
from langchain_huggingface import HuggingFaceEndpoint

dotenv.load_dotenv(dotenv_path=Path(__file__).with_name(".env"))

def get_llm():
    api_key = os.getenv("HUGGINGFACE_API_KEY")
    if not api_key:
        raise RuntimeError("Set HUGGINGFACE_API_KEY in .env before running the agent.")

    return HuggingFaceEndpoint(
        model="google/flan-t5-large",
        task="text2text-generation",
        temperature=0.3,
        max_new_tokens=512,
        huggingfacehub_api_token=api_key,
    )