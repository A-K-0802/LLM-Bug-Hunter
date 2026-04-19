import os
from pathlib import Path

import dotenv
from langchain_huggingface import HuggingFaceEndpoint
from langchain_community.llms import Ollama

dotenv.load_dotenv(dotenv_path=Path(__file__).with_name(".env"))

def get_analyser():
    # api_key = os.getenv("HUGGINGFACE_API_KEY")
    # if not api_key:
    #     raise RuntimeError("Set HUGGINGFACE_API_KEY in .env before running the agent.")

    # return HuggingFaceEndpoint(
    #     model="HuggingFaceH4/zephyr-7b-beta",
    #     task="text-generation",
    #     provider="hf-inference",
    #     temperature=0.3,
    #     max_new_tokens=512,
    #     huggingfacehub_api_token=api_key,
    # )
    return Ollama(
        model="phi",
        temperature=0.1
    )

def get_planner():
    # api_key = os.getenv("HUGGINGFACE_API_KEY")
    # if not api_key:
    #     raise RuntimeError("Set HUGGINGFACE_API_KEY in .env before running the agent.")

    # return HuggingFaceEndpoint(
    #     model="HuggingFaceH4/zephyr-7b-beta",
    #     task="text-generation",
    #     provider="hf-inference",
    #     temperature=0.3,
    #     max_new_tokens=512,
    #     huggingfacehub_api_token=api_key,
    # )
    return Ollama(
        model="phi",
        temperature=0.1
    )