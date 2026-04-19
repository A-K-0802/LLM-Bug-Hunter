import os
from pathlib import Path
import dotenv
from langchain_huggingface import HuggingFaceEndpoint
from langchain_community.llms import Ollama
from groq import Groq
dotenv.load_dotenv(dotenv_path=Path(__file__).with_name(".env"))

# def get_analyser():
#     # api_key = os.getenv("HUGGINGFACE_API_KEY")
#     # if not api_key:
#     #     raise RuntimeError("Set HUGGINGFACE_API_KEY in .env before running the agent.")

#     # return HuggingFaceEndpoint(
#     #     model="HuggingFaceH4/zephyr-7b-beta",
#     #     task="text-generation",
#     #     provider="hf-inference",
#     #     temperature=0.3,
#     #     max_new_tokens=512,
#     #     huggingfacehub_api_token=api_key,
#     # )
#     return Ollama(
#         model="phi",
#         temperature=0.1
#     )

# def get_planner():
#     # api_key = os.getenv("HUGGINGFACE_API_KEY")
#     # if not api_key:
#     #     raise RuntimeError("Set HUGGINGFACE_API_KEY in .env before running the agent.")

#     # return HuggingFaceEndpoint(
#     #     model="HuggingFaceH4/zephyr-7b-beta",
#     #     task="text-generation",
#     #     provider="hf-inference",
#     #     temperature=0.3,
#     #     max_new_tokens=512,
#     #     huggingfacehub_api_token=api_key,
#     # )
#     return Ollama(
#         model="phi",
#         temperature=0.1
#     )


client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def call_llm(prompt: str, system: str = "") -> str:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=messages,
        temperature=0.1,
        max_tokens=1024,
    )
    content = response.choices[0].message.content
    return content if content is not None else ""

def get_planner():
    return call_llm

def get_analyser():
    return call_llm