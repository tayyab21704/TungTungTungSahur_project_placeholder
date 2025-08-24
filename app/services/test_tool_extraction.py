import json
import re
from typing import List
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
import os

# -----------------------------
# Load API Key
# -----------------------------
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise ValueError("❌ GROQ_API_KEY not found in environment. Please set it in your .env file.")

# -----------------------------
# Available Tools
# -----------------------------
tools = [
    "create_s3_bucket",
    "launch_ec2_instance",
    "delete_s3_bucket",
    "list_ec2_instances"
]

# Example AI-generated plan (text)
ai_plan_text = """
 Create a storage bucket in Mumbai for logs.
 Launch a small EC2 instance (t2.micro) in Mumbai for batch jobs.
"""

# -----------------------------
# Initialize LLM
# -----------------------------
llm = ChatGroq(model="llama3-8b-8192")

# -----------------------------
# Prompt
# -----------------------------
tool_name_prompt = ChatPromptTemplate.from_messages([
    ("system",
     "You are a tool selector. Your job is to read an AI-generated plan "
     "and choose the correct tools from the available list.\n\n"
     "Return only a list of tool names. Text only, no extra explanation.\n"
     "Tools must be from the available list."),
    ("user", "AI Plan:\n{plan_text}\n\nAvailable tools:\n{tools_list}")
])


def extract_tool_names_from_text_plan(plan_text: str, tools_list: List[str]) -> List[str]:
    """
    Extract tool names required for the AI-generated text plan.
    Handles text response from LLM and returns a clean list of strings.
    """
    # Call LLM
    response = tool_name_prompt | llm
    raw_message = response.invoke({
        "plan_text": plan_text,
        "tools_list": json.dumps(tools_list, indent=2)
    })

    # Access the text content
    raw_text = raw_message.content if hasattr(raw_message, "content") else str(raw_message)

    # -----------------------------
    # Extract tool names from text
    # -----------------------------
    tool_names = []
    try:
        # Try parsing JSON if LLM returned JSON
        tool_names = json.loads(raw_text)
        if isinstance(tool_names, str):
            tool_names = [tool_names]
    except Exception:
        # Fallback: regex to extract names matching available tools
        for tool in tools_list:
            if re.search(rf"\b{re.escape(tool)}\b", raw_text, re.IGNORECASE):
                tool_names.append(tool)

    # Deduplicate
    return list(dict.fromkeys(tool_names))
# -----------------------------
# Run Example
# -----------------------------
if __name__ == "__main__":
    extracted_tools = extract_tool_names_from_text_plan(ai_plan_text, tools)
    print("✅ Extracted tool names:", extracted_tools)
