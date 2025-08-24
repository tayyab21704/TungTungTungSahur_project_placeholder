from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from app.services.aws_tools import get_all_aws_tools
from typing import Dict, Any
from dotenv import load_dotenv

# ---------------------------
# State
# ---------------------------
class State(dict):
    user_query: str
    plan: str
    confirmed_plan: bool = False
    tool_call: Dict[str, Any]
    final_answer: str


# ---------------------------
# LLM
# ---------------------------
load_dotenv()

llm = ChatGroq(
    model="llama3-70b-8192",  # choose Groq model
    temperature=0
)


# ---------------------------
# Nodes
# ---------------------------
def prepare_plan(state: State):
    """LLM prepares a plan."""
    query = state["user_query"]
    plan = llm.invoke(f"Prepare a plan to solve this user query: {query}")
    return {"plan": plan.content, "confirmed_plan": False}


def confirm_plan(state: State):
    """Human validation of plan (HITL)."""
    print(f"\n--- LLM Proposed Plan ---\n{state['plan']}\n")
    confirm = input("Do you approve this plan? (yes/no): ")
    if confirm.strip().lower() == "yes":
        return {"confirmed_plan": True}
    else:
        return {"confirmed_plan": False}


def validate_tool_call(state: State):
    """Before executing tool, ask for human validation (HITL)."""
    print(f"\n--- Tool Call Proposed ---\n{state['tool_call']}\n")
    confirm = input("Execute this tool call? (yes/no): ")
    if confirm.strip().lower() != "yes":
        raise Exception("Tool call rejected by human.")
    return {}


def call_tool(state: State):
    """Execute the tool call."""
    tool_call = state["tool_call"]
    tool = tool_call["tool"]
    args = tool_call["args"]

    result = tool.invoke(args)
    return {"final_answer": str(result)}


# ---------------------------
# Graph Construction
# ---------------------------
def build_graph():
    tools = get_all_aws_tools()

    graph = StateGraph(State)

    # Add nodes
    graph.add_node("prepare_plan", prepare_plan)
    graph.add_node("confirm_plan", confirm_plan)
    graph.add_node("validate_tool_call", validate_tool_call)
    graph.add_node("call_tool", call_tool)

    # Define edges
    graph.set_entry_point("prepare_plan")
    graph.add_edge("prepare_plan", "confirm_plan")
    graph.add_edge("confirm_plan", "validate_tool_call")
    graph.add_edge("validate_tool_call", "call_tool")
    graph.add_edge("call_tool", END)

    return graph.compile()
