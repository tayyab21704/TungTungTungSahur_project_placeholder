from typing import Dict, Any, List, Optional
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from pydantic import BaseModel
import json
import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from app.services.aws_tools import get_all_aws_tools
from app.utils.logging_decorator import logging_decorator

load_dotenv()

class GraphState(BaseModel):
    messages: List[BaseMessage] = []
    plan: Optional[str] = None
    tool_calls: List[Dict[str, Any]] = []
    current_tool_index: int = 0
    requires_validation: bool = False
    session_id: str = ""
    user_inputs: Dict[str, Any] = {}
    execution_results: List[Dict[str, Any]] = []

class AWSWorkflowGraph:
    def __init__(self):
        self.tools = get_all_aws_tools()
        self.llm = ChatGroq(
            temperature=0,
            groq_api_key=os.getenv("GROQ_API_KEY"),
            model_name="llama3-8b-8192"
        )
        self.graph = self._build_graph()
    
    @logging_decorator
    def _build_graph(self):
        workflow = StateGraph(GraphState)
        
        # Add nodes
        workflow.add_node("plan_creation", self.create_plan)
        workflow.add_node("tool_validation", self.validate_tools)
        workflow.add_node("tool_execution", self.execute_tools)
        workflow.add_node("completion", self.complete_workflow)
        
        # Add edges
        workflow.set_entry_point("plan_creation")
        workflow.add_conditional_edges(
            "plan_creation",
            self.should_validate,
            {
                "validate": "tool_validation",
                "execute": "tool_execution"
            }
        )
        workflow.add_edge("tool_validation", "tool_execution")
        workflow.add_edge("tool_execution", "completion")
        workflow.add_edge("completion", END)
        
        return workflow.compile(checkpointer=MemorySaver())
    
    @logging_decorator
    def create_plan(self, state: GraphState) -> Dict[str, Any]:
        """Create execution plan from user prompt using Groq LLM"""
        user_message = state.messages[-1].content if state.messages else ""
        
        # Use Groq LLM to create plan and extract tool calls
        plan_prompt = f"""
        Based on the user request: "{user_message}"
        Create a detailed execution plan and identify required AWS tools.
        ignore the currently available tools and create a complete plan to fulfil the needs of users needs based on the services aws provides
        
        Available tools: {[tool.name for tool in self.tools]}
        
        Respond in JSON format with:
        - plan: string describing the execution plan
        - tool_calls: array of objects with name, arguments, and requires_input fields
        """
        
        response = self.llm.invoke([HumanMessage(content=plan_prompt)])
        
        try:
            # Parse LLM response
            response_data = json.loads(response.content)
            print("response data ",response_data)
            plan = response_data.get("plan", f"{response['plan']}")
            tool_calls = response_data.get("tool_calls", self._extract_tool_calls(user_message))
        except:
            # Fallback to simple extraction if JSON parsing fails
            plan = f"Plan for: {user_message}"
            tool_calls = self._extract_tool_calls(user_message)
        
        # Check if validation is required
        requires_validation = len(tool_calls) > 1 or any(
            call.get("requires_input", False) for call in tool_calls
        )
        
        return {
            "plan": plan,
            "tool_calls": tool_calls,
            "requires_validation": requires_validation,
            "messages": state.messages + [AIMessage(content=f"Created plan: {plan}")]
        }
    
    @logging_decorator
    def validate_tools(self, state: GraphState) -> Dict[str, Any]:
        """Validate tool calls with user using Groq LLM"""
        validation_prompt = f"""
        Validate the following tool execution plan:
        Plan: {state.plan}
        Tools to execute: {[call['name'] for call in state.tool_calls]}
        
        Provide a validation summary for user confirmation.
        """
        
        response = self.llm.invoke([HumanMessage(content=validation_prompt)])
        
        return {
            "messages": state.messages + [AIMessage(content=f"Validation: {response.content}")]
        }
    
    @logging_decorator
    def execute_tools(self, state: GraphState) -> Dict[str, Any]:
        """Execute the planned tools"""
        results = []
        for i, tool_call in enumerate(state.tool_calls):
            try:
                tool_name = tool_call["name"]
                tool_args = tool_call.get("arguments", {})
                
                # Merge user inputs if available
                if state.user_inputs:
                    tool_args.update(state.user_inputs)
                
                # Find and execute tool
                tool = next((t for t in self.tools if t.name == tool_name), None)
                if tool:
                    result = tool.invoke(tool_args)
                    results.append({"tool": tool_name, "result": result, "status": "success"})
                else:
                    results.append({"tool": tool_name, "result": "Tool not found", "status": "error"})
            except Exception as e:
                results.append({"tool": tool_name, "result": str(e), "status": "error"})
        
        return {
            "execution_results": results,
            "messages": state.messages + [AIMessage(content="Tools executed successfully")]
        }
    
    @logging_decorator
    def complete_workflow(self, state: GraphState) -> Dict[str, Any]:
        """Complete the workflow using Groq LLM"""
        completion_prompt = f"""
        Summarize the workflow execution:
        Plan: {state.plan}
        Results: {state.execution_results}
        
        Provide a completion summary.
        """
        response = self.llm.invoke([HumanMessage(content=completion_prompt)])
        
        return {
            "messages": state.messages + [AIMessage(content=f"Workflow completed: {response.content}")]
        }

        # return {
        #     "messages": state.messages + [AIMessage(content=f"Created plan: {plan}")],
        #     "plan": state.plan,
        #     "tool_calls": state.tool_calls,
        #     "current_tool_index": state.current_tool_index,
        #     "requires_validation": state.requires_validation,
        #     "session_id": state.session_id,
        #     "user_inputs": state.user_inputs,
        #     "execution_results": state.execution_results
        # }
    
    @logging_decorator
    def should_validate(self, state: GraphState) -> str:
        """Determine if validation is required"""
        return "validate" if state.requires_validation else "execute"
    
    @logging_decorator
    def _extract_tool_calls(self, user_input: str) -> List[Dict[str, Any]]:
        """Extract tool calls from user input (simplified fallback)"""
        tool_calls = []
        
        # Simple keyword matching for demo
        if "list buckets" in user_input.lower():
            tool_calls.append({"name": "list_s3_buckets", "arguments": {}})
        elif "create bucket" in user_input.lower():
            tool_calls.append({
                "name": "create_s3_bucket", 
                "arguments": {},
                "requires_input": True
            })
        
        return tool_calls

# Global graph instance
aws_graph = AWSWorkflowGraph()