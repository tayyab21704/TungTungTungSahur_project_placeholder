from typing import Dict, Any, List, Optional
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from pydantic import BaseModel
import json
import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from app.services.aws_tools1 import get_all_aws_tools
from app.utils.logging_decorator import logging_decorator
# from langchain_google_vertexai import ChatVertexAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
import re

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
        
        # LLM for plan creation and tool selection
        self.planner_llm = ChatGroq(
            temperature=0,
            groq_api_key=os.getenv("GROQ_API_KEY"),
            model_name="llama3-8b-8192"
        )
        
        # LLM with tools bound for tool calling
        self.tool_llm = ChatGroq(
            temperature=0,
            groq_api_key=os.getenv("GROQ_API_KEY"),
            model_name="llama3-8b-8192"
        ).bind_tools(self.tools)
        
        # LLM for validation and completion
        self.completion_llm = ChatGroq(
            temperature=0,
            groq_api_key=os.getenv("GROQ_API_KEY"),
            model_name="llama3-8b-8192"
        )

        # LLM for planning
        self.planner_llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash-latest", temperature=0)

        # # LLM with tools bound for tool calling
        self.tool_llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash-latest", 
                                               temperature=0).bind_tools(self.tools)

        # # LLM for validation and completion
        self.completion_llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash-latest", 
                                               temperature=0)
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
        """Create execution plan from user prompt using Groq LLM with tool binding"""
        user_message = state.messages[-1].content if state.messages else ""
        
        # Step 1: Create high-level plan using planner LLM
        plan_prompt = f"""
        Based on the user request: "{user_message}"
        
        Create a detailed execution plan for AWS operations. Focus on what needs to be accomplished step by step.
        Available AWS services include: S3, EC2, IAM, Lambda, CloudWatch, RDS, etc.
        
        Provide a clear, actionable plan that explains what AWS operations will be performed.
        """
        
        plan_response = self.planner_llm.invoke([HumanMessage(content=plan_prompt)])
        plan = plan_response.content
        
        # Step 2: Use tool-bound LLM to identify required tools
        tool_selection_prompt = f"""
        Based on this user request: "{user_message}"
        And this execution plan: "{plan}"
        
        You need to select and call the appropriate AWS tools to fulfill this request.
        Analyze the request carefully and make the necessary tool calls.
        
        Available tools are bound to this model. Make the actual tool calls now.
        """
        
        # Get tool calls from the LLM
        tool_response = self.tool_llm.invoke([HumanMessage(content=tool_selection_prompt)])
        
        # Extract tool calls from the response
        # -----
        tool_calls = self._extract_tool_calls_from_response(tool_response)
        
        print("Tool calls extracted:", tool_calls)
        # ----
        # Check if validation is required (more than 1 tool or requires user input)
        requires_validation = len(tool_calls) > 1 or self._check_requires_user_input(tool_calls)
        
        return {
            "plan": plan,
            "tool_calls": tool_calls,
            "requires_validation": requires_validation,
            "messages": state.messages + [AIMessage(content=f"Created plan: {plan}")]
        }
    
    # @logging_decorator
    # def _extract_tool_calls_from_response(self, response) -> List[Dict[str, Any]]:
    #     """Extract tool calls from LLM response"""
    #     tool_calls = []
        
    #     # Check if the response has tool calls
    #     if hasattr(response, 'tool_calls') and response.tool_calls:
    #         for tool_call in response.tool_calls:
    #             tool_call_dict = {
    #                 "name": tool_call["name"],
    #                 "arguments": tool_call["args"],
    #                 "requires_input": self._tool_requires_user_input(tool_call["name"])
    #             }
    #             tool_calls.append(tool_call_dict)
        
    #     # If no tool calls were made, try to infer from the response content
    #     elif not tool_calls:
    #         tool_calls = self._fallback_tool_extraction(response.content)
        
    #     return tool_calls

    # def _extract_tool_calls_from_response(self, response) -> List[str]:
    #     """
    #     Extract tool names required for the AI-generated text plan.
    #     Handles text response from LLM and returns a clean list of strings.
    #     """
    #     # Call LLM
    #     print("1----------------------------------")
    #     tool_name_prompt = ChatPromptTemplate.from_messages([
    #         ("system",
    #          "You are a tool selector. Your job is to read an AI-generated plan "
    #          "and choose the correct tools from the available list.\n\n"
    #          "Return only a list of tool names. Text only, no extra explanation.\n"
    #          "Tools must be from the available list."),
    #         ("user", "AI Plan:\n{plan_text}\n\nAvailable tools:\n{tools_list}")
    #     ])

    #     tool_objects = get_all_aws_tools()
    #     tools_list = [t.name for t in tool_objects]

    #     print("2----------------------------------")
    #     response_llm = tool_name_prompt | self.planner_llm
    #     print("3----------------------------------")
    #     raw_message = response_llm.invoke({
    #         "plan_text": response.content,
    #         "tools_list": tools_list
    #     })
    #     print("4----------------------------------")
    #     # Access the text content
    #     raw_text = raw_message.content if hasattr(raw_message, "content") else str(raw_message)
    #     print("5----------------------------------")
    #     # -----------------------------
    #     # Extract tool names from text
    #     # -----------------------------
    #     tool_names = []
    #     try:
    #         # Try parsing JSON if LLM returned JSON
    #         tool_names = json.loads(raw_text)
    #         print("6----------------------------------")
    #         if isinstance(tool_names, str):
    #             tool_names = [tool_names]
    #     except Exception:
    #         for tool in tools_list:
    #             tool_name = getattr(tool, "name", str(tool))
    #             if re.search(rf"\b{re.escape(tool_name)}\b", raw_text, re.IGNORECASE):
    #                 tool_names.append(tool_name)

    #     # Deduplicate
    #     return list(dict.fromkeys(tool_names))

    def _extract_tool_calls_from_response(self, response) -> List[Dict[str, Any]]:
        """
        Extract tool calls from LLM response.
        Always returns list of dicts with keys: name, arguments, requires_input.
        """
        tool_objects = get_all_aws_tools()
        available_tool_names = [t.name for t in tool_objects]
    
        tool_calls: List[Dict[str, Any]] = []
    
        # Get raw text from LLM
        raw_text = response.content if hasattr(response, "content") else str(response)
    
        try:
            parsed = json.loads(raw_text)
            # If model returned a single string
            if isinstance(parsed, str):
                parsed = [parsed]
            # If model returned a list of strings
            if isinstance(parsed, list) and all(isinstance(x, str) for x in parsed):
                for name in parsed:
                    if name in available_tool_names:
                        tool_calls.append({
                            "name": name,
                            "arguments": {},
                            "requires_input": self._tool_requires_user_input(name)
                        })
        except Exception:
            # Fallback: regex match against available tool names
            for name in available_tool_names:
                if re.search(rf"\b{re.escape(name)}\b", raw_text, re.IGNORECASE):
                    tool_calls.append({
                        "name": name,
                        "arguments": {},
                        "requires_input": self._tool_requires_user_input(name)
                    })
    
        return tool_calls

    
    @logging_decorator
    def _tool_requires_user_input(self, tool_name: str) -> bool:
        """Check if a tool requires user input for sensitive parameters"""
        tools_requiring_input = {
            "create_s3_bucket", 
            "delete_s3_bucket", 
            "set_s3_bucket_encryption",
            "enable_s3_versioning",
            "create_ec2_instance",
            "terminate_ec2_instance"
        }
        return tool_name in tools_requiring_input
    
    @logging_decorator
    def _check_requires_user_input(self, tool_calls: List[Dict[str, Any]]) -> bool:
        """Check if any tool calls require user input"""
        return any(call.get("requires_input", False) for call in tool_calls)
    
    @logging_decorator
    def _fallback_tool_extraction(self, content: str) -> List[Dict[str, Any]]:
        """Fallback method for tool extraction when LLM doesn't make tool calls"""
        tool_calls = []
        content_lower = content.lower()
        
        # S3 Operations
        if any(keyword in content_lower for keyword in ["list buckets", "show buckets", "get buckets"]):
            tool_calls.append({"name": "list_s3_buckets", "arguments": {}, "requires_input": False})
        
        if any(keyword in content_lower for keyword in ["create bucket", "make bucket", "new bucket"]):
            tool_calls.append({
                "name": "create_s3_bucket", 
                "arguments": {},
                "requires_input": True
            })
        
        if any(keyword in content_lower for keyword in ["delete bucket", "remove bucket"]):
            tool_calls.append({
                "name": "delete_s3_bucket", 
                "arguments": {},
                "requires_input": True
            })
        
        if any(keyword in content_lower for keyword in ["encrypt", "encryption"]):
            tool_calls.append({
                "name": "set_s3_bucket_encryption", 
                "arguments": {},
                "requires_input": True
            })
        
        if any(keyword in content_lower for keyword in ["versioning", "version"]):
            tool_calls.append({
                "name": "enable_s3_versioning", 
                "arguments": {},
                "requires_input": True
            })
        
        # EC2 Operations
        if any(keyword in content_lower for keyword in ["list instances", "show instances", "get instances"]):
            tool_calls.append({"name": "list_ec2_instances", "arguments": {}, "requires_input": False})
        
        if any(keyword in content_lower for keyword in ["create instance", "launch instance", "start instance"]):
            tool_calls.append({
                "name": "create_ec2_instance", 
                "arguments": {},
                "requires_input": True
            })
        
        if any(keyword in content_lower for keyword in ["stop instance", "terminate instance"]):
            tool_calls.append({
                "name": "terminate_ec2_instance", 
                "arguments": {},
                "requires_input": True
            })
        
        return tool_calls
    
    @logging_decorator
    def validate_tools(self, state: GraphState) -> Dict[str, Any]:
        """Validate tool calls with user using Groq LLM"""
        validation_prompt = f"""
        Please review the following execution plan:
        
        Plan: {state.plan}
        
        Tools that will be executed:
        {self._format_tool_calls_for_display(state.tool_calls)}
        
        Provide a clear validation summary that explains:
        1. What operations will be performed
        2. What AWS resources will be affected
        3. Any potential risks or considerations
        4. What user inputs are required (if any)
        
        Make it user-friendly and informative.
        """
        
        response = self.completion_llm.invoke([HumanMessage(content=validation_prompt)])
        
        return {
            "messages": state.messages + [AIMessage(content=f"Validation: {response.content}")]
        }
    
    @logging_decorator
    def _format_tool_calls_for_display(self, tool_calls: List[Dict[str, Any]]) -> str:
        """Format tool calls for user display"""
        formatted = []
        for i, call in enumerate(tool_calls, 1):
            tool_name = call["name"]
            requires_input = call.get("requires_input", False)
            input_note = " (requires user input)" if requires_input else ""
            formatted.append(f"{i}. {tool_name}{input_note}")
        return "\n".join(formatted)
    
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
        Workflow Execution Summary:
        
        Original Plan: {state.plan}
        
        Execution Results: {self._format_execution_results(state.execution_results)}
        
        Please provide a comprehensive summary of what was accomplished, including:
        1. What operations were successfully completed
        2. Any errors encountered and their implications
        3. Current state of AWS resources
        4. Next steps or recommendations (if any)
        
        Keep the summary clear and actionable.
        """
        
        response = self.completion_llm.invoke([HumanMessage(content=completion_prompt)])
        
        return {
            "messages": state.messages + [AIMessage(content=f"Workflow completed: {response.content}")]
        }
    
    @logging_decorator
    def _format_execution_results(self, results: List[Dict[str, Any]]) -> str:
        """Format execution results for display"""
        if not results:
            return "No results available"
        
        formatted = []
        for result in results:
            status = result.get("status", "unknown")
            tool = result.get("tool", "unknown")
            result_data = result.get("result", "No data")
            formatted.append(f"- {tool}: {status} - {result_data}")
        
        return "\n".join(formatted)
    
    @logging_decorator
    def should_validate(self, state: GraphState) -> str:
        """Determine if validation is required"""
        return "validate" if state.requires_validation else "execute"

# Global graph instance
aws_graph = AWSWorkflowGraph()
