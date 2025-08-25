from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
from pydantic import BaseModel
import logging
from langchain_core.messages import HumanMessage
import uuid

from app.services.graph import get_aws_graph
from app.authentication.auth import get_current_user

router = APIRouter()
logger = logging.getLogger(__name__)

class PlanRequest(BaseModel):
    prompt: str
    # session_id: str

class ValidationRequest(BaseModel):
    session_id: str
    approved: bool
    user_inputs: Dict[str, Any] = {}

class ExecutionRequest(BaseModel):
    session_id: str
    user_inputs: Dict[str, Any] = {}

@router.post("/create-plan")
async def create_plan(
    request: PlanRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create an execution plan from user prompt"""
    try:
        print("1-----------------------------------")
        logger.info(f"Creating plan for user {current_user.get('user_id')} with prompt: {request.prompt}")
        
        # Get the graph instance
        aws_graph = get_aws_graph()
        print("2-----------------------------------")
        session_id = str(uuid.uuid4())
        
        # Create initial state
        initial_state = {
            "messages": [HumanMessage(content=request.prompt)],
            "session_id": session_id,
            "plan": None,
            "tool_calls": [],
            "current_tool_index": 0,
            "requires_validation": False,
            "user_inputs": {},
            "execution_results": []
        }
        
        # Run only the plan creation node
        result = await aws_graph.graph.invoke(
            initial_state,
            config={"configurable": {"thread_id": request.session_id}}
        )
        print("3-----------------------------------")
        
        return {
            "success": True,
            "plan": result.get("plan"),
            "tool_calls": result.get("tool_calls", []),
            "requires_validation": result.get("requires_validation", False),
            "session_id": request.session_id
        }
        
    except Exception as e:
        logger.error(f"Plan creation failed: {str(e)}")
        logger.error(f"Traceback: ", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Plan creation failed: {str(e)}")

@router.post("/validate-plan")
async def validate_plan(
    request: ValidationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Validate the execution plan with user"""
    try:
        logger.info(f"Validating plan for session {request.session_id}")
        
        if not request.approved:
            return {
                "success": True,
                "message": "Plan rejected by user",
                "session_id": request.session_id
            }
        
        aws_graph = get_aws_graph()
        
        # Get current state from the graph
        current_state = aws_graph.graph.get_state(
            config={"configurable": {"thread_id": request.session_id}}
        )
        
        if not current_state:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Update state with user inputs
        updated_state = current_state.values.copy()
        if request.user_inputs:
            updated_state["user_inputs"].update(request.user_inputs)
        
        # Continue from validation
        result = await aws_graph.graph.ainvoke(
            updated_state,
            config={"configurable": {"thread_id": request.session_id}}
        )
        
        return {
            "success": True,
            "validation_summary": "Plan approved and validated",
            "session_id": request.session_id
        }
        
    except Exception as e:
        logger.error(f"Plan validation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Plan validation failed: {str(e)}")

@router.post("/execute-tools")
async def execute_tools(
    request: ExecutionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Execute the planned tools"""
    try:
        logger.info(f"Executing tools for session {request.session_id}")
        
        aws_graph = get_aws_graph()
        
        # Get current state
        current_state = aws_graph.graph.get_state(
            config={"configurable": {"thread_id": request.session_id}}
        )
        
        if not current_state:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Update state with user inputs if provided
        updated_state = current_state.values.copy()
        if request.user_inputs:
            updated_state["user_inputs"].update(request.user_inputs)
        
        # Continue execution
        result = await aws_graph.graph.ainvoke(
            updated_state,
            config={"configurable": {"thread_id": request.session_id}}
        )
        
        return {
            "success": True,
            "execution_results": result.get("execution_results", []),
            "completion_summary": result.get("messages", [])[-1].content if result.get("messages") else "",
            "session_id": request.session_id
        }
        
    except Exception as e:
        logger.error(f"Tool execution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Tool execution failed: {str(e)}")

@router.get("/session/{session_id}/status")
async def get_session_status(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get the current status of a workflow session"""
    try:
        aws_graph = get_aws_graph()
        
        current_state = aws_graph.graph.get_state(
            config={"configurable": {"thread_id": session_id}}
        )
        
        if not current_state:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return {
            "success": True,
            "session_id": session_id,
            "current_node": current_state.next,
            "state": {
                "plan": current_state.values.get("plan"),
                "tool_calls": current_state.values.get("tool_calls", []),
                "requires_validation": current_state.values.get("requires_validation", False),
                "execution_results": current_state.values.get("execution_results", [])
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get session status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get session status: {str(e)}")

@router.delete("/session/{session_id}")
async def delete_session(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Delete a workflow session"""
    try:
        # Note: LangGraph MemorySaver doesn't have a direct delete method
        # In production, you might want to use a different checkpointer
        # that supports session deletion
        
        return {
            "success": True,
            "message": f"Session {session_id} marked for deletion",
            "session_id": session_id
        }
        
    except Exception as e:
        logger.error(f"Failed to delete session: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete session: {str(e)}")

@router.post("/run-complete-workflow")
async def run_complete_workflow(
    request: PlanRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Run the complete workflow from start to finish"""
    try:
        logger.info(f"Running complete workflow for user {current_user.get('user_id')}")
        
        aws_graph = get_aws_graph()
        
        # Create initial state
        initial_state = {
            "messages": [HumanMessage(content=request.prompt)],
            "session_id": request.session_id,
            "plan": None,
            "tool_calls": [],
            "current_tool_index": 0,
            "requires_validation": False,
            "user_inputs": {},
            "execution_results": []
        }
        
        # Run the complete workflow
        result = await aws_graph.graph.ainvoke(
            initial_state,
            config={"configurable": {"thread_id": request.session_id}}
        )
        
        return {
            "success": True,
            "plan": result.get("plan"),
            "tool_calls": result.get("tool_calls", []),
            "execution_results": result.get("execution_results", []),
            "completion_summary": result.get("messages", [])[-1].content if result.get("messages") else "",
            "session_id": request.session_id
        }
        
    except Exception as e:
        logger.error(f"Complete workflow execution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Complete workflow execution failed: {str(e)}")