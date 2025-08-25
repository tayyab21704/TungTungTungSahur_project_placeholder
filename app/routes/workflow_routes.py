import uuid
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from langchain_core.messages import HumanMessage

from app.authentication.auth import get_current_user
from app.database.mongodb import get_collection
from app.database.redis import get_redis_client
from app.services.graph import get_aws_graph, GraphState
from app.utils.logging_decorator import logging_decorator, logger

router = APIRouter(prefix="/workflow", tags=["workflow"])

# Collections
workflow_collection = get_collection("workflows")
# NEW: Collection to store chat session credentials
chat_collection = get_collection("chat_sessions")
redis_client = get_redis_client()

# Request/Response models
class InitialPromptRequest(BaseModel):
    prompt: str
    # MODIFIED: chat_id is now required to fetch credentials
    chat_id: str = Field(..., description="The active chat session ID to associate credentials.")

class ConfirmPlanRequest(BaseModel):
    session_id: str
    confirmed: bool

class ExecuteWorkflowRequest(BaseModel):
    session_id: str
    inputs: Dict[str, Any] = {}

# Route 1: Initial prompt and plan creation
@router.post("/create-plan")
@logging_decorator
async def create_plan(
    request: InitialPromptRequest,
    current_user: dict = Depends(get_current_user)
):
    """Create execution plan from user prompt using credentials from chat_id"""
    try:
        aws_graph = get_aws_graph()
        session_id = str(uuid.uuid4())

        # NEW: Fetch credentials associated with the chat_id
        chat_session = chat_collection.find_one({"chat_id": request.chat_id})
        if not chat_session or "credentials" not in chat_session:
            raise HTTPException(
                status_code=404,
                detail=f"Credentials for chat_id '{request.chat_id}' not found. Please start a session first."
            )
        credentials = chat_session["credentials"]

        # Initialize state with prompt and fetched credentials
        initial_state = GraphState(
            messages=[HumanMessage(content=request.prompt)],
            session_id=session_id,
            credentials=credentials
        )

        # Run graph until plan creation
        config = {"configurable": {"thread_id": session_id}}
        result = aws_graph.graph.invoke(initial_state, config)
        
        # MODIFIED: Corrected logging
        if result:
            logger.info(f"Plan created successfully for session {session_id}.")
        else:
            logger.error(f"Graph invocation returned None for session {session_id}.")
            raise HTTPException(status_code=500, detail="Failed to generate a plan from the prompt.")

        # Prepare response
        plan_data = {
            "chat_id": request.chat_id,
            "session_id": session_id,
            "user_email": current_user.email,
            "prompt": request.prompt,
            "plan": result["plan"],
            "tool_calls": result["tool_calls"],
            "requires_validation": result["requires_validation"],
            "credentials": credentials,  # Store credentials with the workflow data
            "created_at": datetime.utcnow(),
            "status": "pending_confirmation"
        }

        # Store in MongoDB and cache in Redis
        workflow_collection.insert_one(plan_data)
        redis_client.setex(
            f"workflow:{session_id}",
            300,  # 5 minutes
            json.dumps(plan_data, default=str)
        )

        return {
            "session_id": session_id,
            "plan": result["plan"],
            "tool_calls": result["tool_calls"],
            "requires_validation": result["requires_validation"],
            "message": "Plan created. Please review and confirm to proceed."
        }

    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.error(f"Plan creation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Plan creation failed: {str(e)}")

# Route 2: Confirm plan
@router.post("/confirm-plan")
@logging_decorator
async def confirm_plan(
    request: ConfirmPlanRequest,
    current_user: dict = Depends(get_current_user)
):
    """Confirm the execution plan"""
    cached_data = redis_client.get(f"workflow:{request.session_id}")
    if not cached_data:
        raise HTTPException(status_code=400, detail="Session expired or invalid. Please create a new plan.")
    
    plan_data = json.loads(cached_data)

    if not request.confirmed:
        workflow_collection.update_one(
            {"session_id": request.session_id},
            {"$set": {"status": "rejected", "updated_at": datetime.utcnow()}}
        )
        redis_client.delete(f"workflow:{request.session_id}")
        return {"message": "Plan rejected."}

    workflow_collection.update_one(
        {"session_id": request.session_id},
        {"$set": {"status": "confirmed", "updated_at": datetime.utcnow()}}
    )

    # Get required functional inputs for tools (credentials are handled internally)
    required_inputs = []
    if plan_data.get("tool_calls"):
        for call in plan_data["tool_calls"]:
            # Assuming tool call structure has a 'name'
            tool_name = call.get("name")
            if tool_name:
                required_fields = _get_tool_required_fields(tool_name)
                if required_fields:
                    required_inputs.append({
                        "tool_name": tool_name,
                        "required_fields": required_fields
                    })
    
    return {
        "message": "Plan confirmed. Provide the required inputs to execute.",
        "required_inputs": required_inputs
    }

# Route 3: Execute workflow with inputs
@router.post("/execute")
@logging_decorator
async def execute_workflow(
    request: ExecuteWorkflowRequest,
    current_user: dict = Depends(get_current_user)
):
    """Execute the confirmed workflow with provided inputs"""
    try:
        aws_graph = get_aws_graph()
        # Get workflow data

        workflow_data = workflow_collection.find_one({"session_id": request.session_id})
        if not workflow_data:
            raise HTTPException(status_code=404, detail="Workflow not found.")
        
        if workflow_data["status"] != "confirmed":
            raise HTTPException(status_code=400, detail="Workflow must be confirmed before execution.")
        
        # Prepare state for execution, including credentials from the stored workflow
        execution_state = GraphState(
            messages=[HumanMessage(content=workflow_data["prompt"])],
            session_id=request.session_id,
            plan=workflow_data["plan"],
            tool_calls=workflow_data["tool_calls"],
            user_inputs=request.inputs,
            credentials=workflow_data["credentials"], # Pass stored credentials
            requires_validation=False
        )

        config = {"configurable": {"thread_id": request.session_id}}
        result = aws_graph.graph.invoke(execution_state, config)

        workflow_collection.update_one(
            {"session_id": request.session_id},
            {"$set": {
                "status": "completed",
                "user_inputs": request.inputs,
                "execution_results": result.get("execution_results", []),
                "completed_at": datetime.utcnow()
            }}
        )

        redis_client.delete(f"workflow:{request.session_id}")
        
        return {
            "message": "Workflow executed successfully.",
            "results": result.get("execution_results", [])
        }
        
    except Exception as e:
        logger.error(f"Workflow execution failed for session {request.session_id}: {e}", exc_info=True)
        workflow_collection.update_one(
            {"session_id": request.session_id},
            {"$set": {"status": "failed", "error": str(e), "failed_at": datetime.utcnow()}}
        )
        raise HTTPException(status_code=500, detail=f"Workflow execution failed: {str(e)}")

# MODIFIED: Helper method no longer takes 'self' and doesn't ask for AWS keys
def _get_tool_required_fields(tool_name: str) -> List[str]:
    """Get USER-required functional fields for a specific tool. Credentials are handled by the system."""
    tool_requirements = {
        "create_s3_bucket": ["bucket_name", "region"],
        "delete_s3_bucket": ["bucket_name"],
        "set_s3_bucket_encryption": ["bucket_name", "encryption_type"],
        "enable_s3_versioning": ["bucket_name", "status"],
        "get_bucket_region": ["bucket_name"]
    }
    return tool_requirements.get(tool_name, [])

# Additional utility routes (Unchanged)
@router.get("/status/{session_id}")
async def get_workflow_status(session_id: str, current_user: dict = Depends(get_current_user)):
    """Get workflow status"""
    workflow_data = workflow_collection.find_one(
        {"session_id": session_id, "user_email": current_user.email}
    )
    if not workflow_data:
        raise HTTPException(status_code=404, detail="Workflow not found.")
    
    return {
        "session_id": session_id,
        "status": workflow_data["status"],
        "plan": workflow_data.get("plan"),
        "created_at": workflow_data.get("created_at"),
        "results": workflow_data.get("execution_results", [])
    }