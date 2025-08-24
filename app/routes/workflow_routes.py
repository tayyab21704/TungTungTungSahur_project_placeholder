from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import uuid
import json
from datetime import datetime, timedelta
from langchain_core.messages import HumanMessage

from app.authentication.auth import get_current_user
from app.database.mongodb import get_collection
from app.database.redis import get_redis_client
from app.services.graph import get_aws_graph, GraphState
from app.utils.logging_decorator import logging_decorator, logger

router = APIRouter(prefix="/workflow", tags=["workflow"])

# Collections
workflow_collection = get_collection("workflows")
redis_client = get_redis_client()

# Request/Response models
class InitialPromptRequest(BaseModel):
    prompt: str

class ConfirmPlanRequest(BaseModel):
    session_id: str
    confirmed: bool

class ExecuteWorkflowRequest(BaseModel):
    session_id: str
    inputs: Optional[Dict[str, Any]] = {}

# Route 1: Initial prompt and plan creation
@router.post("/create-plan")
async def create_plan(
    request: InitialPromptRequest,
    current_user: dict = Depends(get_current_user)
):
    """Create execution plan from user prompt"""
    try:
        aws_graph = get_aws_graph()
        session_id = str(uuid.uuid4())
        
        # Initialize state
        initial_state = GraphState(
            messages=[HumanMessage(content=request.prompt)],
            session_id=session_id
        )
        
        # Run graph until plan creation
        config = {"configurable": {"thread_id": session_id}}
        # print(initial_state.model_dump())
        # result = aws_graph.graph.invoke(initial_state.model_dump(), config)
        result = aws_graph.graph.invoke(initial_state, config)
        
        if result is None:
            logger.error("Result in create_plan is None")
        else:
            logger.error("Result in create_plan is None")
        
        # Prepare response
        plan_data = {
            "session_id": session_id,
            "user_email": current_user.email,
            "prompt": request.prompt,
            "plan": result["plan"],
            "tool_calls": result["tool_calls"],
            "requires_validation": result["requires_validation"],
            "created_at": datetime.utcnow(),
            "status": "pending_confirmation"
        }
        
        # Store in MongoDB
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
            "message": "Plan created. Please confirm to proceed." if result["requires_validation"] else "Executing plan..."
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Plan creation failed: {str(e)}")

# Route 2: Confirm plan
@router.post("/confirm-plan")
async def confirm_plan(
    request: ConfirmPlanRequest,
    current_user: dict = Depends(get_current_user)
):
    """Confirm the execution plan"""
    try:
        # Check Redis cache
        cached_data = redis_client.get(f"workflow:{request.session_id}")
        
        if not cached_data:
            raise HTTPException(
                status_code=400, 
                detail="Session expired. Please create a new plan."
            )
        
        plan_data = json.loads(cached_data)
        
        if not request.confirmed:
            # User rejected the plan
            workflow_collection.update_one(
                {"session_id": request.session_id},
                {"$set": {"status": "rejected", "updated_at": datetime.utcnow()}}
            )
            redis_client.delete(f"workflow:{request.session_id}")
            return {"message": "Plan rejected"}
        
        # Update status
        workflow_collection.update_one(
            {"session_id": request.session_id},
            {"$set": {"status": "confirmed", "updated_at": datetime.utcnow()}}
        )
        
        # Get required inputs for tools
        required_inputs = []
        for call in plan_data["tool_calls"]:
            if call.get("requires_input", False):
                required_inputs.append({
                    "tool_name": call["name"],
                    "required_fields": _get_tool_required_fields(call["name"])
                })
        
        
        return {
            "message": "Plan confirmed. Ready for execution.",
            "required_inputs": required_inputs
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Plan confirmation failed: {str(e)}")

# Route 3: Execute workflow with inputs
@router.post("/execute")
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
            raise HTTPException(status_code=404, detail="Workflow not found")
        
        # Check if workflow is ready for execution
        if workflow_data["status"] != "confirmed":
            raise HTTPException(
                status_code=400, 
                detail="Workflow not confirmed. Please confirm the plan first."
            )
        
        # Prepare state for execution
        execution_state = GraphState(
            messages=[HumanMessage(content=workflow_data["prompt"])],
            session_id=request.session_id,
            plan=workflow_data["plan"],
            tool_calls=workflow_data["tool_calls"],
            user_inputs=request.inputs,
            requires_validation=False  # Skip validation since already confirmed
        )
        
        # Execute workflow
        config = {"configurable": {"thread_id": request.session_id}}
        result = aws_graph.graph.invoke(execution_state.model_dump(), config)
        
        # Update workflow status
        workflow_collection.update_one(
            {"session_id": request.session_id},
            {
                "$set": {
                    "status": "completed",
                    "user_inputs": request.inputs,
                    "execution_results": result.get("execution_results", []),
                    "completed_at": datetime.utcnow()
                }
            }
        )
        
        # Clean up Redis
        redis_client.delete(f"workflow:{request.session_id}")
        
        return {
            "message": "Workflow executed successfully",
            "results": result.get("execution_results", [])
        }
        
    except Exception as e:
        # Update workflow status to failed
        workflow_collection.update_one(
            {"session_id": request.session_id},
            {
                "$set": {
                    "status": "failed",
                    "error": str(e),
                    "failed_at": datetime.utcnow()
                }
            }
        )
        raise HTTPException(status_code=500, detail=f"Workflow execution failed: {str(e)}")

# Helper method
def _get_tool_required_fields(self, tool_name: str) -> List[str]:
    """Get required fields for a specific tool"""
    tool_requirements = {
        "create_s3_bucket": ["bucket_name", "region", "aws_access_key_id", "aws_secret_access_key"],
        "delete_s3_bucket": ["bucket_name", "aws_access_key_id", "aws_secret_access_key"],
        "set_s3_bucket_encryption": ["bucket_name", "encryption_type", "aws_access_key_id", "aws_secret_access_key"],
        "enable_s3_versioning": ["bucket_name", "status", "aws_access_key_id", "aws_secret_access_key"],
        "get_bucket_region": ["bucket_name", "aws_access_key_id", "aws_secret_access_key"]
    }
    return tool_requirements.get(tool_name, [])

# Additional utility routes
@router.get("/status/{session_id}")
async def get_workflow_status(
    session_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get workflow status"""
    workflow_data = workflow_collection.find_one(
        {"session_id": session_id, "user_email": current_user.email}
    )
    
    if not workflow_data:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    return {
        "session_id": session_id,
        "status": workflow_data["status"],
        "plan": workflow_data.get("plan"),
        "created_at": workflow_data.get("created_at"),
        "results": workflow_data.get("execution_results", [])
    }