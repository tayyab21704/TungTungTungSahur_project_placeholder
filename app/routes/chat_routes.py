from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Dict, Any, Optional
from app.authentication.auth import get_current_user
from app.models.authentication_models import SignUp
from app.services.graph import build_graph
import asyncio
import logging

# Create a router for graph-related routes
router = APIRouter(prefix="/graph", tags=["graph"])

# Request/Response models
class GraphQueryRequest(BaseModel):
    query: str
    user_id: Optional[str] = None

class GraphQueryResponse(BaseModel):
    success: bool
    result: Optional[str] = None
    error: Optional[str] = None
    execution_id: Optional[str] = None

class GraphStatusResponse(BaseModel):
    status: str
    message: str

# Set up logging
logger = logging.getLogger(__name__)

@router.post("/execute", response_model=GraphQueryResponse)
async def execute_graph_query(
    request: GraphQueryRequest,
    current_user: SignUp = Depends(get_current_user)
):
    """
    Execute a graph query with user authentication
    
    Features:
    - Accepts user query and processes it through the LangGraph
    - Includes human-in-the-loop validation steps
    - Returns execution results or errors
    - Tracks execution for the authenticated user
    """
    try:
        # Build the graph
        graph = build_graph()
        
        # Prepare initial state
        initial_state = {
            "user_query": request.query,
            "plan": "",
            "confirmed_plan": False,
            "tool_call": {},
            "final_answer": ""
        }
        
        # Execute the graph
        logger.info(f"Executing graph for user: {current_user.email}, query: {request.query}")
        
        # Since the graph includes human-in-the-loop steps, we need to handle this carefully
        # The graph execution will pause for user input during confirm_plan and validate_tool_call
        result = graph.invoke(initial_state)
        
        logger.info(f"Graph execution completed for user: {current_user.email}")
        
        return GraphQueryResponse(
            success=True,
            result=result.get("final_answer", "No final answer generated"),
            execution_id=f"{current_user.email}_{request.query[:20]}"
        )
        
    except Exception as e:
        logger.error(f"Graph execution failed for user {current_user.email}: {str(e)}")
        
        # Handle specific error types
        if "Tool call rejected by human" in str(e):
            return GraphQueryResponse(
                success=False,
                error="Tool execution was rejected during validation",
                execution_id=f"{current_user.email}_{request.query[:20]}"
            )
        
        return GraphQueryResponse(
            success=False,
            error=f"Graph execution failed: {str(e)}",
            execution_id=f"{current_user.email}_{request.query[:20]}"
        )

@router.post("/execute-async", response_model=GraphQueryResponse)
async def execute_graph_query_async(
    request: GraphQueryRequest,
    current_user: SignUp = Depends(get_current_user)
):
    """
    Execute a graph query asynchronously (for long-running operations)
    
    Features:
    - Non-blocking execution
    - Returns execution ID for status tracking
    - Suitable for complex queries that might take time
    """
    try:
        # Generate execution ID
        execution_id = f"{current_user.email}_{hash(request.query)}"
        
        # Start async execution
        async def run_graph():
            try:
                graph = build_graph()
                initial_state = {
                    "user_query": request.query,
                    "plan": "",
                    "confirmed_plan": False,
                    "tool_call": {},
                    "final_answer": ""
                }
                
                result = graph.invoke(initial_state)
                logger.info(f"Async graph execution completed for {execution_id}")
                return result
                
            except Exception as e:
                logger.error(f"Async graph execution failed for {execution_id}: {str(e)}")
                raise e
        
        # Start the task (you might want to store this in a task manager/database)
        asyncio.create_task(run_graph())
        
        return GraphQueryResponse(
            success=True,
            result="Query submitted for async processing",
            execution_id=execution_id
        )
        
    except Exception as e:
        logger.error(f"Failed to start async graph execution: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start query processing: {str(e)}"
        )

@router.get("/status/{execution_id}", response_model=GraphStatusResponse)
async def get_execution_status(
    execution_id: str,
    current_user: SignUp = Depends(get_current_user)
):
    """
    Get the status of an async graph execution
    
    Note: This is a basic implementation. In production, you'd want to store
    execution status in a database or task queue system like Celery/Redis
    """
    # Verify the execution belongs to the current user
    if not execution_id.startswith(current_user.email):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this execution"
        )
    
    # This is a placeholder - implement actual status tracking
    return GraphStatusResponse(
        status="completed",  # or "running", "failed", "pending"
        message="Execution status tracking not fully implemented. Check logs for details."
    )

@router.get("/health")
async def graph_health_check():
    """
    Health check endpoint for the graph service
    """
    try:
        # Test graph building
        graph = build_graph()
        return {"status": "healthy", "message": "Graph service is operational"}
    except Exception as e:
        logger.error(f"Graph health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Graph service is unhealthy: {str(e)}"
        )

@router.post("/validate-query")
async def validate_query(
    request: GraphQueryRequest,
    current_user: SignUp = Depends(get_current_user)
):
    """
    Validate a query before execution
    
    Features:
    - Checks query format and content
    - Returns validation results without executing
    - Helps prevent invalid queries from consuming resources
    """
    try:
        # Basic validation
        if not request.query or len(request.query.strip()) == 0:
            return {
                "valid": False,
                "message": "Query cannot be empty"
            }
        
        if len(request.query) > 10000:  # Example limit
            return {
                "valid": False,
                "message": "Query too long (max 10,000 characters)"
            }
        
        # You can add more sophisticated validation here
        # For example, check for required keywords, format, etc.
        
        return {
            "valid": True,
            "message": "Query validation passed",
            "estimated_complexity": "medium"  # Could implement complexity analysis
        }
        
    except Exception as e:
        logger.error(f"Query validation failed: {str(e)}")
        return {
            "valid": False,
            "message": f"Validation error: {str(e)}"
        }