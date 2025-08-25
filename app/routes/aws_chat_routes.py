import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from app.authentication.auth import get_current_user
from app.database.mongodb import get_collection

router = APIRouter(prefix="/chat", tags=["chat"])

# Collections
chat_collection = get_collection("chat_sessions")

# Request/Response models
class CreateChatRequest(BaseModel):
    aws_access_key_id: str = Field(..., description="AWS Access Key ID for this chat session")
    aws_secret_access_key: str = Field(..., description="AWS Secret Access Key for this chat session")
    chat_name: Optional[str] = Field(None, description="Optional name for the chat session")

class ChatResponse(BaseModel):
    chat_id: str
    chat_name: Optional[str]
    created_at: datetime
    user_email: str

class ChatListResponse(BaseModel):
    chat_id: str
    chat_name: Optional[str]
    created_at: datetime

@router.post("/create", response_model=ChatResponse)
async def create_chat(
    request: CreateChatRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new chat session with AWS credentials
    
    Features:
    - Generates unique chat ID
    - Stores AWS credentials securely for the session
    - Associates chat with the authenticated user
    """
    try:
        # Generate unique chat ID
        chat_id = str(uuid.uuid4())
        
        # Prepare chat data
        chat_data = {
            "chat_id": chat_id,
            "user_email": current_user.email,
            "chat_name": request.chat_name or f"Chat {chat_id[:8]}",
            "credentials": {
                "aws_access_key_id": request.aws_access_key_id,
                "aws_secret_access_key": request.aws_secret_access_key
            },
            "created_at": datetime.utcnow(),
            "is_active": True
        }
        
        # Insert into database
        chat_collection.insert_one(chat_data)
        
        return ChatResponse(
            chat_id=chat_id,
            chat_name=chat_data["chat_name"],
            created_at=chat_data["created_at"],
            user_email=current_user.email
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create chat: {str(e)}"
        )

@router.get("/list", response_model=List[ChatListResponse])
async def list_chats(current_user: dict = Depends(get_current_user)):
    """
    List all chat sessions for the authenticated user
    
    Features:
    - Returns only active chats for the current user
    - Excludes sensitive credential information
    - Sorted by creation date (newest first)
    """
    try:
        chats = list(chat_collection.find(
            {
                "user_email": current_user.email,
                "is_active": True
            },
            {
                "chat_id": 1,
                "chat_name": 1,
                "created_at": 1,
                "_id": 0
            }
        ).sort("created_at", -1))
        
        return [ChatListResponse(**chat) for chat in chats]
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve chats: {str(e)}"
        )

@router.get("/{chat_id}")
async def get_chat(
    chat_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get chat session details (without credentials)
    
    Features:
    - Returns chat metadata
    - Verifies user ownership
    - Excludes sensitive credential information
    """
    try:
        chat = chat_collection.find_one(
            {
                "chat_id": chat_id,
                "user_email": current_user.email,
                "is_active": True
            },
            {
                "credentials": 0,  # Exclude credentials from response
                "_id": 0
            }
        )
        
        if not chat:
            raise HTTPException(
                status_code=404,
                detail="Chat not found"
            )
        
        return chat
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve chat: {str(e)}"
        )

@router.delete("/{chat_id}")
async def delete_chat(
    chat_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete (deactivate) a chat session
    
    Features:
    - Soft delete by setting is_active to False
    - Verifies user ownership
    - Preserves data for potential recovery
    """
    try:
        result = chat_collection.update_one(
            {
                "chat_id": chat_id,
                "user_email": current_user.email,
                "is_active": True
            },
            {
                "$set": {
                    "is_active": False,
                    "deleted_at": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Chat not found"
            )
        
        return {"message": "Chat deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete chat: {str(e)}"
        )

@router.put("/{chat_id}/name")
async def update_chat_name(
    chat_id: str,
    chat_name: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Update chat session name
    
    Features:
    - Updates only the chat name
    - Verifies user ownership
    """
    try:
        result = chat_collection.update_one(
            {
                "chat_id": chat_id,
                "user_email": current_user.email,
                "is_active": True
            },
            {
                "$set": {
                    "chat_name": chat_name,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=404,
                detail="Chat not found"
            )
        
        return {"message": "Chat name updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update chat name: {str(e)}"
        )