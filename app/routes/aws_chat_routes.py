import uuid
from datetime import datetime
from typing import List, Optional, AsyncGenerator
import os
import pymongo # ✅ Added for the reset functionality

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from langgraph.checkpoint.mongodb import MongoDBSaver
from langchain_core.messages import HumanMessage, BaseMessage

from graph import aws_graph  # assumes you've built aws_graph in graph.py

router = APIRouter(prefix="/chat", tags=["AWS Chat"])

# ---------- Setup MongoDB Connection ----------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "aws_agent_chat_db"
COLLECTION_NAME = "threads"

# ---------- Pydantic Models ----------
class ChatRequest(BaseModel):
    chat_id: Optional[str] = None
    message: str

class ThreadsResponse(BaseModel):
    threads: List[str]

class HistoryResponse(BaseModel):
    chat_id: str
    messages: List[dict]  # [{role: "user"/"assistant", content: "..."}]

class ResetResponse(BaseModel):
    chat_id: str
    message: str

# ---------- Dependency for MongoDB Connection ----------
def get_checkpointer() -> MongoDBSaver:
    """
    Dependency to get a MongoDB checkpointer per request.
    MongoDBSaver handles connection pooling internally.
    """
    return MongoDBSaver.from_conn_string(
        conn_string=MONGO_URI, db_name=DB_NAME, collection_name=COLLECTION_NAME
    )

# ---------- Utility ----------
def generate_chat_id():
    return str(uuid.uuid4())

# ---------- Chat Routes ----------

# @router.post("/message")
# async def send_message_stream(
#     payload: ChatRequest,
#     checkpointer: MongoDBSaver = Depends(get_checkpointer)
# ):
#     """
#     Handles sending a message to the chat agent and streams the response back.
#     Continues a chat if chat_id is provided, otherwise starts a new one.
#     """
#     chat_id = payload.chat_id or generate_chat_id()
#     user_input = payload.message
    
#     config = {"configurable": {"thread_id": chat_id, "checkpointer": checkpointer}}

#     async def stream_generator() -> AsyncGenerator[str, None]:
#         response_stream = await run_in_threadpool(
#             aws_graph.graph.stream,
#             {"messages": [HumanMessage(content=user_input)]},
#             config=config,
#             stream_mode="messages"
#         )
#         for message_chunk in response_stream:
#             yield message_chunk.content

#     try:
#         return StreamingResponse(stream_generator(), media_type="text/plain")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Chat streaming failed: {str(e)}")


@router.get("/threads", response_model=ThreadsResponse)
async def get_threads(checkpointer: MongoDBSaver = Depends(get_checkpointer)):
    """Retrieves all unique thread IDs from the database."""
    try:
        all_checkpoints = await run_in_threadpool(checkpointer.list, None)
        all_threads = {c.config["configurable"]["thread_id"] for c in all_checkpoints}
        return ThreadsResponse(threads=list(all_threads))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve threads: {str(e)}")


@router.get("/history/{chat_id}", response_model=HistoryResponse)
async def get_history(chat_id: str, checkpointer: MongoDBSaver = Depends(get_checkpointer)):
    """Retrieves the message history for a given chat ID."""
    config = {"configurable": {"thread_id": chat_id, "checkpointer": checkpointer}}
    
    try:
        state = await run_in_threadpool(aws_graph.graph.get_state, config)
        
        if not state or "messages" not in state.values:
            return HistoryResponse(chat_id=chat_id, messages=[])

        messages = state.values["messages"]
        formatted_messages = []
        for msg in messages:
            role = "user" if isinstance(msg, HumanMessage) else "assistant"
            formatted_messages.append({"role": role, "content": msg.content})

        return HistoryResponse(chat_id=chat_id, messages=formatted_messages)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve history: {str(e)}")


# ---------- ✅ NEW: Resume Chat Route ----------
@router.get("/resume/{chat_id}", response_model=HistoryResponse)
async def resume_chat(chat_id: str, checkpointer: MongoDBSaver = Depends(get_checkpointer)):
    """
    Resumes a chat by fetching its history. This allows a client to load
    and display the conversation before the user sends a new message.
    """
    return await get_history(chat_id, checkpointer)


# ---------- ✅ NEW: Reset Chat Route ----------
def _delete_thread_history(chat_id: str):
    """Synchronous helper function to delete checkpoints from MongoDB."""
    with pymongo.MongoClient(MONGO_URI) as client:
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        # A single thread can have multiple checkpoints, so use delete_many
        result = collection.delete_many({"configurable.thread_id": chat_id})
        return result.deleted_count

@router.delete("/history/{chat_id}", response_model=ResetResponse)
async def reset_chat(chat_id: str):
    """
    Resets a chat by permanently deleting all of its history.
    """
    try:
        # Run the blocking database operation in a thread pool
        deleted_count = await run_in_threadpool(_delete_thread_history, chat_id)
        if deleted_count > 0:
            return ResetResponse(
                chat_id=chat_id,
                message=f"Successfully reset chat history. {deleted_count} checkpoints deleted."
            )
        else:
            raise HTTPException(status_code=404, detail="Chat ID not found.")
    except Exception as e:
        # Catch potential database errors
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=f"Failed to reset chat history: {str(e)}")