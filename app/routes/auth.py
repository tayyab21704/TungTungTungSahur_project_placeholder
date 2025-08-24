from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import timedelta
from typing import Dict, Any
from app.authentication.auth import get_current_user

# Local imports
from app.models.authentication_models import SignUp, SignUpInput, UserProfile, UpdateProfileRequest
from app.database.mongodb import get_collection
from app.authentication.auth import (
    create_access_token,
    get_password_hash,
    verify_password,
    ACCESS_TOKEN_EXPIRE_DAYS
)
from app.authentication.emailverification import (
    validate_email,
)

# Create a router for user-related routes
router = APIRouter(prefix="/users", tags=["users"])

# Users collection
users_collection = get_collection("users")
verification_collection = get_collection("email_verifications")

# Token response model
class Token(BaseModel):
    access_token: str
    token_type: str

class ChangePasswordRequest(BaseModel):
    new_password: str
    current_password: str
    
class PasswordCheckRequest(BaseModel):
    current_password: str
        
@router.get("/token/validate")
async def validate_token(current_user: SignUp = Depends(get_current_user)):
    """
    Validate the JWT token
    
    Features:
    - Returns a message confirming token validity
    """
    return {"message": "Token is valid", "email": current_user.email, "is_valid": True}

@router.post("/signup")
async def signup(user: SignUpInput):
    """
    Enhanced signup process with email verification
    """
    # Validate email format
    if not validate_email(user.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format"
        )

    # Check if user already exists
    existing_user = users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Email already registered"
        )
    
    # Hash the password
    hashed_password = get_password_hash(user.password)
    
    # Prepare user data for database
    user_data = user.model_dump(exclude={"password", "id"})
    user_data["hashed_password"] = hashed_password
    
    try:
        """
        comment below line when adding verification for signup
        """
        # Insert user into database
        users_collection.insert_one(user_data)
        
        return {
            "message": "Signup successful. Please check your email to verify your account.",
            "email": user.email
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signup failed: {str(e)}"
        )

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    User login route with Firebase authentication support
    """
    user = users_collection.find_one({"email": form_data.username})

    if not user or not verify_password(form_data.password, user.get("hashed_password")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    access_token = create_access_token(
        data={"sub": form_data.username},
        expires_delta=access_token_expires
    )

    return {
        "user_id": str(user["_id"]),
        "access_token": access_token,
        "token_type": "bearer"
    }

@router.get("/profile", response_model=UserProfile)
async def get_user_profile(current_user: SignUp = Depends(get_current_user)):
    """
    Retrieve detailed user profile
    
    Features:
    - Fetches full user profile from database
    - Handles cases where user might not exist
    - Excludes sensitive information
    - Supports additional metadata
    """
    # Find user by email
    user = users_collection.find_one({"email": current_user.email})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User profile not found"
        )
    
    # Convert ObjectId to string if present
    if '_id' in user:
        user['_id'] = str(user['_id'])
    
    # Remove sensitive information
    user.pop('hashed_password', None)
    
    # Create and return user profile
    return UserProfile(**user)

# update user profile
@router.put("/profile", response_model=UserProfile)
async def update_user_profile(
    update_data: UpdateProfileRequest, 
    current_user: SignUp = Depends(get_current_user)
):
    """
    Update user profile
    
    Features:
    - Partial updates allowed
    - Validation of update fields
    - Supports adding/updating additional metadata
    """
    # Prepare update operation
    update_operation = {}
    
    # Validate and prepare update fields
    update_fields = update_data.model_dump(exclude_unset=True)
    
    if not update_fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No update fields provided"
        )
    
    # Special handling for additional metadata
    if 'additional_metadata' in update_fields:
        update_operation['$set'] = {
            'additional_metadata': update_fields.pop('additional_metadata')
        }
    
    # Add remaining update fields
    if update_fields:
        update_operation.setdefault('$set', {}).update(update_fields)
    
    # Perform update
    updated_user = users_collection.find_one_and_update(
        {"email": current_user.email},
        update_operation,
        return_document=True  # Return the updated document
    )
    
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Convert ObjectId to string
    if '_id' in updated_user:
        updated_user['_id'] = str(updated_user['_id'])
    
    # Remove sensitive information
    updated_user.pop('hashed_password', None)
    
    # Return updated profile
    return UserProfile(**updated_user)

# get user
@router.get("/profile/metadata")
async def get_user_metadata(current_user: SignUp = Depends(get_current_user)):
    """
    Retrieve user's additional metadata
    
    Allows for custom, flexible metadata storage
    """
    user = users_collection.find_one({"email": current_user.email})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User profile not found"
        )
    
    # Return additional metadata, or empty dict if not present
    return user.get('additional_metadata', {})

@router.patch("/profile/metadata")
async def update_user_metadata(
    metadata: Dict[str, Any], 
    current_user: SignUp = Depends(get_current_user)
):
    """
    Update user's additional metadata
    
    Features:
    - Allows adding or updating custom metadata
    - Flexible key-value storage
    """
    result = users_collection.update_one(
        {"email": current_user.email},
        {"$set": {"additional_metadata": metadata}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User profile not found or no changes made"
        )
    
    return {"message": "Metadata updated successfully"}

@router.post("/check-password")
async def check_password(data: PasswordCheckRequest, current_user: dict = Depends(get_current_user)):
    """
    Check if the entered password matches the current password.
    
    Steps:
    - Retrieve the user's hashed password from the database.
    - Compare it with the entered password.
    """
    # Fetch the user's data from MongoDB
    user = users_collection.find_one({"email": current_user.email})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    # Verify the entered password with the stored hashed password
    if not verify_password(data.current_password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password."
        )

    return {"message": "Password is correct"}

@router.post("/change-password")
async def change_password(data: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    """
    Change user password with OTP verification using Firebase.
    
    Steps:
    - Verify the OTP with Firebase.
    - If OTP is valid, update the user's password in the database.
    """
        
    # Check if the user exists
    user = users_collection.find_one({"email": current_user.email})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
    # Verify the entered password with the stored hashed password
    if not verify_password(data.current_password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password."
        )
        
    # Hash the new password
    hashed_password = get_password_hash(data.new_password)
    
    # Update password in MongoDB
    users_collection.update_one(
        {"email": current_user.email},
        {"$set": {"hashed_password": hashed_password}}
    )
    
    return {"message": "Password changed successfully"}

        