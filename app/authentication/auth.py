from datetime import datetime, timedelta
from typing import Optional, Annotated
from dotenv import load_dotenv
import os

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.models.authentication_models import SignUp  # Adjust import as needed
from app.database.mongodb import get_collection

load_dotenv()

# Security configurations
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ACCESS_TOKEN_EXPIRE_DAYS = 7

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password bearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Users collection
users_collection = get_collection("users")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a hashed password
    
    Args:
        plain_password (str): The password to verify
        hashed_password (str): The stored hashed password
    
    Returns:
        bool: True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Hash a plain text password
    
    Args:
        password (str): The password to hash
    
    Returns:
        str: The hashed password
    """
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token
    
    Args:
        data (dict): The data to encode in the token
        expires_delta (Optional[timedelta]): Token expiration time
    
    Returns:
        str: Encoded JWT token
    """
    to_encode = data.copy()
    
    # Set expiration time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    
    # Encode the token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt

def get_user(email: str) -> Optional[SignUp]:
    """
    Retrieve a user from the database by email
    
    Args:
        email (str): User's email address
    
    Returns:
        Optional[SignUp]: User object if found, None otherwise
    """
    user_dict = users_collection.find_one({"email": email})
    
    if user_dict:
        # Convert ObjectId to string if present
        if '_id' in user_dict:
            user_dict['_id'] = str(user_dict['_id'])
        
        # Remove hashed password before returning
        user_dict.pop('hashed_password', None)
        
        return SignUp(**user_dict)
    
    return None

def get_current_user(token: str = Depends(oauth2_scheme)) -> SignUp:
    """
    Get the current authenticated user from the JWT token
    
    Args:
        token (str): JWT access token
    
    Returns:
        SignUp: Authenticated user object
    
    Raises:
        HTTPException: If credentials cannot be validated
    """
    # Exception for unauthorized access
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Extract email from token
        email: str = payload.get("sub")
        
        if email is None:
            raise credentials_exception
    
    except JWTError:
        raise credentials_exception
    
    # Retrieve user from database
    user = get_user(email)
    
    if user is None:
        raise credentials_exception
    
    return user