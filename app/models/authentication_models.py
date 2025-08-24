from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import Optional, Annotated, Dict, Any, List
from bson import ObjectId
from pydantic.json_schema import JsonSchemaValue
from datetime import date, datetime
import json

# Helper class to manage ObjectId serialization
class PyObjectId(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, value, field = None):
        if not ObjectId.is_valid(value):
            raise ValueError("Invalid ObjectId")
        return str(ObjectId(value))

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema, handler) -> JsonSchemaValue:
        return {'type': 'string'}

# New User model for authentication
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: Annotated[str, Field(alias="_id")] = Field(default_factory=lambda: str(ObjectId()))
    username: str
    email: EmailStr

class UserInDB(UserResponse):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


class DateEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, date):
            return obj.isoformat()
        elif isinstance(obj, ObjectId):
            return str(obj)
        return super().default(obj)

# Pydantic model for a Sign up
class SignUp(BaseModel):
    """
    Pydantic model representing a user signing up for an application.

    This model defines the data required for user signup, including:

    * Optional ID (used internally, not required during signup)
    * First name (must be between 1 and 50 characters)
    * Last name (must be between 1 and 50 characters)
    * Email address (must be a valid email format)
    * Phone number (must follow the specified regex pattern)
    * Date of birth (must be a valid date format)
    * Password (must be between 8 and 64 characters)

    The model also defines the following configuration:

    * `json_encoders`: Specifies how to serialize `ObjectId` instances to strings.
    * `allow_population_by_field_name`: Allows populating fields using JSON field names.
    * `arbitrary_types_allowed`: Allows handling arbitrary types during serialization/deserialization (use with caution).
    * `schema_extra`: Provides an example object for API documentation.
    """
    
    id: Optional[str] = Field(None, alias="_id")
    name: str = Field(..., min_length=1, max_length=50, example="John")
    # last_name: str = Field(..., min_length=1, max_length=50, example="Doe")
    email: EmailStr = Field(..., example="john.doe@example.com")
    phone_number: str = Field(..., pattern=r"^\+?1?\d{9,15}$", example="+1234567890")
    # date_of_birth: date = Field(..., example="2000-01-01")
    password: Optional[str] = None
    
    model_config = {
        "json_encoders": {
            ObjectId: str,
            date: lambda v: v.isoformat() if v else None
        },
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

    def model_dump(self, **kwargs):
        """
        Custom dump method to ensure date is converted to string
        """
        dump = super().model_dump(**kwargs)
        
        # Explicitly convert date to string
        if isinstance(dump.get('date_of_birth'), date):
            dump['date_of_birth'] = dump['date_of_birth'].isoformat()
        
        return dump

class SignUpInput(BaseModel):
    """
    Pydantic model representing a user signing up for an application.

    This model defines the data required for user signup, including:

    * name (must be between 1 and 50 characters)
    * Email address (must be a valid email format)
    * Phone number (must follow the specified regex pattern)
    * Password (must be between 8 and 64 characters)

    The model also defines the following configuration:

    * `json_encoders`: Specifies how to serialize `ObjectId` instances to strings.
    * `allow_population_by_field_name`: Allows populating fields using JSON field names.
    * `arbitrary_types_allowed`: Allows handling arbitrary types during serialization/deserialization (use with caution).
    * `schema_extra`: Provides an example object for API documentation.
    """
    
    # id: Optional[str] = Field(None, alias="_id")
    name: str = Field(..., min_length=1, max_length=50, example="John")
    # last_name: str = Field(..., min_length=1, max_length=50, example="Doe")
    email: EmailStr = Field(..., example="john.doe@example.com")
    phone_number: str = Field(..., pattern=r"^\+?1?\d{9,15}$", example="+1234567890")
    # date_of_birth: date = Field(..., example="2000-01-01")
    password: Optional[str] = None
    
    model_config = {
        "json_encoders": {
            ObjectId: str,
            date: lambda v: v.isoformat() if v else None
        },
        "populate_by_name": True,
        "arbitrary_types_allowed": True
    }

    def model_dump(self, **kwargs):
        """
        Custom dump method to ensure date is converted to string
        """
        dump = super().model_dump(**kwargs)
        
        # Explicitly convert date to string
        if isinstance(dump.get('date_of_birth'), date):
            dump['date_of_birth'] = dump['date_of_birth'].isoformat()
        
        return dump
    
def custom_json_encoder(obj):
    """
    Fallback JSON encoder for additional serialization handling
    """
    if isinstance(obj, date):
        return obj.isoformat()
    elif isinstance(obj, ObjectId):
        return str(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

# Pydantic model for a Log in
class Login(BaseModel):
    """
    Pydantic model representing user login credentials.

    This model defines the data required for user login, including:

    * Email address (must be a valid email format)
    * Password (must be between 8 and 128 characters)

    The model also defines the following configuration:

    * `schema_extra`: Provides an example object for API documentation.
    """
    
    email: EmailStr = Field(..., example="john.doe@example.com")
    password: str = Field(..., min_length=8, max_length=128, example="securepassword123")

    class Config:
        schema_extra = {
            "example": {
                "email": "john.doe@example.com",
                "password": "securepassword123",
            }
        }

class UserProfile(BaseModel):
    """
    Detailed user profile model for retrieving and updating user information
    
    Excludes sensitive information like passwords
    Allows for optional additional metadata
    """
    id: Optional[str] = Field(None, alias="_id")
    name: str
    # last_name: str
    email: str
    phone_number: str
    # date_of_birth: str
    profile_picture: Optional[str] = None
    bio: Optional[str] = None
    additional_metadata: Optional[Dict[str, Any]] = None

class UpdateProfileRequest(BaseModel):
    """
    Model for updating user profile
    Allows partial updates with optional fields
    """
    name: Optional[str] = None
    # last_name: Optional[str] = None
    phone_number: Optional[str] = None
    profile_picture: Optional[str] = None
    bio: Optional[str] = None
    additional_metadata: Optional[Dict[str, Any]] = None
