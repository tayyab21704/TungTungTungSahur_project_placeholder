from pymongo import MongoClient
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# MongoDB connection string from MongoDB Atlas
MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")

# Initialize the MongoDB client
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]

def get_collection(collection_name: str):
    return db[collection_name]