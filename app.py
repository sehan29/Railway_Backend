import binascii
import json
from flask import Flask, make_response, request, jsonify, send_file, send_from_directory
from pymongo import MongoClient
from bson import ObjectId
import random
import jwt
from datetime import datetime, timedelta, timezone
import os
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from bson.errors import InvalidId
import base64
import uuid
import pytz

# Initialize Flask
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*",engineio_logger=True, logger=True,ping_timeout=120,ping_interval=30,async_mode='threading',max_http_buffer_size=100 * 1024 * 1024,    http_compression=True,allow_upgrades=True , supports_credentials=True
)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif','aac','mp3'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

           
# MongoDB Connection
client = MongoClient("mongodb+srv://sehandeveloper:GpGeUDiy11QAxqeJ@cluster0.s5hyu.mongodb.net/")
db = client["chat_app"]
users_collection = db["users"]
otp_collection = db["otp_store"]
connections_collection = db["connections"]
messages_collection = db["messages"]
group_messages_collection = db["group_messages"]
deleted_groups_collection = db["deleted_groups"]
calls_collection = db["calls"]


# Create indexes for better performance
messages_collection.create_index([("sender_id", 1), ("receiver_id", 1)])
messages_collection.create_index([("timestamp", -1)])
messages_collection.create_index([("read", 1)])

online_users = {}
user_sockets = {}  # Maps user_id to socket_id
call_rooms = {}  # Stores active call rooms


# JWT Secret Key
SECRET_KEY = "SH123456"
ALGORITHM = "HS256"

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
# Helper Functions
def create_jwt(email):
    payload = {
        "email": email, 
        "exp": datetime.now(timezone.utc) + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

def generate_otp():
    return str(random.randint(100000, 999999))

def user_exists(email):
    return users_collection.find_one({"email": email}) is not None

def store_otp(email, otp):
    otp_collection.update_one(
        {"email": email},
        {"$set": {"otp": otp, "created_at": datetime.now(timezone.utc)}},
        upsert=True
    )

def verify_stored_otp(email, otp):
    record = otp_collection.find_one({"email": email})
    if record and record["otp"] == otp:
        otp_collection.delete_one({"email": email})
        return True
    return False

def serialize_user(user):
    return {
        "id": str(user["_id"]),
        "name": user.get("name", ""),
        "email": user.get("email", ""),
        "profile_pic": user.get("profile_pic", "default.jpg")
    }

# Routes

@app.route("/",methods=["GET"])
def home():
    return "<h1>My Name is Shehan </h1>"


@app.route("/send-otp", methods=["POST"])
def send_otp():
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    otp = generate_otp()
    store_otp(email, otp)
    print(f"OTP for {email}: {otp}")
    return jsonify({"message": "OTP sent successfully"})

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = request.json.get("email")
    otp = request.json.get("otp")
    
    if not all([email, otp]):
        return jsonify({"error": "Email and OTP are required"}), 400
        
    if verify_stored_otp(email, otp):
        user = users_collection.find_one({"email": email})
        if user:
            token = create_jwt(email)
            return jsonify({
                "message": "Login successful", 
                "token": token, 
                "user": serialize_user(user)
            })
        return jsonify({"message": "New user, enter name and profile picture"})
    return jsonify({"error": "Invalid OTP"}), 400

@app.route("/register", methods=["POST"])
def register_user():
    email = request.json.get("email")
    name = request.json.get("name")
    profile_pic_base64 = request.json.get("profile_pic")

    
    if not all([email, name]):
        return jsonify({"error": "Email and name are required"}), 400
        
    if user_exists(email):
        return jsonify({"error": "User already exists"}), 400
    
    profile_pic_data = profile_pic_base64 if profile_pic_base64 else None

    if profile_pic_base64:
        try:
            # Decode base64
            image_data = base64.b64decode(profile_pic_base64.split(",")[-1])
            
            # Generate filename
            # Extract file type from base64 header
            file_header = profile_pic_base64.split(",")[0]
            file_extension = "jpg"  # default
            if "image/" in file_header:
                file_extension = file_header.split("image/")[1].split(";")[0]
            filename = f"profile_{uuid.uuid4()}.{file_extension}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            if len(image_data) > 5 * 1024 * 1024:  # 5MB limit
                return jsonify({"error": "Image too large (max 5MB)"}), 400

            allowed_types = {"jpeg", "jpg", "png", "gif"}
            if file_extension.lower() not in allowed_types:
                return jsonify({"error": "Invalid image format"}), 400

            # Save file
            with open(filepath, 'wb') as f:
                f.write(image_data)
                
            # Store relative path
            profile_pic_url = f"/uploads/{filename}"
            
        except binascii.Error as e:
            print(f"Base64 decode error: {str(e)}")
            return jsonify({"error": "Invalid image data"}), 400
        except IOError as e:
            print(f"File save error: {str(e)}")
            return jsonify({"error": "Failed to save profile picture"}), 500
                    
    user_data = {
        "email": email, 
        "name": name, 
        "profile_pic": profile_pic_url,
        "connections": [],
        "registered_at": datetime.now(timezone.utc)
    }
    
    try:
        user_id = users_collection.insert_one(user_data).inserted_id
        token = create_jwt(email)
        user = users_collection.find_one({"_id": user_id})
        
        return jsonify({
            "message": "User registered successfully",
            "token": token,
            "userId": str(user_id),
            "profilePicUrl": profile_pic_url,
            "user": serialize_user(user)
        })
    except Exception as e:
         if profile_pic_url and os.path.exists(filepath):
            os.remove(filepath)
         raise e
        #return jsonify({"error": str(e)}), 500
 
# Auto-login Route
@app.route("/auto-login", methods=["GET"])
def auto_login():
    token = request.args.get("token")
    decoded_data = decode_jwt(token)
    if "error" in decoded_data:
        return jsonify({"error": decoded_data["error"]}), 401
    
    user = users_collection.find_one({"email": decoded_data["email"]})
    if user:
        return jsonify({"message": "User logged in", "user": serialize_user(user)})
    return jsonify({"error": "User not found"}), 404

# Logout Route
@app.route("/logout", methods=["POST"])
def logout():
    return jsonify({"message": "User logged out successfully"})
 
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
