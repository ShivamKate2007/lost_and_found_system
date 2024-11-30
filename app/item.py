import os
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from .models import db, Item

item_bp = Blueprint('item', __name__)

# Set up the upload folder and allowed file types
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to check if file type is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Create the upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@item_bp.route('/', methods=['POST'])
def add_item():
    data = request.get_json()

    # Check if the request has an image
    image = None
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            # Secure the file name and save the file
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            image = filename

    # Create a new item object
    new_item = Item(
        name=data['name'],
        description=data['description'],
        location=data['location'],
        status=data.get('status', 'lost'),  # Default to 'lost' if not provided
        user_id=data['user_id'],  # Assuming user_id is provided in the request
        image=image  # Store the image file name
    )

    # Add the item to the database
    db.session.add(new_item)
    db.session.commit()

    return jsonify({'message': 'Item added!', 'item_id': new_item.id}), 201

@item_bp.route('/', methods=['GET'])
def get_items():
    items = Item.query.all()

    # Fetch items with image paths and return as JSON
    return jsonify([{
        'id': item.id,
        'name': item.name,
        'status': item.status,
        'image': item.image  # Include image in the response
    } for item in items])
