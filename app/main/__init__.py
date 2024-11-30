from flask import Blueprint

# Initialize the main blueprint
main = Blueprint('main', __name__)

# Import routes to register them with the blueprint
from . import routes

