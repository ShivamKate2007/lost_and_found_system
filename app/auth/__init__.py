from flask import Flask
from flask import Blueprint

# Create the auth blueprint
auth = Blueprint('auth', __name__)

# Import routes to register them with the blueprint
from . import routes

