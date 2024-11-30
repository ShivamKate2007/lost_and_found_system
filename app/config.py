import os
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

class Config:
    # Secret key for session management and CSRF protection
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')  # Default if not found
    
    # Database URI for SQLAlchemy
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'SQLALCHEMY_DATABASE_URI', 
        'sqlite:///D:/lost_and_found_system/instance/lost_and_found.db'
    )
    
    # Disable modification tracking to save resources
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Email configuration (Gmail SMTP)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('EMAIL_USER')  # Email username from environment variable
    MAIL_PASSWORD = os.getenv('EMAIL_PASS')  # Email password from environment variable

    # File upload configuration
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))  # Get the absolute directory of the project
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'app/static/uploads')  # Dynamically set the upload folder
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image extensions

    @staticmethod
    def allowed_file(filename):
        """Check if the file has an allowed extension."""
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS
