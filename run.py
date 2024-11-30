import os
import sys
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from the .env file

# Add the 'app' directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'app')))

# Now you can import create_app and db from the app module
from app import create_app, db  # This should now work fine

app = create_app()

# Print the database URI to check if it's set correctly
print("Database URI:", app.config['SQLALCHEMY_DATABASE_URI'])

# Use the app context to create all tables in the database
with app.app_context():
    db.create_all()  # Create tables in the database

if __name__ == "__main__":
    app.run(debug=True, port=5003)



