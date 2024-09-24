from dotenv import load_dotenv
import os
from app import app  # Importing app here

load_dotenv()


UPLOAD_FOLDER = os.path.abspath(os.path.join(os.getcwd(), 'static', 'uploads'))
ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'pdf,png,jpg,jpeg').split(','))

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///db.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_default_secret_key')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

print('configured')

