# Gmail SMTP configuration — credentials loaded from .env (next to this file)
import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = os.getenv('EMAIL_ADDRESS')
APP_PASSWORD = os.getenv('EMAIL_PASSWORD')
RECIPIENT_EMAIL = os.getenv('EMAIL_TO')
OTX_API_KEY = os.getenv('OTX_API_KEY')
