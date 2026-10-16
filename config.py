# -*- coding: utf-8 -*-
import os
from dotenv import load_dotenv

load_dotenv()

PORT = int(os.getenv('PORT', 8000))
HOST = os.getenv('HOST', '0.0.0.0')
SECRET_KEY = os.getenv('SECRET_KEY', 'change-me')
BOT_TOKEN = os.getenv('BOT_TOKEN', '')
OWNER_ID = int(os.getenv('OWNER_ID', 0))
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./daraa.db')
DB_FILE = 'daraa.db'
DOMAIN = os.getenv('DOMAIN', 'http://localhost:8000')

PLANS = {
    'free': {'name': 'Free', 'price': 0, 'duration_days': 7, 'scans': 5},
    'pro': {'name': 'Pro', 'price': 50000, 'duration_days': 30, 'scans': 100},
    'enterprise': {'name': 'Enterprise', 'price': 500000, 'duration_days': 365, 'scans': 999999},
}