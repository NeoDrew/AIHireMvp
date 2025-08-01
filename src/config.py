from dotenv import load_dotenv
import os
import redis

load_dotenv()

class ApplicationConfig:
    SECRET_KEY = os.environ["SECRET_KEY"]

    SQLACHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_DATABASE_URI = r'sqlite:///./db.sqlite'

    SESSION_TYPE = "redis"
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_REDIS = redis.from_url("redis://127.0.0.1:6379")
    SESSION_COOKIE_SAMESITE = "None" if os.environ.get("FLASK_ENV") == "development" else "Lax"
    SESSION_COOKIE_SECURE = True if os.environ.get("FLASK_ENV") == "production" else False