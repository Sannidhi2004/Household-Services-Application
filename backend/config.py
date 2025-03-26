import os
class Config:
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))  # Move up to root
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'data.sqlite3')}"
  # Example: SQLite
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Optional but recommended
    SECRET_KEY="shhh...secret"
    SECURITY_JOIN_USER_ROLES = True  # or False, depending on your needs
    SECURITY_PASSWORD_SALT = "some_random_salt"
    SECURITY_TOKEN_AUTHENTICATION_HEADER="Authentication-Token"
    SECURITY_TOKEN_MAX_AGE=3600
    SECURITY_TOKEN_EXPIRE_TIMESTAMP = lambda user: int(3600)
    SECURITY_API_ENABLED_METHODS = ["token", "password"]
    SECURITY_REDIRECT_BEHAVIOR = "spa"  # ✅ Prevents 302 redirects
    SECURITY_UNAUTHORIZED_VIEW= None  # Prevents redirects







# If using environment variables, set it as follows:
# os.environ.get('DATABASE_URL', 'sqlite:///site.db')


class localdev(Config):
    DEBUG=True
    
    CACHE_TYPE = "RedisCache"
    CACHE_DEFAULT_TIMEOUT = 60
    CACHE_KEY_PREFIX = "household_services"
    CACHE_REDIS_HOST = "localhost"
    CACHE_REDIS_PORT = 6379
    CACHE_REDIS_DB = 2
    
    MAIL_SERVER="localhost"
    MAIL_PORT=1025
    MAIL_DEFAULT_SENDER="household_services@abc.com"
    MAIL_DEBUG = True 
    
class celery_config():
    broker_url = 'redis://localhost:6379/0'
    result_backend = 'redis://localhost:6379/1'
    timezone = 'Asia/Kolkata'