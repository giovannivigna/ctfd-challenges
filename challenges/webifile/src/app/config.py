# timeout=10: fail fast if DB locked instead of hanging
SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db?timeout=10'
SQLALCHEMY_ECHO = True
SQLALCHEMY_RECORD_QUERIES = True
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = 'SessionSuperSecretKey'
DEBUG = True
