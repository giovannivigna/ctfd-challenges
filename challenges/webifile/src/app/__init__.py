import os
from flask import Flask
from database import db
from pprint import pprint

def create_app():
    # Use instance path under app dir so non-root user can write (database, etc.)
    instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    app = Flask(__name__, instance_path=instance_path)
    app.config.from_pyfile('config.py')
    db.init_app(app)
    with app.app_context():
        db.create_all()

    return app