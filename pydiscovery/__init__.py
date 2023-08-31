from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from celery import Celery
#celery -A pydiscovery.celery worker --loglevel=info
#brew install libpq --build-from-source
app = Flask(__name__)
app.secret_key = "eb8da71a31fb3af3b2381a40dc465954" 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root@localhost/app'  
#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres@mlocalhost/app'
app.config["UPLOAD_FOLDER"] = "static/user_pictures"


db = SQLAlchemy(app)

# Configure Celery
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'  
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0' 
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

#db.init_app(app)
with app.app_context():
    db.create_all()  # Create database tables

from pydiscovery import routes
