from flask import Flask
from dotenv import load_dotenv
from flask_cors import CORS

load_dotenv()

def create_app():
    app = Flask(__name__)
    # load config
    from .config import Config
    app.config.from_object(Config)

    # enable CORS for dev (customise origins for production)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # register routes
    from .routes import bp
    app.register_blueprint(bp, url_prefix="/api")

    return app
