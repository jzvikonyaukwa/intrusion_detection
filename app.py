from flask import Flask
from extensions import socketio
from capture_and_log import setup_event_listeners
from routes import main 

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret!'
    app.register_blueprint(main)
    socketio.init_app(app)
    return app

if __name__ == '__main__':
    app = create_app()
    
    setup_event_listeners(socketio)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)

