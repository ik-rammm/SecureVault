from app import create_app, socketio
import os

app = create_app()

if __name__ == '__main__':
    debug = os.environ.get('FLASK_ENV') == 'development'
    socketio.run(app, host='0.0.0.0', port=5000, debug=debug, use_reloader=False, allow_unsafe_werkzeug=True)
