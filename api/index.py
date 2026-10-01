import sys
import os

# Add root workspace directory to sys.path for Vercel serverless runtime
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app as flask_app

class VercelMiddleware:
    """
    WSGI Middleware to normalize PATH_INFO for Vercel Serverless Functions.
    Vercel sets HTTP_X_MATCHED_PATH with the original request path from the browser.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        matched_path = environ.get('HTTP_X_MATCHED_PATH')
        if matched_path:
            environ['PATH_INFO'] = matched_path
        else:
            path = environ.get('PATH_INFO', '')
            if path.startswith('/api/index.py'):
                new_path = path[len('/api/index.py'):]
                environ['PATH_INFO'] = new_path if new_path.startswith('/') else ('/' + new_path)
            elif path.startswith('/api/index'):
                new_path = path[len('/api/index'):]
                environ['PATH_INFO'] = new_path if new_path.startswith('/') else ('/' + new_path)
            elif path in ('/api', '/api/'):
                environ['PATH_INFO'] = '/'

        return self.wsgi_app(environ, start_response)

# Vercel entrypoint
app = VercelMiddleware(flask_app)
