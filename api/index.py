import sys
import os

# Add root workspace directory to sys.path for Vercel serverless runtime
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app

# Vercel serverless function entrypoint
# 'app' is the WSGI application instance
