import sys
import os

# Add the parent directory to the path to import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from main import app

# This is the entry point for Vercel
application = app

if __name__ == "__main__":
    app.run()