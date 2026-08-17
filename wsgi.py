"""
Production entry point. A WSGI server (gunicorn, waitress, Azure App
Service's default runner, etc.) points at `wsgi:app` instead of running
app.py's dev server directly.

Example: gunicorn wsgi:app
"""

from app import app

if __name__ == "__main__":
    app.run()
