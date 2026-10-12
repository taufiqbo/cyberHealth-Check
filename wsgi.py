"""Entry point for gunicorn (see Dockerfile). Use one worker process: the job queue runs in it."""
from app import create_app

app = create_app()
