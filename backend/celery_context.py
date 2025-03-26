from app import create_app
from celery import Task

app = create_app()
class flask_context(Task):
    def __call__(self, *args, **kwargs):
        with app.app_context():
            return Task.__call__(self, *args, **kwargs)