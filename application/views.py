from flask import current_app as app

@app.get('/')
def home():
    return "Hello world"