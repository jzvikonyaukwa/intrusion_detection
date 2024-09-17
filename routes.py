from flask import Blueprint, render_template, request, jsonify,send_from_directory

import json  # Import the json module
from datetime import datetime  # Import the datetime module
main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')
@main.route('/alerts.json')
def get_alerts():
    print(send_from_directory(directory='.', path='alerts.json'))
    return send_from_directory(directory='.', path='alerts.json')


