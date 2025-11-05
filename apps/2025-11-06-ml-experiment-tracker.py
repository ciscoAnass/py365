import sqlite3
import os
import json
import uuid
import datetime
from flask import Flask, request, render_template_string, redirect, send_file
import matplotlib.pyplot as plt
import io
import base64

app = Flask(__name__)

DB_PATH = 'experiments.db'

def init_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS experiments (
            id TEXT PRIMARY KEY,
            name TEXT,
            model_type TEXT,
            hyperparameters TEXT,
            metrics TEXT,
            timestamp DATETIME,
            artifacts TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_experiment(name, model_type, hyperparameters, metrics, artifacts=None):
    exp_id = str(uuid.uuid4())
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO experiments 
        (id, name, model_type, hyperparameters, metrics, timestamp, artifacts) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        exp_id, 
        name, 
        model_type, 
        json.dumps(hyperparameters), 
        json.dumps(metrics), 
        datetime.datetime.now(), 
        json.dumps(artifacts or [])
    ))
    conn.commit()
    conn.close()
    return exp_id

def get_experiments():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM experiments ORDER BY timestamp DESC')
    columns = [column[0] for column in cursor.description]
    experiments = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    return experiments

def generate_plot(data, title):
    plt.figure(figsize=(10, 5))
    plt.plot(data)
    plt.title(title)
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')
    return graphic

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>ML Experiment Tracker</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .artifact { max-width: 300px; }
    </style>
</head>
<body>
    <h1>ML Experiment Tracker</h1>
    
    <h2>Log New Experiment</h2>
    <form method="POST" action="/log">
        <input type="text" name="name" placeholder="Experiment Name" required>
        <input type="text" name="model_type" placeholder="Model Type" required>
        <textarea name="hyperparameters" placeholder="Hyperparameters (JSON)" required></textarea>
        <textarea name="metrics" placeholder="Metrics (JSON)" required></textarea>
        <input type="submit" value="Log Experiment">
    </form>

    <h2>Experiments</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Model Type</th>
                <th>Hyperparameters</th>
                <th>Metrics</th>
                <th>Timestamp</th>
            </tr>
        </thead>
        <tbody>
            {% for exp in experiments %}
            <tr>
                <td>{{ exp.id }}</td>
                <td>{{ exp.name }}</td>
                <td>{{ exp.model_type }}</td>
                <td>{{ exp.hyperparameters }}</td>
                <td>{{ exp.metrics }}</td>
                <td>{{ exp.timestamp }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
'''

@app.route('/')
def index():
    experiments = get_experiments()
    return render_template_string(HTML_TEMPLATE, experiments=experiments)

@app.route('/log', methods=['POST'])
def log_experiment():
    name = request.form['name']
    model_type = request.form['model_type']
    hyperparameters = json.loads(request.form['hyperparameters'])
    metrics = json.loads(request.form['metrics'])
    
    exp_id = save_experiment(name, model_type, hyperparameters, metrics)
    return redirect('/')

def main():
    init_database()
    app.run(debug=True, port=5000)

if __name__ == '__main__':
    main()