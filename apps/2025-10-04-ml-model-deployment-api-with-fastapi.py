import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np
import pickle

app = FastAPI()

class IrisRequest(BaseModel):
    sepal_length: float
    sepal_width: float
    petal_length: float
    petal_width: float

class ModelTrainer:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.train_model()

    def train_model(self):
        iris = load_iris()
        X, y = iris.data, iris.target
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train_scaled, y_train)

    def predict(self, features):
        features_scaled = self.scaler.transform([features])
        return self.model.predict(features_scaled)[0]

model_trainer = ModelTrainer()

@app.post("/predict")
async def predict_iris(request: IrisRequest):
    features = [
        request.sepal_length,
        request.sepal_width,
        request.petal_length,
        request.petal_width
    ]
    prediction = model_trainer.predict(features)
    iris_classes = ['Setosa', 'Versicolor', 'Virginica']
    return {"prediction": iris_classes[prediction]}

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Iris Classifier API</title>
        <style>
            body { font-family: Arial; max-width: 600px; margin: 0 auto; padding: 20px; }
            form { background: #f4f4f4; padding: 20px; border-radius: 5px; }
            input { width: 100%; margin: 10px 0; padding: 10px; }
            button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; }
        </style>
    </head>
    <body>
        <h1>Iris Flower Classifier</h1>
        <form id="predictionForm">
            <input type="number" step="0.1" id="sepalLength" placeholder="Sepal Length" required>
            <input type="number" step="0.1" id="sepalWidth" placeholder="Sepal Width" required>
            <input type="number" step="0.1" id="petalLength" placeholder="Petal Length" required>
            <input type="number" step="0.1" id="petalWidth" placeholder="Petal Width" required>
            <button type="submit">Predict Iris Species</button>
        </form>
        <div id="result"></div>
        <script>
            document.getElementById('predictionForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const data = {
                    sepal_length: parseFloat(document.getElementById('sepalLength').value),
                    sepal_width: parseFloat(document.getElementById('sepalWidth').value),
                    petal_length: parseFloat(document.getElementById('petalLength').value),
                    petal_width: parseFloat(document.getElementById('petalWidth').value)
                };
                
                try {
                    const response = await fetch('/predict', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(data)
                    });
                    const result = await response.json();
                    document.getElementById('result').innerText = `Predicted Species: ${result.prediction}`;
                } catch (error) {
                    console.error('Error:', error);
                }
            });
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)