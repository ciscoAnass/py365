import os
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.image import load_img, img_to_array
from tensorflow.keras.applications.mobilenet_v2 import preprocess_input, MobileNetV2
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Dense, GlobalAveragePooling2D
from tensorflow.keras.optimizers import Adam
from flask import Flask, request, jsonify, render_template_string
import base64
import io
from PIL import Image

app = Flask(__name__)

def create_model():
    base_model = MobileNetV2(weights='imagenet', include_top=False, input_shape=(224, 224, 3))
    x = base_model.output
    x = GlobalAveragePooling2D()(x)
    x = Dense(1024, activation='relu')(x)
    predictions = Dense(2, activation='softmax')(x)
    model = Model(inputs=base_model.input, outputs=predictions)
    
    for layer in base_model.layers:
        layer.trainable = False
    
    model.compile(optimizer=Adam(learning_rate=0.0001), 
                  loss='categorical_crossentropy', 
                  metrics=['accuracy'])
    return model

def train_model(model, train_data, train_labels):
    model.fit(train_data, train_labels, 
              epochs=10, 
              batch_size=32, 
              validation_split=0.2)
    return model

def prepare_image(image, target_size=(224, 224)):
    if isinstance(image, str):
        image = Image.open(io.BytesIO(base64.b64decode(image)))
    image = image.convert('RGB')
    image = image.resize(target_size)
    image_array = img_to_array(image)
    image_array = np.expand_dims(image_array, axis=0)
    image_array = preprocess_input(image_array)
    return image_array

def generate_dummy_data():
    num_samples = 1000
    train_data = np.random.random((num_samples, 224, 224, 3))
    train_labels = np.zeros((num_samples, 2))
    train_labels[0:500, 0] = 1  # First half cats
    train_labels[500:, 1] = 1   # Second half dogs
    return train_data, train_labels

@app.route('/', methods=['GET'])
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Image Classification</title>
        <style>
            body { font-family: Arial; max-width: 600px; margin: auto; padding: 20px; }
            input, button { margin: 10px 0; }
        </style>
    </head>
    <body>
        <h1>Image Classification</h1>
        <form id="uploadForm" enctype="multipart/form-data">
            <input type="file" id="imageUpload" accept="image/*">
            <button type="button" onclick="uploadImage()">Classify</button>
        </form>
        <div id="result"></div>
        <script>
            function uploadImage() {
                var file = document.getElementById('imageUpload').files[0];
                var reader = new FileReader();
                reader.onloadend = function() {
                    fetch('/predict', {
                        method: 'POST',
                        body: JSON.stringify({image: reader.result.split(',')[1]}),
                        headers: {'Content-Type': 'application/json'}
                    })
                    .then(response => response.json())
                    .then(data => {
                        document.getElementById('result').innerHTML = 
                            `Prediction: ${data.class} (${(data.confidence * 100).toFixed(2)}%)`;
                    });
                }
                reader.readAsDataURL(file);
            }
        </script>
    </body>
    </html>
    ''')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    image = prepare_image(data['image'])
    prediction = model.predict(image)
    class_names = ['Cat', 'Dog']
    predicted_class = class_names[np.argmax(prediction)]
    confidence = np.max(prediction)
    return jsonify({
        'class': predicted_class,
        'confidence': float(confidence)
    })

if __name__ == '__main__':
    model = create_model()
    train_data, train_labels = generate_dummy_data()
    model = train_model(model, train_data, train_labels)
    app.run(debug=True)