import os
import io
import hashlib
from datetime import datetime
from typing import Tuple, Optional
from functools import lru_cache

from flask import Flask, request, send_file
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)

CACHE_DIR = 'cache'
os.makedirs(CACHE_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_IMAGE_SIZE = (2048, 2048)
WATERMARK_FONT = ImageFont.truetype('arial.ttf', size=36)
WATERMARK_OPACITY = 0.5

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_cache_key(image_file: bytes, width: int, height: int, watermark: Optional[str]) -> str:
    key_parts = [
        image_file,
        str(width),
        str(height),
        watermark or ''
    ]
    key = '|'.join(key_parts)
    return hashlib.md5(key.encode()).hexdigest()

@lru_cache(maxsize=1024)
def process_image(image_file: bytes, width: int, height: int, watermark: Optional[str]) -> bytes:
    image = Image.open(io.BytesIO(image_file))
    image.thumbnail((width, height), resample=Image.BICUBIC)

    if watermark:
        draw = ImageDraw.Draw(image)
        text_width, text_height = draw.textsize(watermark, font=WATERMARK_FONT)
        x = image.width - text_width - 10
        y = image.height - text_height - 10
        draw.text((x, y), watermark, font=WATERMARK_FONT, fill=(255, 255, 255, int(255 * WATERMARK_OPACITY)))

    output = io.BytesIO()
    image.save(output, format=image.format)
    return output.getvalue()

@app.route('/resize', methods=['POST'])
def resize_image():
    if 'file' not in request.files:
        return 'No file uploaded', 400

    file = request.files['file']
    if file.filename == '':
        return 'No file selected', 400

    if file and allowed_file(file.filename):
        width = request.form.get('width', type=int)
        height = request.form.get('height', type=int)
        watermark = request.form.get('watermark')

        if width is None or height is None:
            return 'Width and height are required', 400

        if width > MAX_IMAGE_SIZE[0] or height > MAX_IMAGE_SIZE[1]:
            return f'Maximum image size is {MAX_IMAGE_SIZE[0]}x{MAX_IMAGE_SIZE[1]}', 400

        cache_key = get_cache_key(file.read(), width, height, watermark)
        cache_file = os.path.join(CACHE_DIR, cache_key)

        if os.path.exists(cache_file):
            return send_file(cache_file, mimetype=file.content_type)

        processed_image = process_image(file.read(), width, height, watermark)
        with open(cache_file, 'wb') as f:
            f.write(processed_image)

        return send_file(io.BytesIO(processed_image), mimetype=file.content_type)
    else:
        return 'Invalid file type', 400

if __name__ == '__main__':
    app.run(debug=True)