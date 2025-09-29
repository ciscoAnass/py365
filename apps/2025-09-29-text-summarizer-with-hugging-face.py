import os
import requests
from flask import Flask, request, render_template_string
from transformers import pipeline
from bs4 import BeautifulSoup

app = Flask(__name__)

SUMMARIZER_MODEL = pipeline("summarization", model="facebook/bart-large-cnn")

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Text Summarizer</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        textarea { width: 100%; height: 200px; margin-bottom: 10px; }
        .summary { background-color: #f4f4f4; padding: 15px; border-radius: 5px; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>Text Summarizer</h1>
    <form method="POST">
        <label>Enter Text or URL:</label>
        <textarea name="input_text" placeholder="Paste long text or enter a URL"></textarea>
        <br>
        <label>Summary Length (%):</label>
        <input type="number" name="summary_ratio" min="10" max="90" value="30">
        <br>
        <input type="submit" value="Generate Summary">
    </form>
    {% if summary %}
    <div class="summary">
        <h2>Summary:</h2>
        <p>{{ summary }}</p>
    </div>
    {% endif %}
    {% if error %}
    <div class="error">
        <p>{{ error }}</p>
    </div>
    {% endif %}
</body>
</html>
'''

def extract_text_from_url(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Try multiple strategies to extract main content
        article_tags = ['article', 'main', 'div.content', 'div.article-body']
        
        for tag in article_tags:
            content = soup.select_one(tag)
            if content:
                return content.get_text(strip=True)
        
        # Fallback to full body text
        return soup.get_text(strip=True)
    
    except Exception as e:
        raise ValueError(f"Could not extract text from URL: {e}")

def generate_summary(text, summary_ratio=30):
    if not text:
        raise ValueError("No text provided")
    
    # Compute max length based on input text and ratio
    max_length = max(50, int(len(text.split()) * (summary_ratio/100)))
    min_length = max(10, int(max_length * 0.5))
    
    try:
        summary = SUMMARIZER_MODEL(
            text, 
            max_length=max_length, 
            min_length=min_length, 
            do_sample=False
        )[0]['summary_text']
        
        return summary
    except Exception as e:
        raise ValueError(f"Summarization failed: {e}")

@app.route('/', methods=['GET', 'POST'])
def summarize():
    summary = None
    error = None
    
    if request.method == 'POST':
        input_text = request.form.get('input_text', '').strip()
        summary_ratio = int(request.form.get('summary_ratio', 30))
        
        try:
            # Check if input looks like a URL
            if input_text.startswith(('http://', 'https://')):
                input_text = extract_text_from_url(input_text)
            
            summary = generate_summary(input_text, summary_ratio)
        
        except ValueError as ve:
            error = str(ve)
    
    return render_template_string(HTML_TEMPLATE, summary=summary, error=error)

def main():
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

if __name__ == '__main__':
    main()