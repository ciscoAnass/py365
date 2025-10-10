import re
import hashlib
import string
import random
from typing import List, Dict
from flask import Flask, request, render_template_string

app = Flask(__name__)

COMMON_PASSWORDS = {
    'password', '123456', 'qwerty', 'admin', 'welcome', 
    'letmein', 'password123', 'abc123', 'monkey', 'dragon'
}

def generate_salt() -> str:
    """Generate a random salt for additional password complexity."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(16))

def calculate_entropy(password: str) -> float:
    """Calculate password entropy based on character set complexity."""
    character_sets = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation
    ]
    unique_chars = set(password)
    possible_chars = set()
    for char_set in character_sets:
        if any(char in char_set for char in unique_chars):
            possible_chars.update(char_set)
    
    entropy = len(password) * (len(possible_chars) / len(password)) if password else 0
    return round(entropy, 2)

def check_password_strength(password: str) -> Dict[str, Any]:
    """Comprehensive password strength analysis."""
    if not password:
        return {
            'strength': 'Invalid',
            'score': 0,
            'feedback': 'Password cannot be empty'
        }

    # Length check
    length_score = min(len(password) * 2, 20)
    
    # Character variety checks
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    
    variety_score = (
        (4 if has_lowercase else 0) +
        (4 if has_uppercase else 0) +
        (4 if has_digit else 0) +
        (4 if has_symbol else 0)
    )
    
    # Common password check
    common_password_penalty = 20 if password.lower() in COMMON_PASSWORDS else 0
    
    # Entropy calculation
    entropy = calculate_entropy(password)
    entropy_score = min(entropy * 2, 20)
    
    # Total score calculation
    total_score = length_score + variety_score + entropy_score - common_password_penalty
    total_score = max(0, min(total_score, 100))
    
    # Strength categorization
    if total_score < 30:
        strength = 'Very Weak'
    elif total_score < 50:
        strength = 'Weak'
    elif total_score < 70:
        strength = 'Moderate'
    elif total_score < 90:
        strength = 'Strong'
    else:
        strength = 'Very Strong'
    
    return {
        'strength': strength,
        'score': total_score,
        'feedback': {
            'length': f"Length: {len(password)} characters",
            'lowercase': f"Lowercase: {'✓' if has_lowercase else '✗'}",
            'uppercase': f"Uppercase: {'✓' if has_uppercase else '✗'}",
            'digits': f"Digits: {'✓' if has_digit else '✗'}",
            'symbols': f"Symbols: {'✓' if has_symbol else '✗'}",
            'entropy': f"Entropy: {entropy}"
        }
    }

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Password Strength Checker</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
        .result { margin-top: 20px; padding: 15px; border-radius: 5px; }
        .very-weak { background-color: #ffcccc; color: #990000; }
        .weak { background-color: #fff0cc; color: #cc6600; }
        .moderate { background-color: #ccffcc; color: #006600; }
        .strong { background-color: #ccffff; color: #0066cc; }
        .very-strong { background-color: #e6ccff; color: #660099; }
    </style>
</head>
<body>
    <h1>Password Strength Checker</h1>
    <form method="POST">
        <input type="password" name="password" placeholder="Enter your password" required>
        <button type="submit">Check Strength</button>
    </form>
    {% if result %}
    <div class="result {{ result.strength.lower().replace(' ', '-') }}">
        <h2>Result: {{ result.strength }}</h2>
        <p>Score: {{ result.score }}/100</p>
        <h3>Details:</h3>
        <ul>
            {% for key, value in result.feedback.items() %}
            <li>{{ value }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def password_checker():
    result = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        result = check_password_strength(password)
    return render_template_string(HTML_TEMPLATE, result=result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)