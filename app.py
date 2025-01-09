# Password Strength Analyzer using Flask (Full Stack Project)

from flask import Flask, render_template, request, jsonify
import re
import requests

app = Flask(__name__)

# Function to calculate password strength
def calculate_strength(password):
    score = 0
    suggestions = []

    # Criteria: Password length
    if len(password) >= 12:
        score += 20
    else:
        suggestions.append("Use at least 12 characters.")

    # Criteria: Upper and lowercase letters
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        score += 20
    else:
        suggestions.append("Include both uppercase and lowercase letters.")

    # Criteria: Numbers
    if re.search(r'\d', password):
        score += 20
    else:
        suggestions.append("Add some numbers.")

    # Criteria: Special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 20
    else:
        suggestions.append("Include special characters (e.g., @, #, $).")

    # Criteria: Avoid common patterns
    common_patterns = ['12345', 'password', 'qwerty', 'letmein']
    if any(pattern in password.lower() for pattern in common_patterns):
        suggestions.append("Avoid common patterns like '12345' or 'password'.")
    else:
        score += 20

    return score, suggestions

# Optional: Check if password is in a known data breach
def check_breach(password):
    hashed_password = requests.utils.quote(password)
    response = requests.get(f"https://api.pwnedpasswords.com/range/{hashed_password[:5]}")
    return hashed_password in response.text

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    password = data.get('password', '')

    if not password:
        return jsonify({"error": "Password cannot be empty"}), 400

    score, suggestions = calculate_strength(password)
    breached = check_breach(password)

    return jsonify({
        "score": score,
        "suggestions": suggestions,
        "breached": breached
    })

if __name__ == '__main__':
    app.run(debug=True)
