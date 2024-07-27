from flask import Flask, request, render_template, redirect, url_for
import hashlib
import json

app = Flask(__name__)

# Load the JSON database
def load_db():
    with open('database.json', 'r') as file:
        return json.load(file)

db = load_db()

# Load the config
def load_config():
    config = {}
    with open('config.txt', 'r') as file:
        for line in file:
            line = line.strip()
            if line and '=' in line:
                key, value = line.split('=', 1)
                config[key] = value
    return config

config = load_config()

@app.route('/')
def index():
    return render_template('verify.html')

@app.route('/verify', methods=['POST'])
def verify():
    user_answer = request.form['answer'].strip()
    user_hashes = {
        'hash1': request.form['hash1'].strip(),
        'hash2': request.form['hash2'].strip(),
        'hash3': request.form['hash3'].strip(),
        'hash4': request.form['hash4'].strip()
    }
    
    # Check the answer
    if user_answer != config['answer']:
        return render_template('verify.html', error="Incorrect answer.")
    
    # Check the hashes
    correct_hashes = {
        'hash1': "12345678",
        'hash2': "123456789",
        'hash3': "1234",
        'hash4': "12345"
    }
    
    for key, value in correct_hashes.items():
        if user_hashes[key] != value:
            return render_template('verify.html', error=f"Incorrect value for {key}.")
    
    # If all are correct, redirect to the main page
    return redirect(url_for('main'))

@app.route('/main')
def main():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    user_input = request.form['id']
    try:
        # Hardcoded payloads for demonstration purposes
        valid_payloads = [
            "1 OR 1=1",
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' /*",
            "1 OR 1=1--",
            "1' OR '1'='1'--",
            "1=1"
        ]
        
        if user_input.strip() in valid_payloads:
            # If the input matches any of the valid payloads, return the flag
            return render_template('search.html', result=f"Flag: {db['flags'][0]['flag']}")
        
        # Otherwise, treat the input as a regular ID lookup
        query = f"SELECT flag FROM flags WHERE id = {user_input}"
        print(f"Executing query: {query}")  # Debugging purpose

        results = []
        for entry in db['flags']:
            if str(entry['id']) == user_input:
                results.append(entry['flag'])
        
        if results:
            return render_template('search.html', result=f"Flag: {results[0]}")
        else:
            return render_template('search.html', result="No flag found")
    except Exception as e:
        return render_template('search.html', result=f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(debug=True)

