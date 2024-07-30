from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Correct classifications using 1 for phishing and 2 for safe
correct_answers = {
    'email1': '1',  # Phishing
    'email2': '2',  # Safe
    'email3': '1',  # Phishing
    'email4': '2',  # Safe
    'email5': '1',  # Phishing
    'email6': '2',  # Safe
    'email7': '1'   # Phishing
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_crackland', methods=['POST'])
def start_crackland():
    return redirect(url_for('verify'))

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        user_hashes = {
            'hash1': request.form['hash1'].strip(),
            'hash2': request.form['hash2'].strip(),
            'hash3': request.form['hash3'].strip(),
            'hash4': request.form['hash4'].strip()
        }

        correct_hashes = {
            'hash1': "password",
            'hash2': "123456",
            'hash3': "qwerty",
            'hash4': "abc123"
        }

        incorrect = []
        for key, value in correct_hashes.items():
            if user_hashes[key] != value:
                incorrect.append(key)

        if incorrect:
            error_message = f"Incorrect value(s) for: {', '.join(incorrect)}."
            return render_template('verify.html', error=error_message)

        return redirect(url_for('sql_start'))

    return render_template('verify.html')

@app.route('/sql_start')
def sql_start():
    return render_template('sql_start.html')

@app.route('/perform_sql', methods=['GET', 'POST'])
def perform_sql():
    if request.method == 'POST':
        user_input = request.form['user_input']
        successful_payloads = [
            "1' OR '1'='1", "' OR '1'='1", "1 OR 1=1", "admin' --", "' OR 'a'='a",
            "admin' #", "admin'/*", "admin' or '1'='1", "admin' or '1'='1'--", "admin' or '1'='1' /*",
            "' or '1'='1", "or 1=1", "' or '1'='1'--", "' or '1'='1' /*", "1' or '1'='1' #",
            "' or 1=1--", "' or 1=1/*", "' or 1=1#", "' or 1=1--", "' or 1=1#", "' or 1=1/*",
            "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "1 OR '1' = '1", "' OR '1' = '1",
            "1' OR '1' = '1", "1 OR 1 = 1", "admin' or 'a'='a", "' or 'a'='a", "admin' or 'a'='a",
            "' or 'a'='a'--", "' or 'a'='a' /*", "' or 'a'='a#", "' or a=a--", "' or a=a#", "' or a=a/*",
            "' or 'a'='a'--", "' or 'a'='a' /*", "' or 'a'='a#", "' or a=a--", "' or a=a#", "' or a=a/*",
            "' or 1=1--", "' or 1=1/*", "' or 1=1#", "' or '1'='1'--", "' or '1'='1' /*", "' or '1'='1'#",
            "' or 'a'='a'--", "' or 'a'='a' /*", "' or 'a'='a'#", "' or a=a--", "' or a=a#", "' or a=a/*",
            "1' or 1=1 --", "1' or 1=1 #", "1' or 1=1/*", "' or 1=1#", "' or '1'='1'--", "' or '1'='1'/*",
            "' or 'a'='a'--", "' or 'a'='a'/*", "' or 'a'='a'#", "' or a=a--", "' or a=a#", "' or a=a/*",
        ]

        if user_input in successful_payloads:
            return redirect(url_for('sql_success'))
        else:
            return render_template('perform_sql.html', error="No flag found. Try again.")

    return render_template('perform_sql.html')

@app.route('/sql_success')
def sql_success():
    return render_template('sql_success.html', result="Congratulations! You've bypassed the authentication.")

@app.route('/breaking_the_bank', methods=['GET', 'POST'])
def breaking_the_bank():
    if request.method == 'POST':
        cracked_password = request.form['cracked_password']
        amount = request.form['amount']
        recipient = request.form['recipient']

        if cracked_password == "password":  # Example password from rockyou.txt
            return redirect(url_for('emails'))
        else:
            error = "Incorrect password. Transfer failed."
            return render_template('breaking_the_bank.html', error=error, account_balance="10000000", preset_account="33298923456")

    return render_template('breaking_the_bank.html', account_balance="10000000", preset_account="33298923456")

@app.route('/view_email')
def view_email():
    hash_value = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"  # SHA-1 hash of "password"
    return render_template('view_email.html', hash_value=hash_value)

@app.route('/emails', methods=['GET', 'POST'])
def emails():
    if request.method == 'POST':
        # Collecting user selections
        user_answers = {
            'email1': request.form.get('email1'),
            'email2': request.form.get('email2'),
            'email3': request.form.get('email3'),
            'email4': request.form.get('email4'),
            'email5': request.form.get('email5'),
            'email6': request.form.get('email6'),
            'email7': request.form.get('email7')
        }

        # Checking for correctness
        incorrect_answers = [key for key, value in user_answers.items() if value != correct_answers[key]]

        if incorrect_answers:
            return render_template('emails.html', error="One or more inputs were incorrect. Try again.")
        else:
            return redirect(url_for('congratulations'))

    return render_template('emails.html')

@app.route('/congratulations')
def congratulations():
    flag = "FLAG{correct_all_emails_identified}"
    return render_template('congratulations.html', flag=flag)

if __name__ == '__main__':
    app.run(debug=True)

