from flask import Flask, render_template, request, redirect, session, url_for
from cryptography.fernet import Fernet, InvalidToken
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
cipher = Fernet(os.getenv("FERNET_KEY").encode())
ADMIN_PASSWORD = os.getenv("PASSWORD")

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'logged_in' not in session:
        return redirect('/login')

    if request.method == 'POST':
        note = request.form['note'].strip()
        if note == "":
            return redirect('/')
        encrypted = cipher.encrypt(note.encode())
        with open("notes.txt", "ab") as f:
            f.write(encrypted + b'\n')  # ✅ binary write
        return redirect('/')

    return render_template('index.html')

@app.route('/view')
def view_notes():
    if 'logged_in' not in session:
        return redirect('/login')

    notes = []
    if os.path.exists("notes.txt"):
        with open("notes.txt", "rb") as f:
            for line in f:
                if not line.strip():
                    continue  # ✅ skip blank lines
                try:
                    decrypted = cipher.decrypt(line.strip()).decode()
                    notes.append(decrypted)
                except InvalidToken:
                    notes.append("[❌ Error decrypting note]")
    print(f"[LOG] {request.remote_addr} accessed /view")
    return render_template("view.html", notes=notes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        if password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect('/')
        else:
            return "Unauthorized – Incorrect password", 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
