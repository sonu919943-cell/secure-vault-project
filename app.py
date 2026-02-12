import os, random, smtplib
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from email.message import EmailMessage

load_dotenv()
app = Flask(__name__)
app.secret_key = "SECRET_KEY_FOR_SESSIONS" # Kuch bhi random string
bcrypt = Bcrypt(app)

# --- CONFIGURATION (Apna Email Details Yahan Dalein) ---
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_APP_PASSWORD = os.getenv("SENDER_APP_PASSWORD")

# Encryption Setup for Passwords in Vault
raw_key = os.getenv("FERNET_KEY")
if raw_key:
    # Agar Render ya .env mein key mil gayi toh use encode karo
    FERNET_KEY = raw_key.encode()
else:
    # Agar kuch nahi mila (local testing), toh yeh default use karo
    FERNET_KEY = b'uX6M_6S0-X3z8v2K9_N5jWqL7m1R4t0P3s2D5f8G9h0='

cipher_suite = Fernet(FERNET_KEY)

# Database Setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///final_vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) # Store Hashed PW

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50))
    title = db.Column(db.String(100))
    username = db.Column(db.String(100))
    encrypted_password = db.Column(db.String(500))

with app.app_context():
    db.create_all()

# # --- OTP LOGIC ---
# def send_otp(receiver_email, otp):
#     msg = EmailMessage()
#     msg['Subject'] = "🔐 OTP for Secure Asset Manager"
#     msg['From'] = SENDER_EMAIL
#     msg['To'] = receiver_email
#     msg.set_content(f"Your OTP for login is: {otp}")
#     try:
#         with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
#             smtp.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
#             smtp.send_message(msg)
#         return True
#     except Exception as e:
#         print(f"SMTP Error: {e}")
#         return False

# --- ROUTES ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(username=request.form['username'], email=request.form['email'], password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        print(f"User {new_user.username} registered successfully!")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['temp_user_id'] = user.id
            if send_otp(user.email, otp):
                print(f"OTP {otp} sent to {user.email}")
                return redirect(url_for('otp_page'))
            return "Email failed to send. Check App Password."
        return "Invalid Username or Password!"
    return render_template('login.html')

@app.route('/otp')
def otp_page():
    return render_template('otp.html')

@app.route('/verify-otp', methods=['POST'])
def verify():
    if request.form['otp'] == session.get('otp'):
        session['user_id'] = session.pop('temp_user_id')
        return redirect(url_for('dashboard'))
    return "Invalid OTP!"

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    assets = Asset.query.filter_by(user_id=session['user_id']).all()
    for a in assets:
        a.decrypted_val = cipher_suite.decrypt(a.encrypted_password.encode()).decode()
    return render_template('dashboard.html', assets=assets)

@app.route('/add', methods=['POST'])
def add_asset():
    if 'user_id' not in session: return redirect(url_for('login'))
    enc_pwd = cipher_suite.encrypt(request.form['password'].encode()).decode()
    new_asset = Asset(user_id=session['user_id'], category=request.form['category'], 
                      title=request.form['title'], username=request.form['username'], 
                      encrypted_password=enc_pwd)
    db.session.add(new_asset)
    db.session.commit()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)