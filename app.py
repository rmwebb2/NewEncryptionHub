from flask import Flask, render_template, request, redirect, url_for, flash, current_app, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import base64, os
from werkzeug.utils import secure_filename
from io import BytesIO

# create Flask app and configure it with necessary extensions (bcrypt, login manager, etc.)
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  ## change this in production/sprint 2
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # redirects if route requires login

# create a User model for SQLite and SQLAlchemy
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# function to ensure the uploaded file is of the correct type
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# create a File model for SQLite and SQLAlchemy
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    filepath = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encryption_key = db.Column(db.String(120), nullable=False)  # stores the Base64-encoded key

# create user loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# route for registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # hash the password with bcrypt
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        # create a new user object and add it to the database 
        user = User(username=username, email=email, password=hashed_pw)
        db.session.add(user)
        db.session.commit()

        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            # redirect to the dashboard instead of the home page
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')
    return render_template('login.html')

# file upload route
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part in the request.", "danger")
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash("No file selected.", "danger")
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            user_folder = os.path.join(current_app.root_path, 'uploads', str(current_user.id))
            os.makedirs(user_folder, exist_ok=True)
            filepath = os.path.join(user_folder, filename)
            
            # Read the file's contents into memory
            file_data = file.read()
            # Generate a random 256-bit AES key
            key = os.urandom(32)
            # Create an AES cipher in CBC mode (this generates a random IV)
            cipher = AES.new(key, AES.MODE_CBC)
            # Encrypt the file data (pad it to the block size)
            encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
            # Prepend the IV to the encrypted data so we can use it during decryption
            stored_data = cipher.iv + encrypted_data
            
            # Save the encrypted data to disk
            with open(filepath, 'wb') as f:
                f.write(stored_data)
            
            # Convert the encryption key to a Base64 string for storage
            key_b64 = base64.b64encode(key).decode('utf-8')
            
            # Save file info in the database (including the encryption key)
            new_file = File(filename=filename, filepath=filepath, user_id=current_user.id, encryption_key=key_b64)
            db.session.add(new_file)
            db.session.commit()
            
            flash("File uploaded and encrypted successfully!", "success")
            return redirect(url_for('my_files'))
        else:
            flash("File type not allowed.", "danger")
            return redirect(request.url)
    
    return render_template('upload.html')

# route to list user files
@app.route('/my_files')
@login_required
def my_files():
    user_files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('my_files.html', files=user_files)


# download file route (for encrypted file)
@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = File.query.get_or_404(file_id)
    # ensure the current user is authorized to download this file
    if file_record.user_id != current_user.id:
        flash("You do not have permission to access this file.", "danger")
        return redirect(url_for('dashboard'))
    
    directory = os.path.dirname(file_record.filepath)
    filename = os.path.basename(file_record.filepath)
    return send_from_directory(directory, filename, as_attachment=True)

# new route to download decrypted file
@app.route('/download_decrypted/<int:file_id>')
@login_required
def download_decrypted_file(file_id):
    file_record = File.query.get_or_404(file_id)
    # Ensure the current user is authorized to download this file
    if file_record.user_id != current_user.id:
        flash("You do not have permission to access this file.", "danger")
        return redirect(url_for('dashboard'))
    
    # Read the encrypted file data from disk
    with open(file_record.filepath, 'rb') as f:
        encrypted_data = f.read()
    
    # Retrieve the stored encryption key and decode it
    key = base64.b64decode(file_record.encryption_key)
    # Extract the IV (first block) and the ciphertext
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    
    try:
        # Create cipher with the stored key and extracted IV, then decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except Exception as e:
        flash(f"Decryption failed: {str(e)}", "danger")
        return redirect(url_for('my_files'))
    
    # Use BytesIO to send the decrypted file as an attachment
    return send_file(BytesIO(decrypted_data),
                 download_name=file_record.filename,
                 as_attachment=True)

@app.route('/view_decrypted/<int:file_id>')
@login_required
def view_decrypted_file(file_id):
    file_record = File.query.get_or_404(file_id)
    # Ensure the file belongs to the current user
    if file_record.user_id != current_user.id:
        flash("You do not have permission to view this file.", "danger")
        return redirect(url_for('my_files'))
    
    # Read the encrypted file data from disk
    with open(file_record.filepath, 'rb') as f:
        encrypted_data = f.read()
    
    # Retrieve the stored encryption key and decode it
    key = base64.b64decode(file_record.encryption_key)
    # Extract the IV (first block) and the ciphertext
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    
    try:
        # Decrypt the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except Exception as e:
        flash(f"Decryption failed: {str(e)}", "danger")
        return redirect(url_for('my_files'))
    
    # Convert bytes to a string (assuming the file is text-based)
    try:
        content = decrypted_data.decode('utf-8')
    except UnicodeDecodeError:
        # If it's not a text file, let the user know
        flash("This file doesn't appear to be a text file.", "warning")
        return redirect(url_for('my_files'))
    
    return render_template('view_decrypted.html', content=content, filename=file_record.filename)

# route to delete a file
@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_record = File.query.get_or_404(file_id)
    # Ensure the current user owns the file
    if file_record.user_id != current_user.id:
        flash("You do not have permission to delete this file.", "danger")
        return redirect(url_for('my_files'))
    
    # Delete the file from disk
    try:
        os.remove(file_record.filepath)
    except Exception as e:
        flash(f"Error deleting file from disk: {str(e)}", "danger")
        return redirect(url_for('my_files'))
    
    # Remove the file record from the database
    db.session.delete(file_record)
    db.session.commit()
    
    flash("File deleted successfully!", "success")
    return redirect(url_for('my_files'))


# logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/about')
def about():
    return render_template('about.html')

# home route
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

# encryption route
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        # get user inputs from the form
        plaintext = request.form.get('plaintext')
        method = request.form.get('method')  # e.g., 'AES-256' or 'RSA-2048'

        if method == 'AES-256':
            # AES encryption
            key = os.urandom(32)  # generate a random 256-bit key
            cipher = AES.new(key, AES.MODE_CBC)  # create AES cipher in CBC mode with random IV
            ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))  # encrypt with padding
            iv_b64 = base64.b64encode(cipher.iv).decode('utf-8')
            ct_b64 = base64.b64encode(ct_bytes).decode('utf-8')
            key_b64 = base64.b64encode(key).decode('utf-8')

            # display encryption details (for demo)
            result = (
                f"**AES-256 Encryption**\n\n"
                f"Key (Base64): {key_b64}\n"
                f"IV (Base64): {iv_b64}\n"
                f"Ciphertext (Base64): {ct_b64}"
            )
            return render_template('results.html', result=result, operation="Encryption")

        elif method == 'RSA-2048':
            # RSA Encryption
            key_pair = RSA.generate(2048)
            public_key = key_pair.publickey()
            cipher = PKCS1_OAEP.new(public_key)
            ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
            ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
            private_key_pem = key_pair.export_key().decode('utf-8')
            public_key_pem = public_key.export_key().decode('utf-8')

            result = (
                f"**RSA-2048 Encryption**\n\n"
                f"Public Key (PEM):\n{public_key_pem}\n\n"
                f"Ciphertext (Base64):\n{ciphertext_b64}\n\n"
                f"Private Key (PEM):\n{private_key_pem}"
            )
            return render_template('results.html', result=result, operation="Encryption")

        else:
            flash("Invalid encryption method selected.", "danger")
            return redirect(url_for('encrypt'))

    return render_template('encrypt.html')

# decryption route
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        method = request.form.get('method')  # 'AES-256' or 'RSA-2048'
        encrypted_data = request.form.get('encrypted')  # ciphertext in Base64

        if method == 'AES-256':
            key_b64 = request.form.get('key')
            iv_b64 = request.form.get('iv')
            if not key_b64 or not iv_b64 or not encrypted_data:
                flash("Missing AES key/IV or ciphertext.", "danger")
                return redirect(url_for('decrypt'))

            try:
                key = base64.b64decode(key_b64)
                iv = base64.b64decode(iv_b64)
                ciphertext = base64.b64decode(encrypted_data)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
                plaintext = pt.decode('utf-8')
            except Exception as e:
                flash(f"AES Decryption failed: {str(e)}", "danger")
                return redirect(url_for('decrypt'))

            return render_template('results.html', result=plaintext, operation="Decryption")

        elif method == 'RSA-2048':
            private_key_pem = request.form.get('private_key')
            if not private_key_pem or not encrypted_data:
                flash("Missing RSA private key or ciphertext.", "danger")
                return redirect(url_for('decrypt'))

            try:
                private_key = RSA.import_key(private_key_pem)
                cipher = PKCS1_OAEP.new(private_key)
                ciphertext = base64.b64decode(encrypted_data)
                plaintext = cipher.decrypt(ciphertext).decode('utf-8')
            except Exception as e:
                flash(f"RSA Decryption failed: {str(e)}", "danger")
                return redirect(url_for('decrypt'))

            return render_template('results.html', result=plaintext, operation="Decryption")

        else:
            flash("Invalid decryption method selected.", "danger")
            return redirect(url_for('decrypt'))

    return render_template('decrypt.html')

# run the app and create tables
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # ensure the tables exist
    app.run(debug=True)
