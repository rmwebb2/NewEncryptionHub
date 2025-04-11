from flask import Flask, render_template, request, redirect, url_for, flash, current_app, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20 
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import base64, os
from werkzeug.utils import secure_filename
from io import BytesIO
from flask_migrate import Migrate
from flask import make_response, send_file, Response
from mimetypes import guess_type
import base64
from google.cloud.vision_v1 import ImageAnnotatorClient, Likelihood
from google.cloud import vision


# create Flask app and configure it with necessary extensions (bcrypt, login manager, etc.)
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_dev_key')  ## change this in production/sprint 2
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')  # SQLite database URI
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "default/path/to/service-account.json")
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # redirects if route requires login
migrate = Migrate(app, db)

# create a User model for SQLite and SQLAlchemy
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}

# function to ensure the uploaded file is of the correct type (listed above^)
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_image(image_content):
 
    # uses Google Cloud Vision SafeSearch detection to determine if an image contains
    # violent or explicit content. Returns False if such content is likely, otherwise True.

    client = ImageAnnotatorClient()
    image = vision.Image(content=image_content)
    response = client.safe_search_detection(image=image)
    safe = response.safe_search_annotation

    if safe.adult >= Likelihood.LIKELY or safe.violence >= Likelihood.LIKELY:
        return False
    return True

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
            
            # read the file's contents into memory
            file_data = file.read()
            
            # SafeSearch detection integration using Google Cloud Vision
            file_ext = filename.rsplit('.', 1)[1].lower()
            if file_ext in {'png', 'jpg', 'jpeg', 'gif'}:
                if not is_safe_image(file_data):
                    flash("The image appears to contain violent or explicit content. Please upload another file.", "danger")
                    return redirect(request.url)
                # Reset file pointer after safe search check
                file.seek(0)
                file_data = file.read()
            
            # generate a random 256-bit AES key
            key = os.urandom(32)
            # create an AES cipher in CBC mode (this generates a random IV)
            cipher = AES.new(key, AES.MODE_CBC)
            # encrypt the file data (pad it to the block size)
            encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
            # prepend the IV to the encrypted data so we can use it during decryption
            stored_data = cipher.iv + encrypted_data
            
            # save the encrypted data to disk
            with open(filepath, 'wb') as f:
                f.write(stored_data)
            
            # convert the encryption key to a Base64 string for storage
            key_b64 = base64.b64encode(key).decode('utf-8')
            
            # save file info in the database (including encryption key)
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
    # ensure the current user is authorized to download this file
    if file_record.user_id != current_user.id:
        flash("You do not have permission to access this file.", "danger")
        return redirect(url_for('dashboard'))
    
    # read the encrypted file data from disk
    with open(file_record.filepath, 'rb') as f:
        encrypted_data = f.read()
    
    # retrieve the stored encryption key and decode it
    key = base64.b64decode(file_record.encryption_key)
    # extract the IV (first block) and the ciphertext
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    
    try:
        # create cipher with the stored key and extracted IV, then decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except Exception as e:
        flash(f"Decryption failed: {str(e)}", "danger")
        return redirect(url_for('my_files'))
    
    # use BytesIO to send the decrypted file as an attachment
    return send_file(BytesIO(decrypted_data),
                 download_name=file_record.filename,
                 as_attachment=True)

# route to view decrypted text file in browser
@app.route('/view_decrypted/<int:file_id>')
@login_required
def view_decrypted_file(file_id):
    file_record = File.query.get_or_404(file_id)

    # Ensure current user is authorized
    if file_record.user_id != current_user.id:
        flash("You do not have permission to view this file.", "danger")
        return redirect(url_for('my_files'))

    # Read the encrypted file data from disk
    with open(file_record.filepath, 'rb') as f:
        encrypted_data = f.read()

    # Decrypt
    key = base64.b64decode(file_record.encryption_key)
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except Exception as e:
        flash(f"Decryption failed: {str(e)}", "danger")
        return redirect(url_for('my_files'))

    # Guess MIME type from extension
    # e.g., "application/pdf", "image/png", etc.
    mime_type, _ = guess_type(file_record.filename)
    if not mime_type:
        # Fallback if the type can't be guessed
        mime_type = "application/octet-stream"

    # Return as an inline response to let the browser handle it
    response = make_response(decrypted_data)
    response.headers.set('Content-Type', mime_type)
    response.headers.set(
        'Content-Disposition',
        f'inline; filename="{file_record.filename}"'
    )

    return response


# route to delete a file
@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_record = File.query.get_or_404(file_id)
    # ensure the current user owns the file
    if file_record.user_id != current_user.id:
        flash("You do not have permission to delete this file.", "danger")
        return redirect(url_for('my_files'))
    
    # delete the file from disk
    try:
        os.remove(file_record.filepath)
    except Exception as e:
        flash(f"Error deleting file from disk: {str(e)}", "danger")
        return redirect(url_for('my_files'))
    
    # remove the file record from the database
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
        method = request.form.get('method')  # e.g. AES-256 or RSA-2048

        if method == 'AES-256':
            # AES encryption
            key = os.urandom(32)  # generate a random 256-bit key
            cipher = AES.new(key, AES.MODE_CBC)  # create AES cipher in cipher block chaining mode
            ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))  # encrypt with padding using cipher
            iv_b64 = base64.b64encode(cipher.iv).decode('utf-8') # encodes IV to base64 string for storage
            ct_b64 = base64.b64encode(ct_bytes).decode('utf-8') # encodes ciphertext the same way as ^ above
            key_b64 = base64.b64encode(key).decode('utf-8') # encodes key for later use (for decryption)

            # encryption details (for demo)
            result = (
                f"**AES-256 Encryption**\n\n"
                f"Key (Base64): {key_b64}\n"
                f"IV (Base64): {iv_b64}\n"
                f"Ciphertext (Base64): {ct_b64}"
            )
            return render_template('results.html', result=result, operation="Encryption")

        elif method == 'RSA-2048':
            # RSA Encryption
            key_pair = RSA.generate(2048) # generates 2048-bit RSA key pair (both public and private)
            public_key = key_pair.publickey() # extracts public key from generated key pair
            cipher = PKCS1_OAEP.new(public_key) # creates a cipher object for RSA encryption
            ciphertext = cipher.encrypt(plaintext.encode('utf-8')) # first, encodes plaintext to UTF-8
            ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8') # encodes UTF-8 to base64 string
            private_key_pem = key_pair.export_key().decode('utf-8') # exports private key in PEM format
            public_key_pem = public_key.export_key().decode('utf-8') # exports public key in PEM format (for demo/info purposes)

            # encryption details (for demo)
            result = (
                f"**RSA-2048 Encryption**\n\n"
                f"Public Key (PEM):\n{public_key_pem}\n\n"
                f"Ciphertext (Base64):\n{ciphertext_b64}\n\n"
                f"Private Key (PEM):\n{private_key_pem}"
            )
            return render_template('results.html', result=result, operation="Encryption")
        
        elif method == 'ChaCha20':
            # ChaCha20 Encryption:
            # generate random 256-bit key and 64-bit nonce
            key = os.urandom(32)
            nonce = os.urandom(8)
            # create ChaCha cipher object w/ key and nonce
            cipher = ChaCha20.new(key=key, nonce=nonce)
            # encrypt plaintext
            ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
            key_b64 = base64.b64encode(key).decode('utf-8')
            nonce_b64 = base64.b64encode(nonce).decode('utf-8')
            ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

            # display results
            result = (
                f"**ChaCha20 Encryption**\n\n"
                f"Key (Base64): {key_b64}\n"
                f"Nonce (Base64): {nonce_b64}\n"
                f"Ciphertext (Base64): {ciphertext_b64}"
            )
            return render_template('results.html', result=result, operation="Encryption")
        else:
            flash("Invalid encryption method selected.", "danger")
            return redirect(url_for('encrypt'))

    return render_template('encrypt.html')

# decryption route: handles both AES and RSA decryption based on user selection
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        # retrieves the selected decryption method (either AES-256 or RSA-2048)
        method = request.form.get('method')
        # retrieves the ciphertext (should be base-64 encoding)
        encrypted_data = request.form.get('encrypted')

        if method == 'AES-256':
            # for AES decryption, retrieve the key and IV from the form
            key_b64 = request.form.get('key')
            iv_b64 = request.form.get('iv')
            # makes sure all required fields are provided (key, IV, and ciphertext)
            # redirects and gives error message if incorrect/missing fields
            if not key_b64 or not iv_b64 or not encrypted_data:
                flash("Missing AES key/IV or ciphertext.", "danger")
                return redirect(url_for('decrypt'))

            try:
                # decodes the key, IV, and ciphertext from Base64 to raw bytes
                key = base64.b64decode(key_b64)
                iv = base64.b64decode(iv_b64)
                ciphertext = base64.b64decode(encrypted_data)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                # decrypts the ciphertext and remove the padding to get the original plaintext bytes
                pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
                # decodes the plaintext bytes to a UTF-8 string
                plaintext = pt.decode('utf-8')
            except Exception as e:
                # if decryption fails, flash an error message and redirect back to the decrypt page
                flash(f"AES Decryption failed: {str(e)}", "danger")
                return redirect(url_for('decrypt'))

            # renders the results template with the decrypted plaintext
            return render_template('results.html', result=plaintext, operation="Decryption")

        elif method == 'RSA-2048':
            # for RSA decryption, retrieve the private key in PEM format from the form
            private_key_pem = request.form.get('private_key')
            # makes sure both the private key and ciphertext are provided
            if not private_key_pem or not encrypted_data:
                flash("Missing RSA private key or ciphertext.", "danger")
                return redirect(url_for('decrypt'))

            try:
                # imports the private key from its PEM string format
                private_key = RSA.import_key(private_key_pem)
                # create a new cipher with the private key for decryption aned decodes cipher text to raw bytes
                cipher = PKCS1_OAEP.new(private_key)
                ciphertext = base64.b64decode(encrypted_data)
                # decrypts the ciphertext using RSA and decode it to a UTF-8 string
                plaintext = cipher.decrypt(ciphertext).decode('utf-8')
            except Exception as e:
                # provides error message and redirect if decryption fails
                flash(f"RSA Decryption failed: {str(e)}", "danger")
                return redirect(url_for('decrypt'))
            
            return render_template('results.html', result=plaintext, operation="Decryption")
        
        elif method == 'ChaCha20':
            # for ChaCha20 decryption, retrieve the key and nonce from the form
            key_b64 = request.form.get('chacha_key')
            nonce_b64 = request.form.get('nonce')
            if not key_b64 or not nonce_b64 or not encrypted_data:
                flash("Missing ChaCha20 key, nonce, or ciphertext.", "danger")
                return redirect(url_for('decrypt'))
            try:
                # decodes the key, nonce, and ciphertext from Base64 to raw bytes
                key = base64.b64decode(key_b64)
                nonce = base64.b64decode(nonce_b64)
                ciphertext = base64.b64decode(encrypted_data)
                cipher = ChaCha20.new(key=key, nonce=nonce)
                # decrypt the ciphertext and decode it to a UTF-8 string
                plaintext = cipher.decrypt(ciphertext).decode('utf-8')
            except Exception as e:
                flash(f"ChaCha20 Decryption failed: {str(e)}", "danger")
                return redirect(url_for('decrypt'))
            
            return render_template('results.html', result=plaintext, operation="Decryption")

        else:
            # provides error message/redirects if invalid decryption method selected
            flash("Invalid decryption method selected.", "danger")
            return redirect(url_for('decrypt'))

    return render_template('decrypt.html')

# run the app and create tables
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # ensure the tables exist
    app.run(debug=True)