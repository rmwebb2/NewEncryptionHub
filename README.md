# Capstone Project for IT Capstone Class
This project is still currently in progress and is meant to act as an encryption/decryption hub for education purposes as well as general usage.
**Check it out here:** [CipherGuard](https://rmwebb23.pythonanywhere.com/) 

## CipherGuard
CipherGuard is a secure web application that allows users to encrypt and decrypt their data using industry-standard algorithms like AES-256 and RSA-2048. Built with Flask, this application features user authentication, file upload (with encryption), and management capabilities—ensuring your sensitive information remains private.

## Features
User Authentication:
- Secure registration, login, and logout using Flask-Login and Flask-Bcrypt.

Encryption/Decryption:
- **AES-256:** Encrypt and decrypt text data using symmetric encryption (AES in CBC mode).
- **RSA-2048:** Encrypt and decrypt text data using asymmetric encryption with a public/private key pair.
- **ChaCha20:** Encrypt and decrypt text data using a modern stream cipher, offering a fast and secure alternative for high-speed encryption.

File Storage:
- Upload files that are automatically encrypted using AES-256 before storage.
- Download files in either their encrypted or decrypted form (text-based files can be viewed directly).

Dashboard:
- A user dashboard that provides access to encryption/decryption tools and file management options.

About Section:
- An informative section explaining the basics of AES and RSA encryption.

File Management:
- Users can view, download, and delete their uploaded files, with a confirmation modal before deletion.

## Technologies Used
**Backend**: Python, Flask, Flask-SQLAlchemy, Flask-Login, Flask-Bcrypt, Flask-Migrate (for schema migrations)
**Encryption**: PyCryptodome (AES-256, RSA-2048)
**Frontend**: HTML, CSS, Bootstrap, Jinja2 templating
**Database**: SQLite (development), with potential for PostgreSQL or Azure SQL in production

## Usage
Registration & Login:
Create an account and log in to access the dashboard.

Dashboard:
Once logged in, the dashboard provides options for:
- Encrypting text with AES-256 or RSA-2048.
- Uploading files (which are encrypted on upload).
- Viewing, downloading, and deleting your encrypted files.
- Viewing decrypted content for text files.

About:
Learn more about AES and RSA encryption on the About page.
