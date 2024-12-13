from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

# Initialize the Flask application
app = Flask(__name__)

# Configurations for the Flask app
app.config['SECRET_KEY'] = 'mysecret'  # Secret key for securely signing the session cookie
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Path to the SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable the modification tracking feature

# Initialize extensions
db = SQLAlchemy(app)  # Database handler
bcrypt = Bcrypt(app)  # For hashing passwords
login_manager = LoginManager(app)  # Manage user sessions
login_manager.login_view = 'login'  # Redirect to 'login' view if not authenticated

# User model for the database, using SQLAlchemy and Flask-Login integration
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  # Unique user ID
    username = db.Column(db.String(20), unique=True, nullable=False)  # Username, must be unique
    email = db.Column(db.String(120), unique=True, nullable=False)  # Email, must be unique
    password = db.Column(db.String(60), nullable=False)  # Password hash

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

# Load user function required by Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Retrieve a user by their ID from the database

with app.app_context():  # Ensure the app context is active for database operations

    # Home route, displays the index page
    @app.route('/')
    def index():
        return render_template('index.html')  # Render the index template

    # Registration route
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':  # Handle form submission
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            
            # Hash the user's password for secure storage
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # Create a new user and save it to the database
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('login'))  # Redirect to login page

        return render_template('register.html')  # Render the registration template

    # Login route
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':  # Handle form submission
            username = request.form['username']
            password = request.form['password']

            # Retrieve the user by username
            user = User.query.filter_by(username=username).first()
            # Verify the provided password against the stored hash
            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user)  # Log the user in
                return redirect(url_for('dashboard'))  # Redirect to the dashboard
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')

        return render_template('login.html')  # Render the login template

    # Dashboard route, accessible only to logged-in users
    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template('dashboard.html')  # Render the dashboard template

    # Profile route, shows user-specific details
    @app.route('/profile')
    @login_required
    def profile():
        return render_template('profile.html', username=current_user.username, email=current_user.email)

    # Logout route, ends the user's session
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()  # Log the user out
        flash('You have been logged out', 'success')
        return redirect(url_for('index'))  # Redirect to the home page

    if __name__ == '__main__':
        db.create_all()  # Create all database tables if they do not exist
        app.run(debug=True)  # Run the Flask application in debug mode