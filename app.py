from flask import Flask, render_template, url_for, flash, redirect, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime, timedelta, timezone, UTC
import os
import re
import stripe
from dotenv import load_dotenv
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Mail, Message

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///marketplace.db'
app.config['UPLOAD_FOLDER'] = 'static'
app.config['AVATARS_FOLDER'] = 'static/avatars'
app.config['PRODUCTS_FOLDER'] = 'static/product_images'
app.config['PURCHASED_PRODUCTS_FOLDER'] = 'static/purchased_products'
app.config['QR_CODES_FOLDER'] = 'static/qr_codes'
app.config['PAYMENT_PROOFS_FOLDER'] = 'static/payment_proofs'
app.config['PAYMENT_SCREENSHOTS_FOLDER'] = 'static/payment_screenshots'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
stripe.api_key = os.getenv('STRIPE_SECRET_KEY', 'your_stripe_secret_key')

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'your-email@gmail.com')
mail = Mail(app)

# Create necessary directories if they don't exist
os.makedirs(app.config['AVATARS_FOLDER'], exist_ok=True)
os.makedirs(app.config['PRODUCTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['PURCHASED_PRODUCTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['QR_CODES_FOLDER'], exist_ok=True)
os.makedirs(app.config['PAYMENT_PROOFS_FOLDER'], exist_ok=True)
os.makedirs(app.config['PAYMENT_SCREENSHOTS_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=True)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    date_joined = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    is_active = db.Column(db.Boolean, default=True)
    avatar = db.Column(db.String(20), nullable=False, default='default.jpg')
    products = db.relationship('Product', backref='seller', lazy=True)
    location = db.Column(db.String(100), nullable=True)
    bio = db.Column(db.Text, nullable=True)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    qr_code = db.Column(db.String(20), nullable=True)
    category = db.Column(db.String(50), nullable=False)
    condition = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='available')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    date_ordered = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))
    status = db.Column(db.String(20), default='pending')
    payment_id = db.Column(db.String(100))
    payment_screenshot = db.Column(db.String(100))
    payment_status = db.Column(db.String(20), default='pending')
    payment_verified = db.Column(db.Boolean, default=False)
    payment_method = db.Column(db.String(20), nullable=True)
    payment_proof = db.Column(db.String(100), nullable=True)
    purchased_image = db.Column(db.String(100))
  


    # Add relationships
    buyer = db.relationship('User', foreign_keys=[buyer_id], backref='purchases')
    product = db.relationship('Product', backref='orders')

    def __init__(self, **kwargs):
        # Set default values for new columns
        if 'payment_method' not in kwargs:
            kwargs['payment_method'] = 'qr'
        super(Order, self).__init__(**kwargs)

    @property
    def payment_display(self):
        """Helper property to get payment proof or screenshot"""
        return self.payment_proof or self.payment_screenshot

    def __repr__(self):
        return f'<Order {self.id}>'

class PaymentQR(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    qr_code = db.Column(db.String(100), nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    date_updated = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin or current_user.email != 'jiteshbawaskar05@gmail.com':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    filter_type = request.args.get('filter', '')

    # Base query
    query = Product.query

    # Apply search filter
    if search:
        query = query.filter(
            db.or_(
                Product.title.ilike(f'%{search}%'),
                Product.description.ilike(f'%{search}%')
            )
        )

    # Apply category filter
    if category:
        query = query.filter(Product.category == category)

    # Apply user-specific filters
    if filter_type and current_user.is_authenticated:
        if filter_type == 'my_products':
            query = query.filter(Product.user_id == current_user.id)
        elif filter_type == 'my_purchases':
            query = query.join(Order).filter(Order.buyer_id == current_user.id)
        elif filter_type == 'my_sales':
            query = query.join(Order).filter(
                Product.user_id == current_user.id,
                Order.status == 'completed'
            )

    # Apply default status filter unless viewing own products
    if not (filter_type == 'my_products' and current_user.is_authenticated):
        query = query.filter(Product.status == 'available')

    # Order by most recent
    query = query.order_by(Product.date_posted.desc())

    # Paginate results
    products = query.paginate(page=page, per_page=12)

    # Remove 'page' from args to avoid conflict in template
    args = request.args.to_dict()
    args.pop('page', None)

    # Pass the args without 'page' and the products to the template
    return render_template('home.html', products=products, request_args=args)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already logged in!', 'info')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if username is valid
        if not re.match("^[a-zA-Z0-9_.-]+$", username):
            flash('Username can only contain letters, numbers, dots, and underscores', 'danger')
            return redirect(url_for('register'))

        # Check if username length is valid
        if len(username) < 3 or len(username) > 20:
            flash('Username must be between 3 and 20 characters long', 'danger')
            return redirect(url_for('register'))

        # Check if email is valid
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Please enter a valid email address', 'danger')
            return redirect(url_for('register'))

        # Check if phone number is valid
        if not re.match(r'^\+?1?\d{9,15}$', phone):
            flash('Please enter a valid phone number', 'danger')
            return redirect(url_for('register'))

        # Validate password strength
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('register'))
        if not re.search("[a-z]", password):
            flash('Password must contain at least one lowercase letter', 'danger')
            return redirect(url_for('register'))
        if not re.search("[A-Z]", password):
            flash('Password must contain at least one uppercase letter', 'danger')
            return redirect(url_for('register'))
        if not re.search("[0-9]", password):
            flash('Password must contain at least one number', 'danger')
            return redirect(url_for('register'))

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('This username is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('An account with this email already exists. Please use a different email or try logging in.', 'danger')
            return redirect(url_for('register'))

        # Check if phone already exists
        if User.query.filter_by(phone=phone).first():
            flash('An account with this phone number already exists. Please use a different number.', 'danger')
            return redirect(url_for('register'))

        try:
            # Check if this is the first user (will be admin)
            is_first_user = User.query.first() is None

            # Create new user
            user = User(
                username=username,
                email=email,
                phone=phone,
                is_admin=is_first_user  # Make the first user an admin
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            # Send welcome email
            try:
                send_welcome_email(user)
            except Exception as e:
                print(f"Failed to send welcome email: {str(e)}")
                # Don't stop registration if email fails
                pass

            if is_first_user:
                flash('Your admin account has been created successfully! You can now log in.', 'success')
            else:
                flash('Your account has been created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error during registration: {str(e)}")
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Debug print
        print(f"Login attempt for email: {email}")
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('No account found with this email address.', 'danger')
            return redirect(url_for('login'))
            
        if not user.is_active:
            flash('This account has been deactivated. Please contact support.', 'danger')
            return redirect(url_for('login'))
            
        if not bcrypt.check_password_hash(user.password, password):
            flash('Incorrect password. Please try again.', 'danger')
            return redirect(url_for('login'))
        
        # If we get here, credentials are correct
        login_user(user, remember=request.form.get('remember', False))
        user.last_seen = datetime.now(UTC)
        try:
            db.session.commit()
            flash('Welcome back, {}!'.format(user.username), 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        except Exception as e:
            print(f"Error during login: {str(e)}")
            db.session.rollback()
            flash('An error occurred during login. Please try again.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user:
            token = user.get_reset_token()
            send_reset_email(user, token)
            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address.', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        if password != request.form['confirm_password']:
            flash('Passwords do not match.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated! You can now log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    # Delete user's products
    for product in current_user.products:
        if product.image_file != 'default.jpg':
            try:
                os.remove(os.path.join(app.config['PRODUCTS_FOLDER'], product.image_file))
            except:
                pass
        if product.qr_code:
            try:
                os.remove(os.path.join(app.config['QR_CODES_FOLDER'], product.qr_code))
            except:
                pass
        db.session.delete(product)

    # Delete user's avatar if not default
    if current_user.avatar != 'default.jpg':
        try:
            os.remove(os.path.join(app.config['AVATARS_FOLDER'], current_user.avatar))
        except:
            pass

    # Delete user
    db.session.delete(current_user)
    db.session.commit()
    flash('Your account has been deleted successfully.', 'info')
    return redirect(url_for('home'))

# Utility functions
def send_email(to, subject, body):
    try:
        msg = Message(
            subject=subject,
            recipients=[to],
            body=body
        )
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        flash('Email notification could not be sent.', 'warning')

def send_welcome_email(user):
    subject = 'Welcome to StudentEase Marketplace!'
    body = f'''Hi {user.username},

Welcome to StudentEase Marketplace! We're excited to have you join our community.

You can now:
- Browse and search for products
- List your items for sale
- Message other users
- Track your orders

If you have any questions, feel free to contact our support team.

Best regards,
The StudentEase Team
'''
    send_email(user.email, subject, body)

def send_reset_email(user, token):
    subject = 'Password Reset Request'
    body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    send_email(user.email, subject, body)

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(UTC)
        db.session.commit()

@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        if 'image' not in request.files:
            flash('No image file uploaded', 'danger')
            return redirect(request.url)
        
        image = request.files['image']
        if image.filename == '':
            flash('No image selected', 'danger')
            return redirect(request.url)
        
        if image:
            filename = secure_filename(f"product_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_{image.filename}")
            image.save(os.path.join(app.config['PRODUCTS_FOLDER'], filename))
            
            product = Product(
                title=request.form['title'],
                description=request.form['description'],
                price=float(request.form['price']),
                category=request.form['category'],
                condition=request.form['condition'],
                image_file=filename,
                seller=current_user
            )
            db.session.add(product)
            db.session.commit()
            flash('Your product has been listed!', 'success')
            return redirect(url_for('home'))
    
    return render_template('create_product.html')

@app.route('/product/<int:product_id>')
def product(product_id):
    product = Product.query.get_or_404(product_id)
    payment_qr = PaymentQR.query.first()
    return render_template('product.html', 
                         title=product.title,
                         product=product,
                         payment_qr=payment_qr)

@app.route('/product/<int:product_id>/upload_qr', methods=['POST'])
@login_required
def upload_qr_code(product_id):
    product = Product.query.get_or_404(product_id)
    
    if current_user.id != product.seller_id and not current_user.is_admin:
        abort(403)
    
    if 'qr_code' not in request.files:
        flash('No file uploaded', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    qr_code = request.files['qr_code']
    if qr_code.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    if qr_code:
        if product.qr_code:
            old_qr_path = os.path.join(app.config['QR_CODES_FOLDER'], product.qr_code)
            if os.path.exists(old_qr_path):
                os.remove(old_qr_path)
        
        filename = f"qr_{product_id}_{secure_filename(qr_code.filename)}"
        qr_code.save(os.path.join(app.config['QR_CODES_FOLDER'], filename))
        product.qr_code = filename
        db.session.commit()
        flash('QR code uploaded successfully', 'success')
    
    return redirect(url_for('product', product_id=product_id))

@app.route('/process_payment/<int:product_id>', methods=['POST'])
@login_required
def process_payment(product_id):
    product = Product.query.get_or_404(product_id)
    token = request.form.get('stripeToken')
    
    try:
        charge = stripe.Charge.create(
            amount=int(product.price * 100),  # Amount in cents
            currency='usd',
            source=token,
            description=f'Purchase of {product.title}'
        )
        
        if charge.paid:
            order = Order(
                buyer_id=current_user.id,
                product_id=product_id,
                status='completed',
                payment_id=charge.id
            )
            product.status = 'sold'
            db.session.add(order)
            db.session.commit()
            
            flash('Payment successful! Your order has been placed.', 'success')
            return redirect(url_for('home'))
    
    except stripe.error.CardError as e:
        flash(f'Payment failed: {e.error.message}', 'danger')
    except Exception as e:
        flash('An error occurred while processing your payment.', 'danger')
    
    return redirect(url_for('product', product_id=product_id))

# Admin routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    products = Product.query.all()
    orders = Order.query.order_by(Order.date_ordered.desc()).all()
    payment_qr = PaymentQR.query.first()
    return render_template('admin/dashboard.html', 
                         users=users, 
                         products=products, 
                         orders=orders,
                         payment_qr=payment_qr)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/products')
@login_required
@admin_required
def admin_products():
    products = Product.query.all()
    return render_template('admin/products.html', products=products)

@app.route('/admin/orders')
@login_required
@admin_required
def admin_orders():
    orders = Order.query.all()
    return render_template('admin/orders.html', orders=orders)

@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent changing admin status for the main admin account
    if user.email == 'jiteshbawaskar05@gmail.com':
        flash('Cannot modify admin status for the main administrator account.', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    action = "removed from" if not user.is_admin else "added to"
    flash(f'User {user.username} has been {action} administrators.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    products = Product.query.filter_by(seller=user).all()
    
    # Only show completed/processing orders, exclude cancelled and rejected ones
    purchases = Order.query.filter_by(buyer=user)\
        .filter(Order.status.in_(['completed', 'processing']))\
        .filter(Order.payment_status.in_(['completed', 'processing']))\
        .order_by(Order.date_ordered.desc())\
        .all()
    
    payment_qr = PaymentQR.query.first()  # Get the payment QR code
    return render_template('profile.html', 
                         user=user, 
                         products=products, 
                         purchases=purchases,
                         payment_qr=payment_qr)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        if 'password' in request.form:
            # Handle password change
            if bcrypt.check_password_hash(current_user.password, request.form['current_password']):
                hashed_password = bcrypt.generate_password_hash(request.form['new_password']).decode('utf-8')
                current_user.password = hashed_password
                db.session.commit()
                flash('Your password has been updated!', 'success')
            else:
                flash('Current password is incorrect!', 'danger')
        else:
            # Handle profile updates
            current_user.username = request.form['username']
            current_user.email = request.form['email']
            db.session.commit()
            flash('Your account has been updated!', 'success')
        
        return redirect(url_for('settings'))
    
    return render_template('settings.html', user=current_user)

@app.route('/product/<int:product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Check if the user owns the product or is an admin
    if product.user_id != current_user.id and not current_user.is_admin:
        flash('You do not have permission to delete this product.', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    # Check if the product has any orders
    orders = Order.query.filter_by(product_id=product_id).first()
    if orders:
        flash('Cannot delete product as it has associated orders.', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    # Check if the product status is available
    if product.status != 'available':
        flash('Cannot delete product as it is currently involved in a transaction.', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    try:
        # Delete associated files
        if product.image_file != 'default.jpg':
            image_path = os.path.join(app.config['PRODUCTS_FOLDER'], product.image_file)
            if os.path.exists(image_path):
                os.remove(image_path)
        
        if product.qr_code:
            qr_path = os.path.join(app.config['QR_CODES_FOLDER'], product.qr_code)
            if os.path.exists(qr_path):
                os.remove(qr_path)
        
        # Delete the product
        db.session.delete(product)
        db.session.commit()
        flash('Your product has been deleted successfully!', 'success')
    except Exception as e:
        print(f"Error deleting product: {e}")
        db.session.rollback()
        flash('An error occurred while deleting the product.', 'danger')
    
    return redirect(url_for('home'))

@app.route('/create-checkout-session/<int:product_id>')
@login_required
def create_checkout_session(product_id):
    product = Product.query.get_or_404(product_id)
    
    if product.status != 'available':
        return jsonify({'error': 'This product is no longer available'}), 400
    
    if product.seller_id == current_user.id:
        return jsonify({'error': 'You cannot buy your own product'}), 400

    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'unit_amount': int(product.price * 100),
                    'product_data': {
                        'name': product.title,
                        'description': product.description,
                    },
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('order_success', product_id=product.id, _external=True),
            cancel_url=url_for('product', product_id=product.id, _external=True),
        )
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        return jsonify({'error': str(e)}), 403

@app.route('/order-success/<int:product_id>')
@login_required
def order_success(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Create order record
    order = Order(
        buyer_id=current_user.id,
        product_id=product_id,
        status='completed'
    )
    
    # Add order to session first to get the ID
    db.session.add(order)
    db.session.flush()
    
    # Copy product image to purchased products folder
    if product.image_file and product.image_file != 'default.jpg':
        source_path = os.path.join(app.config['PRODUCTS_FOLDER'], product.image_file)
        if os.path.exists(source_path):
            # Create a new filename for the purchased product image with proper order ID
            purchased_filename = f"purchased_{order.id}_{product.image_file}"
            dest_path = os.path.join(app.config['PURCHASED_PRODUCTS_FOLDER'], purchased_filename)
            try:
                import shutil
                shutil.copy2(source_path, dest_path)
                # Update the order with the new image path
                order.payment_proof = purchased_filename
            except Exception as e:
                print(f"Error copying product image: {e}")
    
    # Update product status
    product.status = 'sold'
    
    # Commit all changes
    db.session.commit()
    
    flash('Thank you for your purchase!', 'success')
    payment_qr = PaymentQR.query.first()
    return render_template('order_success.html', product=product, order=order, payment_qr=payment_qr)

@app.route('/product/<int:product_id>/update_image', methods=['POST'])
@login_required
def update_product_image(product_id):
    product = Product.query.get_or_404(product_id)
    
    if product.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    if 'image' not in request.files:
        flash('No image file uploaded', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    image = request.files['image']
    if image.filename == '':
        flash('No image selected', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    if image:
        # Delete old image if it's not the default
        if product.image_file != 'default.jpg':
            try:
                old_image_path = os.path.join(app.config['PRODUCTS_FOLDER'], product.image_file)
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)
            except Exception as e:
                print(f"Error deleting old image: {e}")
        
        # Save new image
        filename = secure_filename(f"product_{product_id}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_{image.filename}")
        image.save(os.path.join(app.config['PRODUCTS_FOLDER'], filename))
        product.image_file = filename
        db.session.commit()
        flash('Product image has been updated!', 'success')
    
    return redirect(url_for('product', product_id=product_id))

@app.route('/update_avatar', methods=['POST'])
@login_required
def update_avatar():
    if 'avatar' not in request.files:
        flash('No image file uploaded', 'danger')
        return redirect(url_for('profile', username=current_user.username))
    
    avatar = request.files['avatar']
    if avatar.filename == '':
        flash('No image selected', 'danger')
        return redirect(url_for('profile', username=current_user.username))
    
    if avatar:
        # Delete old avatar if it's not the default
        if current_user.avatar != 'default.jpg':
            try:
                old_avatar_path = os.path.join(app.config['AVATARS_FOLDER'], current_user.avatar)
                if os.path.exists(old_avatar_path):
                    os.remove(old_avatar_path)
            except Exception as e:
                print(f"Error deleting old avatar: {e}")
        
        # Save new avatar
        filename = secure_filename(f"avatar_{current_user.id}_{avatar.filename}")
        avatar.save(os.path.join(app.config['AVATARS_FOLDER'], filename))
        current_user.avatar = filename
        db.session.commit()
        flash('Your profile picture has been updated!', 'success')
    
    return redirect(url_for('profile', username=current_user.username))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/admin/payment-qr', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_payment_qr():
    payment_qr = PaymentQR.query.first()
    pending_orders = Order.query.filter_by(payment_status='pending').all()
    completed_orders = Order.query.filter_by(payment_status='completed').all()

    if request.method == 'POST':
        if 'qr_code' not in request.files:
            flash('No QR code uploaded', 'danger')
            return redirect(url_for('admin_payment_qr'))
        
        qr_code = request.files['qr_code']
        if qr_code.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('admin_payment_qr'))
        
        if qr_code:
            # Delete old QR code if it exists
            if payment_qr and payment_qr.qr_code:
                try:
                    old_qr_path = os.path.join(app.config['QR_CODES_FOLDER'], payment_qr.qr_code)
                    if os.path.exists(old_qr_path):
                        os.remove(old_qr_path)
                except Exception as e:
                    print(f"Error deleting old QR code: {e}")
            
            # Save new QR code
            filename = secure_filename(f"payment_qr_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_{qr_code.filename}")
            qr_code.save(os.path.join(app.config['QR_CODES_FOLDER'], filename))
            
            # Create or update PaymentQR record
            if not payment_qr:
                payment_qr = PaymentQR(
                    qr_code=filename,
                    instructions=request.form['instructions']
                )
                db.session.add(payment_qr)
            else:
                payment_qr.qr_code = filename
                payment_qr.instructions = request.form['instructions']
            
            try:
                db.session.commit()
                flash('Payment QR code has been updated successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash('An error occurred while updating the QR code.', 'danger')
                print(f"Database error: {e}")
        
        return redirect(url_for('admin_payment_qr'))
    
    return render_template('admin/payment_qr.html', 
                         payment_qr=payment_qr,
                         pending_orders=pending_orders,
                         completed_orders=completed_orders)

@app.route('/admin/payments')
@login_required
def admin_payments():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    orders = Order.query.order_by(Order.date_ordered.desc()).all()
    return render_template('admin/payment_details.html', orders=orders)

@app.route('/admin/verify-payment/<int:order_id>/<action>', methods=['POST'])
@login_required
def verify_payment(order_id, action):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    order = Order.query.get_or_404(order_id)
    product = order.product
    
    try:
        if action == 'approve':
            order.payment_status = 'completed'
            order.status = 'processing'
            product.status = 'sold'  # Mark product as sold when payment is approved
            
            # Send email to buyer
            try:
                msg = Message('Payment Approved',
                         sender=app.config['MAIL_USERNAME'],
                         recipients=[order.buyer.email])
                msg.body = f'''Your payment for order #{order.id} has been approved.
            
Product: {order.product.title}
Amount: ${order.product.price:.2f}
Order Status: Processing

Your order will be processed shortly. Thank you for your purchase!
'''
                mail.send(msg)
            except Exception as e:
                print(f"Error sending buyer email: {str(e)}")

            # Send email to seller
            try:
                msg = Message('New Order Notification',
                         sender=app.config['MAIL_USERNAME'],
                         recipients=[order.product.seller.email])
                msg.body = f'''You have a new order to process!
            
Order ID: #{order.id}
Product: {order.product.title}
Buyer: {order.buyer.username}
Amount: ${order.product.price:.2f}

Please process this order as soon as possible.
'''
                mail.send(msg)
            except Exception as e:
                print(f"Error sending seller email: {str(e)}")
            
            flash('Payment approved and order status updated.', 'success')
        
        elif action == 'reject':
            order.payment_status = 'rejected'
            order.status = 'cancelled'
            product.status = 'available'  # Make product available again
            
            # Send email to buyer
            try:
                msg = Message('Payment Rejected',
                         sender=app.config['MAIL_USERNAME'],
                         recipients=[order.buyer.email])
                msg.body = f'''Your payment for order #{order.id} has been rejected.
            
Product: {order.product.title}
Amount: ${order.product.price:.2f}

The product has been made available again for purchase.
Please contact support if you believe this is an error.
'''
                mail.send(msg)
            except Exception as e:
                print(f"Error sending rejection email: {str(e)}")
            
            flash('Payment rejected and order cancelled. Product is now available again.', 'info')
        
        db.session.commit()
    except Exception as e:
        print(f"Error processing payment verification: {str(e)}")
        db.session.rollback()
        flash('An error occurred while processing the payment verification.', 'danger')
    
    return redirect(url_for('admin_payment_qr'))

@app.route('/submit-payment/<int:product_id>', methods=['POST'])
@login_required
def submit_payment(product_id):
    product = Product.query.get_or_404(product_id)
    
    if 'payment_screenshot' not in request.files:
        flash('No payment proof uploaded', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    screenshot = request.files['payment_screenshot']
    if screenshot.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    if screenshot:
        try:
            # Save payment proof
            filename = secure_filename(f"payment_proof_{product_id}_{current_user.id}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_{screenshot.filename}")
            proof_path = os.path.join(app.config['PAYMENT_PROOFS_FOLDER'], filename)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(proof_path), exist_ok=True)
            
            # Save the file
            screenshot.save(proof_path)
            
            # Create order
            order = Order(
                buyer_id=current_user.id,
                product_id=product_id,
                status='pending',
                payment_method='qr',
                payment_status='pending',
                payment_proof=filename
            )
            
            # Mark product as pending
            product.status = 'pending'
            
            db.session.add(order)
            db.session.commit()

            # Send notification emails
            try:
                # Notify admin
                admin_subject = 'New Payment Verification Required'
                admin_body = f"""
New payment proof submitted:

Order ID: #{order.id}
Product: {product.title}
Price: ${product.price}
Buyer: {current_user.username}
Seller: {product.seller.username}

Please verify the payment in the admin dashboard.
"""
                send_email('jiteshbawaskar05@gmail.com', admin_subject, admin_body)

                # Notify buyer
                buyer_subject = 'Payment Proof Submitted'
                buyer_body = f"""
Dear {current_user.username},

Your payment proof has been submitted for:

Order ID: #{order.id}
Product: {product.title}
Price: ${product.price}

We will notify you once your payment is verified.

Thank you for your purchase!
"""
                send_email(current_user.email, buyer_subject, buyer_body)

            except Exception as e:
                print(f"Error sending emails: {str(e)}")
            
            flash('Your payment proof has been submitted and is pending verification.', 'success')
            return redirect(url_for('profile', username=current_user.username))
            
        except Exception as e:
            print(f"Error processing payment: {str(e)}")
            db.session.rollback()
            flash('Error processing payment. Please try again.', 'danger')
            return redirect(url_for('product', product_id=product_id))
    
    flash('Error uploading payment proof. Please try again.', 'danger')
    return redirect(url_for('product', product_id=product_id))

@app.route('/place-cod-order/<int:product_id>', methods=['POST'])
@login_required
def place_cod_order(product_id):
    product = Product.query.get_or_404(product_id)
    
    # Check if product is available
    if product.status != 'available':
        flash('This product is no longer available.', 'danger')
        return redirect(url_for('product', product_id=product_id))
    
    try:
        # Create order with COD payment method
        order = Order(
            buyer_id=current_user.id,
            product_id=product_id,
            status='pending',
            payment_method='cod',
            payment_status='pending'
        )
        
        # Mark product as pending
        product.status = 'pending'
        
        db.session.add(order)
        db.session.commit()
        
        # Send notification emails
        try:
            # Notify seller
            seller_subject = 'New Cash on Delivery Order'
            seller_body = f"""
A new Cash on Delivery order has been placed:

Order ID: #{order.id}
Product: {product.title}
Price: ${product.price}
Buyer: {current_user.username}

The buyer will pay upon delivery.
"""
            send_email(product.seller.email, seller_subject, seller_body)

            # Notify buyer
            buyer_subject = 'Order Confirmation - Cash on Delivery'
            buyer_body = f"""
Dear {current_user.username},

Your Cash on Delivery order has been placed:

Order ID: #{order.id}
Product: {product.title}
Price: ${product.price}
Seller: {product.seller.username}

You will need to pay when the product is delivered.

Thank you for your order!
"""
            send_email(current_user.email, buyer_subject, buyer_body)

        except Exception as e:
            print(f"Error sending emails: {str(e)}")

        flash('Your Cash on Delivery order has been placed successfully!', 'success')
        return redirect(url_for('profile', username=current_user.username))

    except Exception as e:
        print(f"Error placing order: {str(e)}")
        db.session.rollback()
        flash('Error placing order. Please try again.', 'danger')
        return redirect(url_for('product', product_id=product_id))

@app.route('/product/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        product.title = request.form['title']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        product.category = request.form['category']
        product.condition = request.form['condition']
        
        if 'image' in request.files:
            image = request.files['image']
            if image.filename:
                # Delete old image if it's not the default
                if product.image_file != 'default.jpg':
                    try:
                        old_image_path = os.path.join(app.config['PRODUCTS_FOLDER'], product.image_file)
                        if os.path.exists(old_image_path):
                            os.remove(old_image_path)
                    except Exception as e:
                        print(f"Error deleting old image: {e}")
                
                # Save new image
                filename = secure_filename(f"product_{product_id}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_{image.filename}")
                image.save(os.path.join(app.config['PRODUCTS_FOLDER'], filename))
                product.image_file = filename
        
        try:
            db.session.commit()
            flash('Your product has been updated!', 'success')
            return redirect(url_for('product', product_id=product.id))
        except:
            db.session.rollback()
            flash('An error occurred while updating your product.', 'danger')
    
    return render_template('edit_product.html', product=product)

# Custom template filters
@app.template_filter('timeago')
def timeago_filter(date):
    """Convert a datetime into a human readable time-ago string."""
    if not date.tzinfo:
        # If the date is naive, assume it's in UTC
        date = date.replace(tzinfo=UTC)
    
    now = datetime.now(UTC)
    diff = now - date

    if diff < timedelta(minutes=1):
        return 'just now'
    elif diff < timedelta(hours=1):
        minutes = int(diff.total_seconds() / 60)
        return f'{minutes} minute{"s" if minutes != 1 else ""} ago'
    elif diff < timedelta(days=1):
        hours = int(diff.total_seconds() / 3600)
        return f'{hours} hour{"s" if hours != 1 else ""} ago'
    elif diff < timedelta(days=30):
        days = diff.days
        return f'{days} day{"s" if days != 1 else ""} ago'
    elif diff < timedelta(days=365):
        months = int(diff.days / 30)
        return f'{months} month{"s" if months != 1 else ""} ago'
    else:
        years = int(diff.days / 365)
        return f'{years} year{"s" if years != 1 else ""} ago'

@app.route('/admin/payment-details')
@login_required
@admin_required
def admin_payment_details():
    orders = Order.query.order_by(Order.date_ordered.desc()).all()
    return render_template('admin/payment_details.html', orders=orders)

if __name__ == '__main__':
    with app.app_context():
        # Create tables if they don't exist
        inspector = db.inspect(db.engine)
        if not inspector.has_table('order'):
            db.create_all()
            # Create default admin user if no users exist
            if not User.query.first():
                admin = User(
                    username='admin',
                    email='jiteshbawaskar05@gmail.com',
                    is_admin=True
                )
                admin.set_password('Admin@123')
                db.session.add(admin)
                db.session.commit()
        else:
            # Add missing columns if table exists
            existing_columns = [c['name'] for c in inspector.get_columns('order')]
            with db.engine.begin() as conn:
                if 'payment_method' not in existing_columns:
                    conn.execute(db.text('ALTER TABLE "order" ADD COLUMN payment_method VARCHAR(20)'))
                if 'payment_proof' not in existing_columns:
                    conn.execute(db.text('ALTER TABLE "order" ADD COLUMN payment_proof VARCHAR(100)'))
    
    # Enable debug mode and auto-reloader
    app.run(
        debug=True,
        use_reloader=True,
        host='0.0.0.0',  # Makes the server externally visible
        port=5000
    )
