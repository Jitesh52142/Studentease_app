from flask import Flask, render_template, url_for, flash, redirect, request, jsonify, abort
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
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
from bson import ObjectId

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['MONGO_URI'] = os.getenv('MONGODB_URI', 'mongodb+srv://Jitesh001:Jitesh001@twicky.fxotzly.mongodb.net/marketplace?retryWrites=true&w=majority')
app.config['UPLOAD_FOLDER'] = 'static'
app.config['AVATARS_FOLDER'] = 'static/avatars'
app.config['PRODUCTS_FOLDER'] = 'static/product_pics'
app.config['PURCHASED_PRODUCTS_FOLDER'] = 'static/purchased_products'
app.config['QR_CODES_FOLDER'] = 'static/qr_codes'
app.config['PAYMENT_PROOFS_FOLDER'] = 'static/payment_proofs'
app.config['PAYMENT_SCREENSHOTS_FOLDER'] = 'static/payment_screenshots'
stripe.api_key = os.getenv('STRIPE_SECRET_KEY', 'your_stripe_secret_key')

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'your-app-password')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'your-email@gmail.com')
mail = Mail(app)

# Create necessary directories if they don't exist
os.makedirs(app.config['AVATARS_FOLDER'], exist_ok=True)
os.makedirs(app.config['PRODUCTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['PURCHASED_PRODUCTS_FOLDER'], exist_ok=True)
os.makedirs(app.config['QR_CODES_FOLDER'], exist_ok=True)
os.makedirs(app.config['PAYMENT_PROOFS_FOLDER'], exist_ok=True)
os.makedirs(app.config['PAYMENT_SCREENSHOTS_FOLDER'], exist_ok=True)

# Initialize MongoDB
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Database Models using MongoDB collections
class User(UserMixin):
    def __init__(self, user_data):
        self._id = str(user_data.get('_id', '')) if user_data.get('_id') else ''
        self.username = user_data['username']
        self.email = user_data['email']
        self.phone = user_data.get('phone')
        self.password = user_data['password']
        self.is_admin = user_data.get('is_admin', False)
        self.date_joined = user_data.get('date_joined', datetime.now(UTC))
        self.last_seen = user_data.get('last_seen', datetime.now(UTC))
        self._is_active = user_data.get('is_active', True)
        self.avatar = user_data.get('avatar', 'default.jpg')
        self.location = user_data.get('location')
        self.bio = user_data.get('bio')

    @property
    def id(self):
        return self._id

    @property
    def is_active(self):
        return self._is_active

    @is_active.setter
    def is_active(self, value):
        self._is_active = value

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
        user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        return User(user_data) if user_data else None

    def save(self):
        user_data = {
            'username': self.username,
            'email': self.email,
            'phone': self.phone,
            'password': self.password,
            'is_admin': self.is_admin,
            'date_joined': self.date_joined,
            'last_seen': self.last_seen,
            'is_active': self._is_active,
            'avatar': self.avatar,
            'location': self.location,
            'bio': self.bio
        }
        if hasattr(self, '_id') and self._id:
            mongo.db.users.update_one({'_id': ObjectId(self._id)}, {'$set': user_data})
        else:
            result = mongo.db.users.insert_one(user_data)
            self._id = str(result.inserted_id)

    @staticmethod
    def find_by_email(email):
        user_data = mongo.db.users.find_one({'email': email})
        return User(user_data) if user_data else None

    @staticmethod
    def find_by_username(username):
        user_data = mongo.db.users.find_one({'username': username})
        return User(user_data) if user_data else None

    @staticmethod
    def find_by_id(user_id):
        user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        return User(user_data) if user_data else None

    @staticmethod
    def find_all():
        users = mongo.db.users.find()
        return [User(user_data) for user_data in users]

class Product:
    def __init__(self, product_data):
        self.id = str(product_data.get('_id', '')) if product_data.get('_id') else ''
        self.title = product_data['title']
        self.description = product_data['description']
        self.price = product_data['price']
        self.date_posted = product_data.get('date_posted', datetime.now(UTC))
        self.image_file = product_data.get('image_file', 'default.jpg')
        self.qr_code = product_data.get('qr_code')
        self.category = product_data['category']
        self.condition = product_data['condition']
        self.status = product_data.get('status', 'available')
        self.user_id = product_data['user_id']

    def save(self):
        product_data = {
            'title': self.title,
            'description': self.description,
            'price': self.price,
            'date_posted': self.date_posted,
            'image_file': self.image_file,
            'qr_code': self.qr_code,
            'category': self.category,
            'condition': self.condition,
            'status': self.status,
            'user_id': self.user_id
        }
        if hasattr(self, 'id') and self.id:
            mongo.db.products.update_one({'_id': ObjectId(self.id)}, {'$set': product_data})
        else:
            result = mongo.db.products.insert_one(product_data)
            self.id = str(result.inserted_id)

    @staticmethod
    def find_by_id(product_id):
        product_data = mongo.db.products.find_one({'_id': ObjectId(product_id)})
        return Product(product_data) if product_data else None

    @staticmethod
    def find_all():
        products = mongo.db.products.find()
        return [Product(product_data) for product_data in products]

    @staticmethod
    def find_by_user_id(user_id):
        products = mongo.db.products.find({'user_id': user_id})
        return [Product(product_data) for product_data in products]

    @staticmethod
    def find_available():
        products = mongo.db.products.find({'status': 'available'})
        return [Product(product_data) for product_data in products]

    @staticmethod
    def search(search_term, category=None):
        query = {'status': 'available'}
        if search_term:
            query['$or'] = [
                {'title': {'$regex': search_term, '$options': 'i'}},
                {'description': {'$regex': search_term, '$options': 'i'}}
            ]
        if category:
            query['category'] = category
        products = mongo.db.products.find(query).sort('date_posted', -1)
        return [Product(product_data) for product_data in products]

    def delete(self):
        mongo.db.products.delete_one({'_id': ObjectId(self.id)})

class Order:
    def __init__(self, order_data):
        self.id = str(order_data.get('_id', '')) if order_data.get('_id') else ''
        self.buyer_id = order_data['buyer_id']
        self.product_id = order_data['product_id']
        self.date_ordered = order_data.get('date_ordered', datetime.now(UTC))
        self.status = order_data.get('status', 'pending')
        self.payment_id = order_data.get('payment_id')
        self.payment_screenshot = order_data.get('payment_screenshot')
        self.payment_status = order_data.get('payment_status', 'pending')
        self.payment_verified = order_data.get('payment_verified', False)
        self.payment_method = order_data.get('payment_method', 'qr')
        self.payment_proof = order_data.get('payment_proof')
        self.purchased_image = order_data.get('purchased_image')

    def save(self):
        order_data = {
            'buyer_id': self.buyer_id,
            'product_id': self.product_id,
            'date_ordered': self.date_ordered,
            'status': self.status,
            'payment_id': self.payment_id,
            'payment_screenshot': self.payment_screenshot,
            'payment_status': self.payment_status,
            'payment_verified': self.payment_verified,
            'payment_method': self.payment_method,
            'payment_proof': self.payment_proof,
            'purchased_image': self.purchased_image
        }
        if hasattr(self, 'id') and self.id:
            mongo.db.orders.update_one({'_id': ObjectId(self.id)}, {'$set': order_data})
        else:
            result = mongo.db.orders.insert_one(order_data)
            self.id = str(result.inserted_id)

    @staticmethod
    def find_by_id(order_id):
        order_data = mongo.db.orders.find_one({'_id': ObjectId(order_id)})
        return Order(order_data) if order_data else None

    @staticmethod
    def find_all():
        orders = mongo.db.orders.find().sort('date_ordered', -1)
        return [Order(order_data) for order_data in orders]

    @staticmethod
    def find_by_buyer_id(buyer_id):
        orders = mongo.db.orders.find({'buyer_id': buyer_id})
        return [Order(order_data) for order_data in orders]

    @staticmethod
    def find_by_product_id(product_id):
        orders = mongo.db.orders.find({'product_id': product_id})
        return [Order(order_data) for order_data in orders]

class PaymentQR:
    def __init__(self, qr_data):
        self.id = str(qr_data.get('_id', '')) if qr_data.get('_id') else ''
        self.qr_code = qr_data['qr_code']
        self.instructions = qr_data['instructions']
        self.date_updated = qr_data.get('date_updated', datetime.now(UTC))

    def save(self):
        qr_data = {
            'qr_code': self.qr_code,
            'instructions': self.instructions,
            'date_updated': self.date_updated
        }
        if hasattr(self, 'id') and self.id:
            mongo.db.payment_qr.update_one({'_id': ObjectId(self.id)}, {'$set': qr_data})
        else:
            result = mongo.db.payment_qr.insert_one(qr_data)
            self.id = str(result.inserted_id)

    @staticmethod
    def find_first():
        qr_data = mongo.db.payment_qr.find_one()
        return PaymentQR(qr_data) if qr_data else None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin or current_user.email != 'jiteshbawaskar05@gmail.com':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.find_by_id(user_id)

@app.route('/')
@app.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    filter_type = request.args.get('filter', '')

    if search or category:
        products = Product.search(search, category)
    elif filter_type and current_user.is_authenticated:
        if filter_type == 'my_products':
            products = Product.find_by_user_id(current_user.id)
        elif filter_type == 'my_purchases':
            orders = Order.find_by_buyer_id(current_user.id)
            product_ids = [order.product_id for order in orders]
            products = [Product.find_by_id(pid) for pid in product_ids if Product.find_by_id(pid)]
        elif filter_type == 'my_sales':
            orders = Order.find_all()
            my_products = Product.find_by_user_id(current_user.id)
            my_product_ids = [p.id for p in my_products]
            sold_orders = [o for o in orders if o.product_id in my_product_ids and o.status == 'completed']
            product_ids = [order.product_id for order in sold_orders]
            products = [Product.find_by_id(pid) for pid in product_ids if Product.find_by_id(pid)]
        else:
            products = Product.find_available()
    else:
        products = Product.find_available()

    # Simple pagination
    per_page = 12
    start = (page - 1) * per_page
    end = start + per_page
    paginated_products = products[start:end]
    
    # Create a simple pagination object
    class Pagination:
        def __init__(self, items, page, per_page, total):
            self.items = items
            self.page = page
            self.per_page = per_page
            self.total = total
            self.pages = (total + per_page - 1) // per_page
            self.has_prev = page > 1
            self.has_next = page < self.pages
            self.prev_num = page - 1 if self.has_prev else None
            self.next_num = page + 1 if self.has_next else None

    pagination = Pagination(paginated_products, page, per_page, len(products))
    args = request.args.to_dict()
    args.pop('page', None)

    return render_template('home.html', products=pagination, request_args=args)

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

        if not re.match("^[a-zA-Z0-9_.-]+$", username):
            flash('Username can only contain letters, numbers, dots, and underscores', 'danger')
            return redirect(url_for('register'))

        if len(username) < 3 or len(username) > 20:
            flash('Username must be between 3 and 20 characters long', 'danger')
            return redirect(url_for('register'))

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Please enter a valid email address', 'danger')
            return redirect(url_for('register'))

        if not re.match(r'^\+?1?\d{9,15}$', phone):
            flash('Please enter a valid phone number', 'danger')
            return redirect(url_for('register'))

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

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        if User.find_by_username(username):
            flash('This username is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        if User.find_by_email(email):
            flash('An account with this email already exists. Please use a different email or try logging in.', 'danger')
            return redirect(url_for('register'))

        try:
            is_first_user = mongo.db.users.count_documents({}) == 0
            user = User({
                'username': username,
                'email': email,
                'phone': phone,
                'is_admin': is_first_user,
                'password': '',  # Will be set below
                'date_joined': datetime.now(UTC),
                'last_seen': datetime.now(UTC),
                'is_active': True,
                'avatar': 'default.jpg'
            })
            user.set_password(password)
            user.save()

            try:
                send_welcome_email(user)
            except Exception as e:
                print(f"Failed to send welcome email: {str(e)}")

            if is_first_user:
                flash('Your admin account has been created successfully! You can now log in.', 'success')
            else:
                flash('Your account has been created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error during registration: {str(e)}")
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
        
        print(f"Login attempt for email: {email}")
        
        user = User.find_by_email(email)
        
        if not user:
            flash('No account found with this email address.', 'danger')
            return redirect(url_for('login'))
            
        if not user.is_active:
            flash('This account has been deactivated. Please contact support.', 'danger')
            return redirect(url_for('login'))
            
        if not user.check_password(password):
            flash('Incorrect password. Please try again.', 'danger')
            return redirect(url_for('login'))
        
        login_user(user, remember=request.form.get('remember', False))
        user.last_seen = datetime.now(UTC)
        try:
            user.save()
            flash('Welcome back, {}!'.format(user.username), 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        except Exception as e:
            print(f"Error during login: {str(e)}")
            flash('An error occurred during login. Please try again.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/about')
def about():
    return render_template('about.html')

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
            # Validate file extension
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
            if '.' not in image.filename or image.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                flash('Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed.', 'danger')
                return redirect(request.url)
            
            filename = secure_filename(f"product_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}_{image.filename}")
            image_path = os.path.join(app.config['PRODUCTS_FOLDER'], filename)
            try:
                image.save(image_path)
            except Exception as e:
                print(f"Error saving image: {str(e)}")
                flash('Error saving image. Please try again.', 'danger')
                return redirect(request.url)
            
            product = Product({
                'title': request.form['title'],
                'description': request.form['description'],
                'price': float(request.form['price']),
                'category': request.form['category'],
                'condition': request.form['condition'],
                'image_file': filename,
                'user_id': current_user.id
            })
            try:
                product.save()
                flash('Your product has been listed!', 'success')
                return redirect(url_for('home'))
            except Exception as e:
                print(f"Error saving product: {str(e)}")
                flash('Error listing product. Please try again.', 'danger')
                return redirect(request.url)
    
    return render_template('create_product.html')

@app.route('/product/<int:product_id>')
def product(product_id):
    product = Product.find_by_id(str(product_id))
    if not product:
        abort(404)
    payment_qr = PaymentQR.find_first()
    return render_template('product.html', 
                         title=product.title,
                         product=product,
                         payment_qr=payment_qr)

@app.route('/profile/<username>')
def profile(username):
    user = User.find_by_username(username)
    if not user:
        abort(404)
    products = Product.find_by_user_id(user.id)
    
    orders = Order.find_by_buyer_id(user.id)
    purchases = [o for o in orders if o.status in ['completed', 'processing'] and o.payment_status in ['completed', 'processing']]
    
    payment_qr = PaymentQR.find_first()
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
            if current_user.check_password(request.form['current_password']):
                current_user.set_password(request.form['new_password'])
                current_user.save()
                flash('Your password has been updated!', 'success')
            else:
                flash('Current password is incorrect!', 'danger')
        else:
            current_user.username = request.form['username']
            current_user.email = request.form['email']
            current_user.save()
            flash('Your account has been updated!', 'success')
        
        return redirect(url_for('settings'))
    
    return render_template('settings.html', user=current_user)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        user = User.find_by_email(request.form['email'])
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
            user.set_password(password)
            user.save()
            flash('Your password has been updated! You can now log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html')

def send_reset_email(user, token):
    subject = 'Password Reset Request'
    body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    send_email(user.email, subject, body)

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

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(UTC)
        current_user.save()

@app.template_filter('timeago')
def timeago_filter(date):
    if not date.tzinfo:
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

# Initialize admin user if not exists
def init_admin():
    admin_user = User.find_by_email('jiteshbawaskar05@gmail.com')
    if not admin_user:
        admin = User({
            'username': 'admin',
            'email': 'jiteshbawaskar05@gmail.com',
            'phone': '+1234567890',
            'is_admin': True,
            'password': '',
            'date_joined': datetime.now(UTC),
            'last_seen': datetime.now(UTC),
            'is_active': True,
            'avatar': 'default.jpg'
        })
        admin.set_password('Jitesh001@')
        admin.save()
        print("Admin user created successfully!")

if __name__ == '__main__':
    # Create indexes for better performance
    mongo.db.users.create_index("email", unique=True)
    mongo.db.users.create_index("username", unique=True)
    mongo.db.products.create_index("user_id")
    mongo.db.products.create_index("status")
    mongo.db.orders.create_index("buyer_id")
    mongo.db.orders.create_index("product_id")
    
    # Initialize admin user
    init_admin()
    
    app.run(
        debug=True,
        use_reloader=True,
        host='0.0.0.0',
        port=5000
    )
