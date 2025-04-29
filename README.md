# StudentEase Marketplace

A campus marketplace platform built with Flask where students can buy and sell items within their campus community.

## Features

- User authentication and authorization
- Product listing and management
- Image upload for products
- Search and category filtering
- QR code generation for products
- Secure payment integration
- Responsive design
- Admin dashboard

## Tech Stack

- Python 3.12
- Flask 2.0.1
- SQLAlchemy
- Bootstrap 5
- SQLite (development) / PostgreSQL (production)
- Stripe Payment Integration
- QR Code Generation

## Deployment on Render

1. Fork/Clone this repository
2. Create a new Web Service on Render
3. Connect your GitHub repository
4. Configure the following environment variables:
   - `SECRET_KEY`: Your Flask secret key
   - `STRIPE_SECRET_KEY`: Your Stripe secret key
   - `STRIPE_PUBLISHABLE_KEY`: Your Stripe publishable key
   - `DATABASE_URL`: Your PostgreSQL database URL (Render will provide this)
   - `FLASK_ENV`: Set to 'production'

5. Deploy! Render will automatically:
   - Install dependencies from requirements.txt
   - Run the application using Gunicorn

## Local Development

1. Clone the repository:
```bash
git clone https://github.com/yourusername/studentease.git
cd studentease
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize the database:
```bash
flask db upgrade
```

6. Run the development server:
```bash
flask run
```

## Directory Structure

```
studentease/
├── app.py              # Application entry point
├── requirements.txt    # Project dependencies
├── gunicorn.conf.py   # Gunicorn configuration
├── render.yaml        # Render deployment configuration
├── static/            # Static files
│   ├── avatars/      # User avatars
│   ├── css/          # CSS files
│   ├── images/       # General images
│   └── product_pics/ # Product images
├── templates/         # HTML templates
│   ├── admin/        # Admin panel templates
│   └── ...          # Other templates
└── utils/            # Utility functions
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 