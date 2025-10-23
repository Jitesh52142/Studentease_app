# StudentEase Marketplace - Vercel Deployment Guide

## Prerequisites
- Vercel account
- MongoDB Atlas account
- GitHub account (for version control)

## Environment Variables Setup

Before deploying to Vercel, you need to set up the following environment variables in your Vercel project:

1. **SECRET_KEY**: A secure secret key for Flask sessions
2. **MONGODB_URI**: `mongodb+srv://Jitesh001:Jitesh001@twicky.fxotzly.mongodb.net/marketplace?retryWrites=true&w=majority`
3. **STRIPE_SECRET_KEY**: Your Stripe secret key (if using Stripe payments)
4. **MAIL_USERNAME**: Your Gmail address for sending emails
5. **MAIL_PASSWORD**: Your Gmail app password
6. **MAIL_DEFAULT_SENDER**: Your Gmail address (same as MAIL_USERNAME)

## Deployment Steps

### 1. Prepare the Repository
1. Push your code to a GitHub repository
2. Make sure all files are committed and pushed

### 2. Deploy to Vercel
1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Click "New Project"
3. Import your GitHub repository
4. Vercel will automatically detect it's a Python project
5. Set the following settings:
   - **Framework Preset**: Other
   - **Root Directory**: `Studentease_app`
   - **Build Command**: Leave empty (Vercel will auto-detect)
   - **Output Directory**: Leave empty

### 3. Configure Environment Variables
1. In your Vercel project dashboard, go to **Settings** > **Environment Variables**
2. Click **Add New** for each variable below:

   **Required Variables:**
   - **Name**: `SECRET_KEY` | **Value**: `your_very_secure_secret_key_here_make_it_long_and_random`
   - **Name**: `MONGODB_URI` | **Value**: `mongodb+srv://Jitesh001:Jitesh001@twicky.fxotzly.mongodb.net/marketplace?retryWrites=true&w=majority`
   
   **Optional Variables (for full functionality):**
   - **Name**: `STRIPE_SECRET_KEY` | **Value**: `your_stripe_secret_key_here`
   - **Name**: `MAIL_USERNAME` | **Value**: `your-email@gmail.com`
   - **Name**: `MAIL_PASSWORD` | **Value**: `your-gmail-app-password`
   - **Name**: `MAIL_DEFAULT_SENDER` | **Value**: `your-email@gmail.com`

3. **Important**: Make sure to set the environment for **Production**, **Preview**, and **Development**
4. Click **Save** after adding each variable

### 4. Deploy
1. Click "Deploy"
2. Wait for the deployment to complete
3. Your app will be available at `https://your-project-name.vercel.app`

## Admin Access

After deployment, you can access the admin panel with:
- **Email**: jiteshbawaskar05@gmail.com
- **Password**: Jitesh001@

## File Structure for Vercel

```
Studentease_app/
├── api/
│   └── index.py          # Vercel entry point
├── static/               # Static files (CSS, JS, images)
├── templates/            # HTML templates
├── app_mongodb_complete.py  # Main Flask app with MongoDB
├── requirements.txt      # Python dependencies
├── vercel.json          # Vercel configuration
└── .env                 # Local environment variables (not used in production)
```

## Database

The app uses MongoDB Atlas with the following collections:
- `users` - User accounts and profiles
- `products` - Product listings
- `orders` - Order transactions
- `payment_qr` - Payment QR codes

## Features

- User registration and authentication
- Product listing and management
- Order processing
- Admin dashboard
- Email notifications
- File uploads for product images
- Search and filtering
- Payment integration (Stripe)

## Troubleshooting

1. **Build Errors**: Check that all dependencies are in requirements.txt
2. **Database Connection**: Verify MongoDB URI is correct
3. **Email Issues**: Check Gmail app password setup
4. **File Uploads**: Vercel has limitations on file uploads, consider using cloud storage

## Local Development

To run locally:
1. Install dependencies: `pip install -r requirements.txt`
2. Set up environment variables in `.env` file
3. Run: `python app_mongodb_complete.py`

## Support

For issues or questions, contact the development team.
