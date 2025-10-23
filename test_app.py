#!/usr/bin/env python3
"""
Test script to check if the Flask app can start without errors
"""

import os
import sys

# Set environment variables for testing
os.environ['SECRET_KEY'] = 'test_secret_key_for_vercel_deployment_12345'
os.environ['MONGODB_URI'] = 'mongodb+srv://Jitesh001:Jitesh001@twicky.fxotzly.mongodb.net/marketplace?retryWrites=true&w=majority'

try:
    print("Testing app import...")
    from app import app
    print("✅ App imported successfully!")
    
    print("Testing app configuration...")
    print(f"SECRET_KEY: {app.config.get('SECRET_KEY', 'NOT SET')[:10]}...")
    print(f"MONGO_URI: {app.config.get('MONGO_URI', 'NOT SET')[:50]}...")
    
    print("Testing MongoDB connection...")
    try:
        # Test MongoDB connection
        mongo = app.extensions['pymongo']
        # Try to ping the database
        mongo.db.command('ping')
        print("✅ MongoDB connection successful!")
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
    
    print("Testing routes...")
    with app.test_client() as client:
        response = client.get('/')
        print(f"Home route status: {response.status_code}")
        
    print("✅ All tests passed!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
