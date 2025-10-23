import os
import sys

# Add the parent directory to the path so we can import the app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import app
    print("✅ App imported successfully!")
except Exception as e:
    print(f"❌ Error importing app: {e}")
    import traceback
    traceback.print_exc()
    # Create a simple error app
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def error():
        return f"Error loading app: {e}", 500

# This is the entry point for Vercel
if __name__ == '__main__':
    app.run()
