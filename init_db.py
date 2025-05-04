from app import app, db, User
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect

with app.app_context():
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