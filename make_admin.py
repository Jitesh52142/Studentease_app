from app import app, db, User

def make_user_admin(email):
    if email != 'jiteshbawaskar05@gmail.com':
        print(f"Error: Admin access is restricted to jiteshbawaskar05@gmail.com only")
        return False
        
    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_admin = True
            db.session.commit()
            print(f"Successfully made {email} an admin")
            return True
        else:
            print(f"Error: No user found with email {email}")
            return False

if __name__ == '__main__':
    email = input("Enter the email of the user to make admin: ")
    make_user_admin(email) 