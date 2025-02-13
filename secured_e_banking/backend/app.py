from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from cryptography.fernet import Fernet
import tenseal as ts

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///banking.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Load encryption key
def load_key():
    key_file_path = 'secret.key'
    try:
        if os.path.exists(key_file_path):
            with open(key_file_path, 'rb') as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(key_file_path, 'wb') as key_file:
                key_file.write(key)
            print("New encryption key generated and saved")
            return key
    except Exception as e:
        print(f"Error with encryption key: {e}")
        raise

# Initialize encryption
key = load_key()
cipher_suite = Fernet(key)

# Initialize CKKS context
context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[60, 40, 40, 60]
)
context.global_scale = 2**40

def encrypt_string(value):
    """Encrypt a string using Fernet."""
    return cipher_suite.encrypt(str(value).encode())

def decrypt_string(encrypted_value):
    """Decrypt a string using Fernet."""
    try:
        return cipher_suite.decrypt(encrypted_value).decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def encrypt_value(value):
    """Encrypt a numeric value using CKKS."""
    return ts.ckks_vector(context, [float(value)]).serialize()

def decrypt_value(encrypted_value):
    """Decrypt a CKKS encrypted value."""
    if encrypted_value:
        encrypted = ts.ckks_vector_from(context, encrypted_value)
        return round(encrypted.decrypt()[0], 2)
    return 0.0

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False)
    account_number = db.Column(db.LargeBinary, unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    encrypted_balance = db.Column(db.LargeBinary)
    identity = db.Column(db.String(120), nullable=False)

    @property
    def balance(self):
        if self.encrypted_balance:
            try:
                decrypted_value = decrypt_value(self.encrypted_balance)
                # Add strict validation
                if not isinstance(decrypted_value, (int, float)):
                    print("Invalid balance type detected")
                    return 0.0
                if decrypted_value < 0 or decrypted_value > 1e9:  # Max 1 billion
                    print(f"Balance out of range: {decrypted_value}")
                    return 0.0
                return round(decrypted_value, 2)  # Round to 2 decimal places
            except Exception as e:
                print(f"Balance decryption error: {e}")
                return 0.0
        return 0.0

    @balance.setter
    def balance(self, value):
        try:
            # Validate input value
            if not isinstance(value, (int, float)):
                raise ValueError("Balance must be a number")
            value = float(value)
            if value < 0:
                value = 0.0
            if value > 1e9:  # Max 1 billion
                value = 1e9
            value = round(value, 2)  # Round to 2 decimal places
            self.encrypted_balance = encrypt_value(value)
        except Exception as e:
            print(f"Balance encryption error: {e}")
            self.encrypted_balance = encrypt_value(0.0)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            print("\n=== New Registration Attempt ===")
            print(f"Username: {username}")
            
            # Generate account number
            account_number = "1000000000"
            last_user = User.query.order_by(User.id.desc()).first()
            if last_user:
                last_account = decrypt_string(last_user.account_number)
                account_number = str(int(last_account) + 1)
                print(f"Generated Account Number: {account_number}")
            
            # Check if account number exists
            encrypted_account = encrypt_string(account_number)
            existing_account = User.query.filter_by(account_number=encrypted_account).first()
            
            if existing_account:
                print("Error: Account number already exists")
                flash('Error generating account number. Please try again.', 'error')
                return redirect(url_for('register'))
            
            # Create new user with plain username
            new_user = User(
                username=username,  # Store username as plain text
                account_number=encrypted_account,
                password_hash=generate_password_hash(password),
                identity=username
            )
            new_user.balance = 0.0
            
            db.session.add(new_user)
            db.session.commit()
            
            print(f"Registration successful for {username} with account {account_number}")
            print("=" * 30)
            
            flash(f'Registration successful! Your account number is {account_number}', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Registration error: {e}")
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        account_number = request.form['account_number']
        password = request.form['password']
        
        try:
            print("\n=== Login Attempt ===")
            print(f"Username: {username}")
            print(f"Account Number: {account_number}")
            
            # Find user by account number
            users = User.query.all()
            user = None
            
            for u in users:
                if decrypt_string(u.account_number) == account_number:
                    user = u
                    break
            
            if user and user.username == username:  # Direct comparison since username is plain text
                if check_password_hash(user.password_hash, password):
                    session['user_id'] = user.id
                    print(f"Login successful for {username}")
                    print("=" * 30)
                    flash('Logged in successfully!', 'success')
                    return redirect(url_for('dashboard'))
            
            print("Login failed: Invalid credentials")
            print("=" * 30)
            flash('Invalid credentials.', 'error')
            
        except Exception as e:
            print(f"Login error: {e}")
            flash('Login failed. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        user = db.session.get(User, session['user_id'])
        if user:
            account_number = decrypt_string(user.account_number)
            print(f"\n=== Dashboard Access ===")
            print(f"User: {user.username}")  # Direct username access
            print(f"Account: {account_number}")
            print(f"Balance: ₹{user.balance:.2f}")
            print("=" * 30)
            
            return render_template('dashboard.html',
                                username=user.username,  # Direct username access
                                account_number=account_number,
                                balance=user.balance)
    except Exception as e:
        print(f"Dashboard error: {e}")
        flash('Error loading dashboard.', 'error')
        return redirect(url_for('login'))

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            return redirect(url_for('login'))
        
        username = user.username  # Direct access
        account_number = decrypt_string(user.account_number)
        
        if request.method == 'POST':
            try:
                amount = float(request.form['amount'])
                print(f"\n=== Deposit Attempt ===")
                print(f"User: {username}")
                print(f"Account: {account_number}")
                print(f"Amount: ₹{amount:.2f}")
                
                if amount <= 0:
                    print("Error: Invalid amount")
                    flash('Please enter a positive amount.', 'error')
                else:
                    previous_balance = user.balance
                    user.balance = previous_balance + amount
                    db.session.commit()
                    print(f"Previous Balance: ₹{previous_balance:.2f}")
                    print(f"New Balance: ₹{user.balance:.2f}")
                    print("Deposit successful")
                    flash(f'Successfully deposited ₹{amount:.2f}', 'success')
                    return redirect(url_for('dashboard'))
                
                print("=" * 30)
                
            except ValueError:
                flash('Please enter a valid amount.', 'error')
            except Exception as e:
                print(f"Deposit error: {e}")
                flash('Error processing deposit.', 'error')
        
        return render_template('deposit.html',
                            username=username,
                            account_number=account_number,
                            balance=user.balance)
    except Exception as e:
        print(f"Deposit page error: {e}")
        flash('Error loading deposit page.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            return redirect(url_for('login'))
        
        username = user.username
        account_number = decrypt_string(user.account_number)
        
        if request.method == 'POST':
            try:
                amount = float(request.form['amount'])
                print(f"\n=== Withdrawal Attempt ===")
                print(f"User: {username}")
                print(f"Account: {account_number}")
                print(f"Amount: ₹{amount:.2f}")
                
                if amount <= 0:
                    print("Error: Invalid amount")
                    flash('Please enter a positive amount.', 'error')
                elif amount > user.balance:
                    print("Error: Insufficient funds")
                    flash('Insufficient funds.', 'error')
                else:
                    previous_balance = user.balance
                    user.balance = previous_balance - amount
                    db.session.commit()
                    print(f"Previous Balance: ₹{previous_balance:.2f}")
                    print(f"New Balance: ₹{user.balance:.2f}")
                    print("Withdrawal successful")
                    flash(f'Successfully withdrawn ₹{amount:.2f}', 'success')
                    return redirect(url_for('dashboard'))
                
                print("=" * 30)
                
            except ValueError:
                flash('Please enter a valid amount.', 'error')
            except Exception as e:
                print(f"Withdrawal error: {e}")
                flash('Error processing withdrawal.', 'error')
        
        return render_template('withdraw.html',
                            username=username,
                            account_number=account_number,
                            balance=user.balance)
    except Exception as e:
        print(f"Withdraw page error: {e}")
        flash('Error loading withdraw page.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        sender = db.session.get(User, session['user_id'])
        if not sender:
            return redirect(url_for('login'))
        
        username = sender.username
        account_number = decrypt_string(sender.account_number)
        
        if request.method == 'POST':
            try:
                amount = float(request.form['amount'])
                recipient_account = request.form['recipient_account']
                
                print(f"\n=== Transfer Attempt ===")
                print(f"From User: {username}")
                print(f"From Account: {account_number}")
                print(f"To Account: {recipient_account}")
                print(f"Amount: ₹{amount:.2f}")
                
                if amount <= 0:
                    print("Error: Invalid amount")
                    flash('Please enter a positive amount.', 'error')
                    return redirect(url_for('transfer'))
                
                # Find recipient by account number
                users = User.query.all()
                recipient = None
                for user in users:
                    if decrypt_string(user.account_number) == recipient_account:
                        recipient = user
                        break
                
                if recipient and recipient.id != sender.id:
                    if sender.balance >= amount:
                        # Process transfer
                        sender_previous_balance = sender.balance
                        recipient_previous_balance = recipient.balance
                        
                        sender.balance = sender_previous_balance - amount
                        recipient.balance = recipient_previous_balance + amount
                        
                        db.session.commit()
                        
                        recipient_name = recipient.username
                        print(f"Transfer successful")
                        print(f"Sender previous balance: ₹{sender_previous_balance:.2f}")
                        print(f"Sender new balance: ₹{sender.balance:.2f}")
                        print(f"Recipient previous balance: ₹{recipient_previous_balance:.2f}")
                        print(f"Recipient new balance: ₹{recipient.balance:.2f}")
                        
                        flash(f'Successfully transferred ₹{amount:.2f} to account {recipient_account} ({recipient_name})', 'success')
                        return redirect(url_for('dashboard'))
                    else:
                        print("Error: Insufficient funds")
                        flash('Insufficient funds.', 'error')
                else:
                    print("Error: Invalid recipient account")
                    flash('Invalid recipient account number.', 'error')
                
                print("=" * 30)
                
            except ValueError:
                flash('Please enter a valid amount.', 'error')
            except Exception as e:
                print(f"Transfer error: {e}")
                flash('Error processing transfer.', 'error')
                db.session.rollback()
        
        return render_template('transfer.html',
                            username=username,
                            account_number=account_number,
                            balance=sender.balance)
    except Exception as e:
        print(f"Transfer page error: {e}")
        flash('Error loading transfer page.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    if 'user_id' in session:
        print("\n=== User Logout ===")
        user = db.session.get(User, session['user_id'])
        if user:
            username = user.username
            print(f"User {username} logged out")
            print("=" * 30)
    
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/reset_balance')
def reset_balance():
    if 'user_id' in session:
        try:
            user = db.session.get(User, session['user_id'])
            if user:
                user.balance = 0.0
                db.session.commit()
                flash('Balance has been reset to ₹0.00', 'success')
        except Exception as e:
            print(f"Reset balance error: {e}")
            flash('Error resetting balance', 'error')
    return redirect(url_for('dashboard'))

@app.route('/check_balance')
def check_balance():
    if 'user_id' in session:
        try:
            user = db.session.get(User, session['user_id'])
            if user:
                raw_balance = user.encrypted_balance
                decrypted_balance = user.balance
                print(f"\n=== Balance Check ===")
                print(f"User: {user.username}")
                print(f"Raw encrypted balance exists: {raw_balance is not None}")
                print(f"Decrypted balance: ₹{decrypted_balance:.2f}")
                print("=" * 30)
                flash(f'Balance verified: ₹{decrypted_balance:.2f}', 'success')
        except Exception as e:
            print(f"Balance check error: {e}")
            flash('Error checking balance', 'error')
    return redirect(url_for('dashboard'))

@app.route('/fix_balance')
def fix_balance():
    if 'user_id' in session:
        try:
            user = db.session.get(User, session['user_id'])
            if user:
                print("\n=== Fixing Balance ===")
                print(f"User: {user.username}")
                print(f"Old Balance: ₹{user.balance:.2f}")
                
                # Reset to 0 or your last known correct balance
                user.balance = 0.0  # Or set to your last known correct balance
                db.session.commit()
                
                print(f"New Balance: ₹{user.balance:.2f}")
                print("=" * 30)
                flash('Balance has been fixed', 'success')
        except Exception as e:
            print(f"Fix balance error: {e}")
            flash('Error fixing balance', 'error')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

