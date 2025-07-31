from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
import pandas as pd
import sqlite3
import csv
from datetime import datetime, timedelta
import time
import os
import hashlib  # For password hashing

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure secret key
app.permanent_session_lifetime = timedelta(hours=24)  # Session expires after 24 hours

global username
global password

def hash_password(password):
    """Hash the password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def db_connection():
    """Create a database connection"""
    try:
        df = pd.read_csv('accounts.csv')
        conn = sqlite3.connect(':memory:')
        df.to_sql('accounts', conn, index=False, if_exists='replace')
        return conn
    except Exception as e:
        print(f"Database connection error: {str(e)}")
        return None

@app.route('/', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to index
    if session.get('username'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')

            if not username or not password:
                flash('Please enter both username and password.')
                return render_template('login.html')

            # Hash the password before checking
            hashed_password = hash_password(password)

            conn = db_connection()
            if not conn:
                flash('Database connection error. Please try again later.')
                return render_template('login.html')

            cursor = conn.cursor()
            query = "SELECT * FROM accounts WHERE username = ? AND password = ?;"
            cursor.execute(query, (username, hashed_password))
            user = cursor.fetchone()
            conn.close()

            if user:
                # Set session variables
                session['username'] = username
                session['user_id'] = user[0]  # Store SNo as user_id
                session['firstname'] = user[3]  # Store firstname
                session['lastname'] = user[4]  # Store lastname
                session.permanent = True
                
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password. Please try again.')
                return render_template('login.html')

        except Exception as e:
            flash('An error occurred during login. Please try again.')
            print(f"Login error: {str(e)}")
            return render_template('login.html')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            firstname = request.form.get('firstname')
            lastname = request.form.get('lastname')
            balance = request.form.get('balance')

            # Validate input
            if not all([username, password, firstname, lastname, balance]):
                flash('All fields are required.')
                return render_template('signup.html')

            if len(username) < 3:
                flash('Username must be at least 3 characters long.')
                return render_template('signup.html')

            if len(password) < 8:
                flash('Password must be at least 8 characters long.')
                return render_template('signup.html')

            try:
                balance = float(balance)
                if balance < 0:
                    flash('Starting balance cannot be negative.')
                    return render_template('signup.html')
            except ValueError:
                flash('Please enter a valid balance amount.')
                return render_template('signup.html')

            # Hash the password before storing
            hashed_password = hash_password(password)

            file_path = 'accounts.csv'

            # Create file if it doesn't exist
            if not os.path.exists(file_path):
                with open(file_path, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(['SNo', 'username', 'password', 'firstname', 'lastname', 'Balance', 'MonthlyIncome', 'MonthlyExpenses', 'SavingsRate'])

            df = pd.read_csv(file_path)

            if username in df['username'].values:
                flash('Username already exists. Please choose another one.')
                return render_template('signup.html')

            next_sno = df['SNo'].max() + 1 if not df.empty else 1

            new_user = {
                'SNo': next_sno,
                'username': username,
                'password': hashed_password,  # Store hashed password
                'firstname': firstname,
                'lastname': lastname,
                'Balance': balance,
                'MonthlyIncome': 0,
                'MonthlyExpenses': 0,
                'SavingsRate': 0
            }

            df = pd.concat([df, pd.DataFrame([new_user])], ignore_index=True)
            df.to_csv(file_path, index=False)

            flash('Account created successfully! You can now log in.')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'An error occurred: {str(e)}')
            print(f"Signup error: {str(e)}")
            return render_template('signup.html')

    return render_template('signup.html')

@app.route('/homepage')
def index():
    # Check if user is logged in
    if not session.get('username'):
        flash('Please log in first.')
        return redirect(url_for('login'))
    
    try:
        conn = db_connection()
        if not conn:
            flash('Database connection error. Please try again later.')
            return redirect(url_for('login'))

        cursor = conn.cursor()
        query = "SELECT * FROM accounts WHERE username = ?;"
        cursor.execute(query, (session['username'],))
        user = cursor.fetchone()
        conn.close()

        if user:
            return render_template('index.html', user=user)
        else:
            # If user not found in database, clear session and redirect to login
            session.clear()
            flash('Your session has expired. Please log in again.')
            return redirect(url_for('login'))
            
    except Exception as e:
        flash('An error occurred while loading your dashboard.')
        print(f"Index error: {str(e)}")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

@app.route('/check_notification')
def check_notification():
    try:
        # Read the CSV file
        df = pd.read_csv("accounts.csv")
        
        # Get the current user's data from session
        username = session.get('username')
        if not username:
            return jsonify({'show_notification': False})
            
        # Filter data for the current user
        user_data = df[df['username'] == username].iloc[0]
        
        # Check if expenses exceed 60% of income
        show_notification = user_data['MonthlyExpenses'] > 0.6 * user_data['MonthlyIncome']
        
        return jsonify({'show_notification': show_notification})
    except Exception as e:
        print(f"Error in check_notification: {str(e)}")
        return jsonify({'show_notification': False})

@app.route('/get_income_expense_data')
def get_income_expense_data():
    try:
        # Read the accounts CSV file
        df = pd.read_csv('accounts.csv')
        
        # Get the current user's data from session
        username = session.get('username')
        if not username:
            return jsonify({'error': 'User not logged in'}), 401
            
        # Filter data for the current user
        user_data = df[df['username'] == username].iloc[0]
        
        # Get the last 6 months
        current_month = datetime.now().month
        months = []
        for i in range(6):
            month = (current_month - i - 1) % 12 + 1
            months.append(datetime(2024, month, 1).strftime('%b'))
        months.reverse()
        
        # For now, we'll use the same monthly values since we don't have historical data
        # In a real app, you would store and retrieve historical data
        income_data = [user_data['MonthlyIncome']] * 6
        expense_data = [user_data['MonthlyExpenses']] * 6
        
        # Calculate spending categories based on monthly expenses
        total_expenses = user_data['MonthlyExpenses']
        spending_categories = {
            'Housing': total_expenses * 0.4,
            'Food': total_expenses * 0.2,
            'Transportation': total_expenses * 0.15,
            'Entertainment': total_expenses * 0.1,
            'Utilities': total_expenses * 0.1,
            'Other': total_expenses * 0.05
        }
        
        return jsonify({
            'months': months,
            'income': income_data,
            'expenses': expense_data,
            'spending_categories': spending_categories
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    
    
#checkpoint
@app.route('/update_finance', methods=['POST'])
def update_finance():
    data = request.get_json()
    total_balance = data.get('totalBalance')
    monthly_income = data.get('monthlyIncome')
    monthly_expenses = data.get('monthlyExpenses')
    savings_rate = data.get('savingsRate')
    username = data.get('username')
    
    print(f"Updating for user: {username}, Balance: {total_balance}, Income: {monthly_income}, Expenses: {monthly_expenses}, Savings Rate: {savings_rate}")
    
    # Update the CSV file
    try:
        # Read the CSV file
        csv_path = 'accounts.csv'
        df = pd.read_csv(csv_path)
        

        if username not in df['username'].values:
            return jsonify({"status": "error", "message": "User not found"}), 404
        

        df.loc[df['username'] == username, 'Balance'] = total_balance
        df.loc[df['username'] == username, 'MonthlyIncome'] = monthly_income
        df.loc[df['username'] == username, 'MonthlyExpenses'] = monthly_expenses
        df.loc[df['username'] == username, 'SavingsRate'] = savings_rate
        

        df.to_csv(csv_path, index=False)
        
        return jsonify({"status": "success"})
    except Exception as e:
        import traceback
        print(f"Error updating CSV: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)}), 500

def get_user_transactions(username):
    try:
        df = pd.read_csv('tranxtion.csv')
        user_transactions = df[df['uID'] == username].sort_values('date', ascending=False)
        return user_transactions.to_dict('records')
    except Exception as e:
        print(f"Error reading transactions: {str(e)}")
        return []

def add_transaction(username, transaction_data):
    try:
        # Read existing transactions
        df = pd.read_csv('tranxtion.csv')
        
        # Create new transaction
        new_transaction = {
            'tID': len(df) + 1,
            'TRANS': transaction_data['description'],
            'CATEGORY': transaction_data['category'],
            'date': transaction_data['date'],
            'amount': transaction_data['amount'],
            'uID': username
        }
        
        # Append new transaction
        df = pd.concat([df, pd.DataFrame([new_transaction])], ignore_index=True)
        
        # Save back to CSV
        df.to_csv('tranxtion.csv', index=False)
        return True
    except Exception as e:
        print(f"Error adding transaction: {str(e)}")
        return False

@app.route('/get_transactions')
def get_transactions():
    username = session.get('username')
    if not username:
        return jsonify({'error': 'User not logged in'}), 401
    
    transactions = get_user_transactions(username)
    return jsonify({'transactions': transactions})

@app.route('/add_transaction', methods=['POST'])
def add_transaction_route():
    username = session.get('username')
    if not username:
        return jsonify({'error': 'User not logged in'}), 401
    
    data = request.get_json()
    success = add_transaction(username, data)
    
    if success:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'error': 'Failed to add transaction'}), 500

# Add this function to calculate points
def calculate_points_from_savings(savings_rate):
    # Points = savings_rate / 50 (rounded down)
    return int(savings_rate / 50)

@app.route('/get_points')
def get_points():
    try:
        username = session.get('username')
        if not username:
            return jsonify({'error': 'User not logged in'}), 401

        # Read user data
        df = pd.read_csv('accounts.csv')
        user_data = df[df['username'] == username].iloc[0]
        
        # Get savings rate
        savings_rate = float(user_data['SavingsRate'])
        
        # Calculate points
        points = calculate_points_from_savings(savings_rate)
        
        return jsonify({
            'points': points,
            'savings_rate': savings_rate
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/check_expense_notification')
def check_expense_notification():
    try:
        username = session.get('username')
        if not username:
            return jsonify({'error': 'User not logged in'}), 401

        # Read user data
        df = pd.read_csv('accounts.csv')
        user_data = df[df['username'] == username].iloc[0]
        
        # Calculate expense percentage of income
        monthly_income = float(user_data['MonthlyIncome'])
        monthly_expenses = float(user_data['MonthlyExpenses'])
        
        if monthly_income == 0:
            expense_percentage = 0
        else:
            expense_percentage = (monthly_expenses / monthly_income) * 100
        
        # Check if expenses exceed 60% of income
        show_notification = expense_percentage > 60
        
        return jsonify({
            'show_notification': show_notification,
            'expense_percentage': round(expense_percentage, 2),
            'monthly_income': monthly_income,
            'monthly_expenses': monthly_expenses
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_user_data')
def get_user_data():
    try:
        username = session.get('username')
        if not username:
            return jsonify({'error': 'User not logged in'}), 401

        # Read user data
        df = pd.read_csv('accounts.csv')
        user_data = df[df['username'] == username].iloc[0]
        
        return jsonify({
            'monthly_income': float(user_data['MonthlyIncome']),
            'monthly_expenses': float(user_data['MonthlyExpenses']),
            'savings_rate': float(user_data['SavingsRate'])
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
