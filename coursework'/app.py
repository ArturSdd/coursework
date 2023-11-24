import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
import bcrypt
import ccxt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def init_db():
    with sqlite3.connect('users.db') as db:
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL  -- Make sure this matches the column used in your INSERT statement
            );
        ''')
        db.commit()


# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())

        try:
            with sqlite3.connect('users.db') as db:
                cursor = db.cursor()
                cursor.execute('INSERT INTO users (username, hashed_password) VALUES (?, ?)', (username, hashed))
                db.commit()
            flash('You have successfully registered', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')

    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            cursor.execute('SELECT id, username, hashed_password FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password, user[2]):
                session['loggedin'] = True
                session['user_id'] = user[0]
                session['username'] = user[1]
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect username/password', 'danger')

    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# Dashboard Route
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password == confirm_password:
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            with sqlite3.connect('users.db') as db:
                cursor = db.cursor()
                cursor.execute('UPDATE users SET hashed_password = ? WHERE id = ?', (hashed, session['user_id']))
                db.commit()
            flash('Password successfully updated', 'success')
        else:
            flash('Passwords do not match', 'danger')

    return render_template('dashboard.html', username=session['username'])

# Main Page Route
@app.route('/', methods=['GET', 'POST'])
def main_page():
    selected_exchanges = ['binance', 'kraken', 'coinbasepro', 'bitfinex']  # Default exchanges
    crypto_symbol = 'BTC'  # Default cryptocurrency

    if request.method == 'POST':
        selected_exchanges = request.form.getlist('exchanges')
        crypto_symbol = request.form.get('crypto_symbol', default='BTC').upper()

    prices = fetch_crypto_prices(selected_exchanges, crypto_symbol)

    return render_template('main.html', exchanges=selected_exchanges, prices=prices, crypto_symbol=crypto_symbol)

def fetch_crypto_prices(exchanges, symbol):
    prices = {}
    for exchange_id in exchanges:
        exchange_class = getattr(ccxt, exchange_id)()
        try:
            exchange_class.load_markets()
            price = exchange_class.fetch_ticker(symbol + '/USDT')['last']
            prices[exchange_id] = f'${price:.2f}'
        except Exception as e:
            prices[exchange_id] = 'Error'
    return prices

@app.route('/prices')
def prices():
    selected_exchanges = request.args.getlist('exchanges')
    crypto_symbol = request.args.get('crypto_symbol', 'BTC').upper()
    prices = fetch_crypto_prices(selected_exchanges, crypto_symbol)
    return jsonify(prices)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
