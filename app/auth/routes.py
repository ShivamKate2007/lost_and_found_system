from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app import db
from app.forms import RegistrationForm, LoginForm
from . import auth  # Importing the blueprint

# Login Route
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))  # Redirect to user dashboard if already logged in

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')

            # Redirect based on user role
            if user.is_admin:
                return redirect(url_for('main.admin_dashboard'))
            else:
                return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html', form=form)

# Admin Login Route
@auth.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('main.admin_dashboard'))  # Redirect to admin dashboard if already logged in

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data) and user.is_admin:
            login_user(user)
            flash('Admin login successful!', 'success')
            return redirect(url_for('main.admin_dashboard'))
        else:
            flash('Invalid credentials or not an admin user.', 'danger')

    return render_template('admin_login.html', form=form)

# Register Route
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html', form=form)

# Logout Route
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


