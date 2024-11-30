from flask import Blueprint, render_template, url_for, redirect, flash
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, app, login_manager
from app.models import User
from app.forms import RegistrationForm, LoginForm

# Blueprints for authentication and main routes
auth = Blueprint('auth', __name__)
main = Blueprint('main', __name__)

# Admin dashboard route inside the main blueprint
@main.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:  # Assume `is_admin` is a field in your User model
        flash("Access restricted to admins only.")
        return redirect(url_for('main.user_dashboard'))  # Redirect to the user dashboard if not admin
    return render_template('admin_dashboard.html')

# User dashboard route inside the main blueprint
@main.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')

# Registration route inside the auth blueprint
@auth.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            username=form.username.data, 
            email=form.email.data, 
            password=hashed_password,
            is_admin=form.is_admin.data  # Set admin status
        )
        db.session.add(user)
        db.session.commit()
        flash("Account created!", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html", form=form)

# Login route inside the auth blueprint
@auth.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            # Redirect based on user role
            if user.is_admin:
                return redirect(url_for("main.admin_dashboard"))
            else:
                return redirect(url_for("main.user_dashboard"))
        else:
            flash("Login failed", "danger")
    return render_template("login.html", form=form)

# Logout route inside the auth blueprint
@auth.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))

# Register Blueprints
app.register_blueprint(auth, url_prefix='/auth')
app.register_blueprint(main, url_prefix='/')
