import os
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app import db
from app.models import Item, User
from app.forms import ReportItemForm
from . import main
from functools import wraps
from app.config import Config  # Import Config from the config.py file

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('You must be an admin to view this page.', 'danger')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Set the upload folder and allowed file extensions using Config
UPLOAD_FOLDER = Config.UPLOAD_FOLDER
ALLOWED_EXTENSIONS = Config.ALLOWED_EXTENSIONS

# Function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Index Route
@main.route('/')
def index():
    return render_template('index.html')

# User Dashboard Route
@main.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('main.admin_dashboard'))

    # Fetch items reported by the current user
    lost_items = Item.query.filter_by(user_id=current_user.id, status='Lost').all()
    found_items = Item.query.filter_by(user_id=current_user.id, status='Found').all()

    return render_template(
        'user_dashboard.html',
        lost_items=lost_items,
        found_items=found_items
    )

# Report Item Route (Updated to handle image upload)
@main.route('/report_item', methods=['GET', 'POST'])
@login_required
def report_item():
    form = ReportItemForm()
    if form.validate_on_submit():
        status = form.status.data.capitalize()  # Capitalize status for consistency
        image = None  # Default to no image

        # Check if a file is uploaded
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(UPLOAD_FOLDER, filename))
                image = filename  # Store the image filename

        # Create a new item object
        item = Item(
            name=form.name.data,
            description=form.description.data,
            location=form.location.data,
            status=status,
            image=image,  # Save the image filename
            user_id=current_user.id
        )

        # Save the item to the database
        db.session.add(item)
        db.session.commit()

        flash('Item reported successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('report_item.html', form=form)

# Admin Dashboard Route
@main.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    items = Item.query.all()
    return render_template('admin_dashboard.html', items=items)

# Manage Users Route
@main.route('/manage_users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

# Manage Items Route
@main.route('/manage_items')
@login_required
@admin_required
def manage_items():
    items = Item.query.all()  # Get all items
    return render_template('manage_items.html', items=items)

# View Items Route
@main.route('/view_items')
@login_required
@admin_required
def view_items():
    items = db.session.query(Item, User).join(User, Item.user_id == User.id).all()
    return render_template('view_items.html', items=items)

# Update Item Route
@main.route('/update_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def update_item(item_id):
    item = Item.query.get_or_404(item_id)
    if request.method == 'POST':
        item.status = 'Found'
        item.location = request.form.get('location')
        db.session.commit()
        flash(f'Item "{item.name}" marked as found!', 'success')
        return redirect(url_for('main.view_items'))

    return render_template('update_item.html', item=item)

# Mark as Found Route
@main.route('/mark_as_found/<int:item_id>', methods=['POST'])
@login_required
@admin_required
def mark_as_found(item_id):
    item = Item.query.get_or_404(item_id)
    if item.status == 'Lost':
        item.status = 'Found'
        db.session.commit()
        flash(f'Item "{item.name}" has been marked as Found!', 'success')
    else:
        flash(f'Item "{item.name}" is already marked as Found.', 'warning')

    return redirect(url_for('main.view_items'))

# Delete Item Route
@main.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
@admin_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash(f'Item "{item.name}" has been deleted.', 'success')
    return redirect(url_for('main.view_items'))








