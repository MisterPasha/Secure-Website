from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from app import db
from werkzeug.utils import secure_filename
from app.models import Requests
import os
import bleach

user_bp = Blueprint('user', __name__)

# set of allowed tags
allowed_tags = {
    'b', 'i', 'u', 'em', 'strong', 'mark', 'small',  # Text formatting
    'p', 'div', 'span',                             # Structural
    'ul', 'ol', 'li',                               # Lists
    'a', 'abbr', 'code', 'pre', 'q'                # Inline elements
}

# set of allowed attributes
allowed_attrs = {
    'a': ['href', 'title', 'target'],               # Links
}
# Configure upload folder and allowed extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}


@user_bp.route('/request-evaluation', methods=['GET', 'POST'])
def request_evaluation():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        comment = request.form['comment']
        preferred_contact = request.form['preferred_contact']

        # Validate comment size
        if len(comment) > 4000:
            flash('Text is too large!', 'danger')
            return redirect(request.url)

        # Sanitise the comment
        sanitised_comment = bleach.clean(comment, tags=allowed_tags, attributes=allowed_attrs)

        # Handle file upload
        if 'photo' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['photo']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        elif file and allowed_file(file.filename):
            # The secure_filename function sanitises a filename to make it safe for use
            # it removes dangerous characters (e.g., ../ for path traversal).
            # also replaces invalid or unsafe characters with underscores.
            filename = secure_filename(file.filename)
            file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
            flash('File successfully uploaded.', 'success')
        else:
            flash('Allowed file types are png, jpg, jpeg', 'danger')
            return redirect(request.url)

        # Save the evaluation request into database
        new_request = Requests(
            id=session['user_id'],  # logged-in user's ID from the session
            comment=sanitised_comment,
            contact_method=preferred_contact,
            filename=filename
        )
        try:
            db.session.add(new_request)
            db.session.commit()
            flash('Evaluation request submitted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while saving your request. Please try again.', 'danger')
            print(f"Database error: {e}")
            return redirect(request.url)

        return redirect(url_for('user.request_evaluation'))

    return render_template('requestEvaluation.html')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
