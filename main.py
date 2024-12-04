from app import create_app
from flask import send_from_directory, render_template

# Create Flask app object
app = create_app()


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """
    It sends the specified file (filename) from a specific directory (uploads)
    to the client in response to an HTTP request.
    :param filename: String
    :return: String
    """
    return send_from_directory('uploads', filename)


@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
