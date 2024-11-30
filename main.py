from app import create_app
from flask import send_from_directory

app = create_app()


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    print(f"Requested file: {filename}")
    return send_from_directory('uploads', filename)


if __name__ == '__main__':
    app.run(debug=True)
