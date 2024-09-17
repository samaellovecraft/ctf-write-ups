import os
from flask import Flask, Blueprint, request, render_template, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
import lzma

app = Flask(__name__) app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 # Limit file size to 5MB UPLOAD_FOLDER = 'uploads'

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'} # Add more allowed file extensions if needed

main_bp = Blueprint('main_bp', __name__, template_folder='./templates/')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@main_bp.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if not allowed_file(file.filename):
            flash('Invalid file extension. Allowed extensions: txt, pdf, docx', 'error')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            uploaded_file = os.path.join(app.root_path, UPLOAD_FOLDER, filename)
            file.save(uploaded_file)
            print(uploaded_file)
            flash('File successfully compressed!', 'success')
            with open(uploaded_file, 'rb') as f_in:
                with lzma.open(os.path.join(app.root_path, UPLOAD_FOLDER, f"{filename}.xz"), 'wb') as f_out:
                    f_out.write(f_in.read())
                    compressed_filename = f"{filename}.xz"
                    file_to_send = os.path.join(app.root_path, UPLOAD_FOLDER, compressed_filename)
                    response = send_file(file_to_send, as_attachment=True, download_name=f"{filename}.xz", mimetype="application/x-xz")
                    os.remove(uploaded_file)
                    os.remove(file_to_send)
            return response
        return redirect(url_for('main_bp.index'))
    return render_template('index/index.html')

