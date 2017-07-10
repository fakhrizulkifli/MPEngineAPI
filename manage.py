#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask import Flask, request, url_for, redirect, jsonify, render_template
from subprocess import check_output, call, CalledProcessError, STDOUT
import hashlib
import os
import re

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join('/path/to/mpengineapi/', 'static')

mpengine_path = './loadlibrary/mpclient'
mpengine_pattern = 'Scanning (.*)...\n.*\n.*Threat (.*)\s'

@app.route('/')
def list():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('index.html', malwares=files)

def process(filepath):
    results = dict()
    cmd = [mpengine_path, filepath]

    try:
        output = check_output(cmd, stderr=STDOUT)
    except CalledProcessError as e:
        output = e.output

    matches = re.findall(mpengine_pattern, output, re.IGNORECASE|re.MULTILINE)
    for match in matches:
        results[match[0]] = match[1]

    return jsonify(results)

@app.route('/api/upload', methods=['POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        file.filename = hashlib.sha1(file.read()).hexdigest()
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
        output = process(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
        return output

if __name__ == "__main__":
    app.run()
