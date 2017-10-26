from flask import Flask, request, make_response
import json
import requests
pythonServiceHostName = "http://localhost:80";

app = Flask(__name__, static_folder='site', static_url_path='')

@app.route("/", methods=['GET'])
def handle():
    return app.send_static_file("index.html")

@app.route("/python", methods=['GET', 'POST'])
def handlePython():
    if request.method == 'POST':
        code = request.form['code']
        # This should return the stdout and stderr in json format
        # return the exact response fom pyService.py only!
        ### BEGIN STUDENT CODE ###
        r = requests.get('http://localhost:9078/predict',data=code)
        resp = make_response(json.dumps(r.text))
        print r.text
        resp.headers['Content-type'] = 'application/json'
        return resp
        ### END STUDENT CODE ###
    else:
        return app.send_static_file("python.html")

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
