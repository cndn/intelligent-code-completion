import os
import torch
import sys
sys.path.append('../token_lstm')
from flask import Flask, jsonify, request, make_response
from lstm_test import *
import json

app = Flask(__name__)

model = torch.load('../token_lstm/model.pt')

def get_args(req):
    if request.method == 'POST':
        args = request.json.data
    elif request.method == "GET":
        args = request.data
    return args

t = Test()
t.load(model_filename='../token_lstm/model.pt')
@app.route("/predict", methods=["GET", "POST", "OPTIONS"])

def predict():
    sentence = get_args(request)
    suggestions = t.predict_next(sentence)
    js = json.dumps({"stdout":sentence+str(suggestions[0])})
    resp = make_response(js)
    resp.headers['Content-type'] = 'application/json'
    return resp


def main(host="127.0.0.1", port=9078):
    app.run(host=host, port=port, debug=True)


if __name__ == "__main__":
    main()
