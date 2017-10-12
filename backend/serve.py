import os
import torch
import sys
sys.path.append('../token_lstm')
from flask import Flask, jsonify, request
from generate import *

app = Flask(__name__)

model = torch.load('../token_lstm/model.pt')

def get_args(req):
    if request.method == 'POST':
        args = request.json
    elif request.method == "GET":
        args = request.args
    return args

model, corpus = load('../token_lstm/model.pt')
@app.route("/predict", methods=["GET", "POST", "OPTIONS"])

def predict():
    args = get_args(request)
    sentence = args.get("sentence", "from ")
    suggestions = test(model, corpus, sentence)
    print suggestions
    return jsonify({"data": {"results": suggestions}})


def main(host="127.0.0.1", port=9078):
    app.run(host=host, port=port, debug=True)


if __name__ == "__main__":
    main()
