from flask import Flask, render_template
from flask_bootstrap import Bootstrap
import numpy as np
from flask import Flask, request, jsonify, render_template
import pickle
import inputScript

app = Flask(__name__)

app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'

Bootstrap(app)

model = pickle.load(open('./Phishing_Website.pkl', 'rb'))


@app.route('/')
def home():
    return render_template('index.html')



@app.route('/predict', methods=["GET", "POST"])
def predict():
    if request.method == "POST":
        url = request.form.get('url')
        checkprediction = inputScript.main(url)
        prediction = model.predict(checkprediction)
        output = prediction
        if output == -1:
            pred = "You are safe!!! This is a legitimate website."
        else:
            pred = "You are wrong site, Be cautious!"
        return render_template('final.html', prediction_text='{}'.format(pred), url=url, method=request.method)

    return render_template('final.html', prediction_text="", url="", method=request.method)


if __name__ == "__main__":
    app.run(debug=True)