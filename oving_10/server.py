import flask


app = flask.Flask(__name__)


@app.route('/')
def index():
    return 'Hei verden'


if __name__ == '__main__':
    app.run(host='::', port=8080, debug=True)
