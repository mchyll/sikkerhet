import flask


app = flask.Flask(__name__)


@app.route('/authenticate', methods=['POST'])
def authenticate():
    credentials = flask.request.get_json() or flask.request.form or flask.request.data
    print(type(credentials))
    return 'Logger inn med credentials {}\n'.format(credentials)


@app.route('/')
@app.route('/<path:placeholder>')
def index(placeholder=''):
    return flask.render_template('login.html')


if __name__ == '__main__':
    app.run(host='::', port=8080, debug=True)
