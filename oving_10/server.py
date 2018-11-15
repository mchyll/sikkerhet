import flask
from flask import request
from oving_10.auth import authenticate, get_session

app = flask.Flask(__name__)


@app.route('/authenticate', methods=['POST'])
def authenticate_endpoint():
    """
    Autentiserer et innloggingsforsøk.
    Brukernavn og (hashet) passord sendes som JSON.
    Dersom de er gyldig genereres en tilfeldig token som knyttes til brukeren,
    og sendes tilbake til klienten.
    """
    credentials = flask.request.get_json() or flask.request.form or flask.request.data

    token = authenticate(credentials['username'], credentials['password'])
    if token is None:
        return flask.jsonify(success=False), 403
    else:
        return flask.jsonify(success=True, token=token)


@app.route('/protected-resource')
def get_protected_resource():
    """
    Representerer en beskyttet ressurs.
    Krever en gyldig token i Authorization: Bearer-headeren.
    """
    auth_header = request.headers.get('Authorization')

    if not auth_header or auth_header[:7] != 'Bearer ':
        return 'Ikke logget inn', 403

    session = get_session(auth_header[7:])  # Fjern "Bearer " og hent ut token
    if not session:
        return 'Ikke logget inn', 403
    else:
        return 'Du er logget inn som {} og har tilgang!'.format(session)


@app.route('/')
@app.route('/<path:placeholder>')
def index(placeholder=''):
    """
    Catch-all endepunkt for å vise innloggingssiden.
    """
    return flask.render_template('login.html')


if __name__ == '__main__':
    app.run(host='::', port=8080, debug=True)
