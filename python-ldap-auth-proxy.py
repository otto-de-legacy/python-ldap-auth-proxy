from flask import Flask, request, Response
import ssl
import ldap3
import argparse
import logging
import json

app = Flask(__name__)


def establish_connection(bind_user, password):
    connection = ldap3.Connection(server, user=bind_user, password=password)
    connection.open()
    connection.start_tls()
    return connection


def ldap_connect(username, password=""):
    logging.info("Got request with " + str(username))
    bind_user = config["username_attr_type"] + "=" + username + "," + config["bind_dn_dir"]
    with establish_connection(bind_user, password) as ldap_connection:
        try:
            if ldap_connection.bind():
                return Response("{\"status\" : \"ok\"}", status=200)
            else:
                return Response("{\"status\" : \"" + ldap_connection.last_error + "\"}", status=401)
        except Exception as err:
            logging.ERROR(str(err))
            return Response("{\"status\" : \"" + ldap_connection.last_error + "\"}", status=500)


@app.route('/', methods=['POST'])
def auth():
    jsondata = request.get_json()
    if "bind_user" not in jsondata:
        logging.error("bind_user is missing in request")
        return Response("{\"error\" : \"Key 'bind_user' is required\"}", status=400)

    if not jsondata["bind_user"]:
        logging.error("bind_user is empty in request")
        return Response("{\"error\" : \"Key 'bind_user' must not be empty\"}", status=400)

    if "bind_pw" in jsondata and jsondata["bind_pw"]:
        response = ldap_connect(jsondata["bind_user"], jsondata["bind_pw"])
    else:
        response = ldap_connect(jsondata["bind_user"])
    logging.info("Returning response: " + str(response))
    return response


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This ldap-proxy provides start_tls connection to a ldap server.')
    parser.add_argument('port',
                        help='The port on which this proxy should run.')
    parser.add_argument('-v', '--verbose', nargs='?', const=logging.INFO, default=logging.ERROR,
                        help='Lets you set the loglevel. Application default: ERROR. Option default: INFO')
    parser.add_argument('-e', '--external', action='store_true',
                        help='Make the auth-proxy available externally')
    args = parser.parse_args()

    logging.basicConfig(level=args.verbose,
                        datefmt='%d-%m %H:%M:%S',
                        format='%(asctime)s %(name)-s %(levelname)-s %(message)s')
    logging.info("auth-proxy starts with " + str(args.port))

    with open('ldap-config.json', 'r') as f:
        config = json.load(f)

    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1, ca_certs_file=config['cert_file'])
    server = ldap3.Server(host=config["uri"], port=config['port'], tls=tls)

    if args.external:
        app.run(debug=True, port=int(args.port), host='0.0.0.0')
    else:
        app.run(debug=True, port=int(args.port))
