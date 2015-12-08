from flask import Flask, request, Response
import ldap
import json
import sys

app = Flask(__name__)

with open('ldap-config.json', 'r') as f:
    config = json.load(f)

# Inspired by flask-multipass-master/util.py
def ldap_connect(bind_user, bind_pw=""):
    credentials = (config["username_attr_type"] + "=" + bind_user + "," + config["bind_dn_dir"], bind_pw)
    print("cred: " + str(credentials))
    ldap_connection = ldap.initialize(config["uri"], config["port"])
    ldap_connection.protocol_version = ldap.VERSION3

    if "cert_file" in config and config["cert_file"]:
        ldap_connection.set_option(ldap.OPT_X_TLS_CACERTFILE, config['cert_file'])

    # Don't resolve referrals
    ldap_connection.set_option(ldap.OPT_REFERRALS, 0)

    ldap_connection.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_NEVER)

    # Force cert validation: ldap.OPT_X_TLS_DEMAND
    if "verfiy_cert" in config and config["verify_cert"]:
        ldap_connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    else:
        ldap_connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

    # Create new TLS Context. Must be the last option
    ldap_connection.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    if config["use_starttls"]:
        try:
            ldap_connection.start_tls_s()
        except ldap.CONNECT_ERROR:
            return Response("{\"error\" : \"Connect error\"}", status=500)
    try:
        ldap_connection.simple_bind_s(*credentials)
    except ldap.INVALID_CREDENTIALS:
        return Response("{\"error\" : \"Invalid credentials\"}", status=401)
    except ldap.UNWILLING_TO_PERFORM:
        return Response("{\"error\" : \"The server is unwilling to perform this request\"}", status=400)
    return Response(None, status=200)


@app.route('/', methods=['POST'])
def auth():
    jsondata = request.get_json()
    if "bind_user" not in jsondata:
        return Response("{\"error\" : \"Key 'bind_user' is required\"}", status=400)

    if not jsondata["bind_user"]:
        return Response("{\"error\" : \"Key 'bind_user' must not be empty\"}", status=400)

    if "bind_pw" in jsondata and jsondata["bind_pw"]:
        return ldap_connect(jsondata["bind_user"], jsondata["bind_pw"])
    else:
        return ldap_connect(jsondata["bind_user"])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This ldap-proxy provides start_tls connection to a ldap server.')
    parser.add_argument('port',
                        help='The port on which this proxy should run.')
    parser.add_argument('-v', '--verbose', nargs='?', const=logging.INFO, default=logging.ERROR,
                        help='Lets you set the loglevel. Application default: ERROR. Option default: INFO')
    parser.add_argument('-e', '--external',
                        help='Make the auth-proxy available externally')
    args = parser.parse_args()

    logging.basicConfig(level=args.verbose,
                        datefmt='%d-%m %H:%M:%S',
                        format='%(asctime)s %(name)-s %(levelname)-s %(message)s')
    logging.info("auth-proxy starts with " + str(args.port))

    if args.external:
        app.run(debug=True, port=int(args.port), host='0.0.0.0')
    else:
        app.run(debug=True, port=int(args.port))
