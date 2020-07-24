from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime as dt, timedelta as td
from utils import update_execution_log
import socket
import ssl
import os
import json

separator = ","  # separator for transmitted strings
app_header = "App"  # header for AppBackend's transmitted strings
health_authority_header = "HealthAuthority"  # header for HealthAuthority's transmitted strings
smartphone_header = "Smartphone"  # header for SmartPhone's transmitted strings
database_dt_format = "%Y-%m-%d %H:%M:%S.%f"  # database string format, json do not support datetime objects
ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:TLS_CHACHA20_POLY1305_SHA256"
key_filename = "key.pem"  # Backend's key
certificate_filename = "certificate.pem"  # Backend's certificate
ca_certificate_filename = "ca_certificate.pem"  # Backend's ca_certificate
database_filename = "database.json"  # Backend database
log_filename = "log.json"  # AuthorityBackend's logfile


class Backend:
    def __init__(self, root, app_port, authority_port):
        """
        constructor of basic Backend class, not used in practice
        serves as a solution for code redundancy
        :param root: root directory for backend data
        :param app_port: port number of AppBackend
        :param authority_port: port number of AuthorityBackend
        """
        path = os.path.join(os.curdir, root)
        os.mkdir(path) if not os.path.exists(path) else None
        self._app_port = app_port  # port number of AppBackend
        self._authority_port = authority_port  # port number of AuthorityBackend
        self._key_encryption = False  # optional certificate RSA key encryption with password
        self._key_path = os.path.join(path, key_filename)  # certificate RSA key path
        self._certificate_path = os.path.join(path, certificate_filename)  # X.509 certificate path
        self._ca_certificate_path = os.path.join(path, ca_certificate_filename)  # X.509 ca_certificate path
        self._database_path = os.path.join(path, database_filename)  # database path
        self._ciphers = ciphers  # suite of adopted ciphers

        if os.path.exists(self._database_path):
            with open(self._database_path, "r") as j:
                self._database = json.load(j)  # database load from json file
        else:
            self._database = dict()  # database initialization

        if not os.path.exists(self._key_path) or not os.path.exists(self._certificate_path):
            self._generate_self_signed_certificate(root, str(root + "_dns"))

    def _generate_rsa_key(self):
        """
        generates 2048bit RSA key with optional key encryption through password
        password is fixed and not used during test
        :return: 2048bit RSA key
        """
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        if self._key_encryption:
            encryption = serialization.BestAvailableEncryption(str.encode("password"))
        else:
            encryption = serialization.NoEncryption()

        with open(self._key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption))

        return key

    def _generate_self_signed_certificate(self, common_name, dns_name):
        """
        encodes a X.509 standard self-signed certificate into a PEM file
        certificate signed with SHA256
        :param common_name: common name of certificate owner
        :param dns_name: dns name of certificate owner
        :return: None
        """
        key = self._generate_rsa_key()
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SALERNO"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "FISCIANO"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UNISA"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

        certificate = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(key.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(dt.utcnow()) \
            .not_valid_after(dt.utcnow() + td(days=365)) \
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=False) \
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False) \
            .sign(key, hashes.SHA256(), default_backend())

        with open(self._certificate_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

    def get_cert_path(self):
        """
        used in the demo to exchange backends' certificates
        :return: backend's certificate path
        """
        return self._certificate_path

    def get_ca_certificate(self, ca_cert_path):
        """
        stores exchanged certificates
        demo purpose only
        :param ca_cert_path: backend certificate obtained with get_cert_path()
        :return: None
        """
        if not os.path.exists(self._ca_certificate_path):
            with open(ca_cert_path, "r") as r, open(self._ca_certificate_path, "w") as f:
                f.write(r.read())


class AppBackend(Backend):
    def _add_phone(self, id_phone, id_beacon, key):
        """
        adds a new phone to AppBackend's database
        stores the actual datetime
        database is stored on a json file in the root directory of AppBackend
        :param id_phone: skt of the phone
        :param id_beacon: identifies the associated beacon
        :param key: key for symmetric encryption
        :return: None
        """
        update_execution_log(["New Patient", id_phone, id_beacon, key])
        self._database[id_phone] = [id_beacon, key, dt.utcnow().strftime(database_dt_format)]
        with open(self._database_path, 'w') as j:
            json.dump(self._database, j, indent=0)

    def _get_key(self, id_phone):
        """
        retrieves key for symmetric encryption of id_phone
        alerts on invalid id_phone
        :param id_phone: skt of the phone sending the ciphertext to AppBackend
        :return: 44bit key
        """
        if id_phone in self._database:
            return self._database[id_phone][1]
        else:
            update_execution_log(["Invalid Phone", id_phone])

    def _decrypt_token(self, id_phone, ciphertext):
        """
        decrypts incoming tokens from SmartPhones
        if decryption succeeds, datetime of id_phone is updated
        alerts on invalid token, datetime not updated
        :param id_phone: skt of the token's phone
        :param ciphertext: ciphertext encrypted from beacon
        :return: None
        """
        update_execution_log(["New Token", id_phone, ciphertext])
        print("New Token from ID Phone: {0}, Ciphertext: {1}".format(id_phone, ciphertext))
        key = self._get_key(id_phone)
        if key is not None:
            try:
                new_datetime_string = Fernet(key).decrypt(str.encode(ciphertext)).decode()
                new_datetime = dt.strptime(new_datetime_string, database_dt_format)
                database_datetime = dt.strptime(self._database[id_phone][2], database_dt_format)
                if new_datetime > database_datetime:
                    self._database[id_phone][2] = new_datetime_string
                    with open(self._database_path, 'w') as j:
                        json.dump(self._database, j, indent=0)
            except InvalidToken:
                update_execution_log(["Invalid Token", id_phone, ciphertext])

    def _client_session(self, data):
        """
        client session of AppBackend
        used to communicate violations to AuthorityBackend
        key, certificate, ca_certificate required to establish connection
        :param data: string of app_header, id_beacon
        :return: None
        """
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("127.0.0.1", self._authority_port))
        secure_socket = ssl.wrap_socket(
            client_socket,
            keyfile=self._key_path,
            certfile=self._certificate_path,
            cert_reqs=ssl.CERT_REQUIRED,
            ssl_version=ssl.PROTOCOL_TLSv1_2,
            ca_certs=self._ca_certificate_path,
            ciphers=self._ciphers)

        secure_socket.write(str.encode(data))
        secure_socket.close()
        client_socket.close()

    def control_routine(self, td_expire):
        """
        control routine used to check violations
        if datetime expires, AppBackend sends an alert to AuthorityBackend
        :param td_expire: time tolerance from last datetime update
        :return: None
        """
        for id_phone in self._database:
            id_beacon = self._database[id_phone][0]
            expire_dt = dt.strptime(self._database[id_phone][2], database_dt_format) + td(seconds=td_expire)
            if dt.utcnow() > expire_dt:
                update_execution_log([app_header, id_beacon])
                self._client_session(separator.join([app_header, id_beacon]))

    def server_session(self):
        """
        server session of AppBackend
        used to retrieve messages from HealthAuthority and SmartPhones
        ca_certificate required to establish connection
        :return: None
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("127.0.0.1", self._app_port))
        server_socket.listen(0)

        while True:
            client_socket, address = server_socket.accept()
            secure_socket = ssl.wrap_socket(
                client_socket,
                keyfile=self._key_path,
                certfile=self._certificate_path,
                server_side=True,
                ssl_version=ssl.PROTOCOL_TLS_SERVER,
                ciphers=self._ciphers)

            data = secure_socket.read().decode().split(separator)
            if data[0] == health_authority_header:
                self._add_phone(data[1], data[2], data[3])
            if data[0] == smartphone_header:
                self._decrypt_token(data[1], data[2])
            secure_socket.close()


class AuthorityBackend(Backend):
    def __init__(self, root, app_port, authority_port):
        """
        overrides basic class constructor
        AuthorityBackend stores a log containing each violation alert and datetime
        :param root: root directory for AuthorityBackend data
        :param app_port: port number of AppBackend
        :param authority_port: port number of AuthorityBackend
        """
        super().__init__(root, app_port, authority_port)

        self._log_path = os.path.join(os.curdir, root, log_filename)  # path of violation's logfile

        if os.path.exists(self._log_path):
            with open(self._log_path, "r") as j:
                self._log = json.load(j)  # violation logfile load from json
        else:
            self._log = dict()  # violation logfile initialization

    def _add_datetime(self, id_beacon):
        """
        adds to log the datetime of id_beacon's violation
        :param id_beacon: identifies the beacon involved in the violation
        :return: None
        """
        update_execution_log(["Quarantine Violation", id_beacon, self._database[id_beacon]])
        print("Quarantine Violation from ID Beacon: {0}, Info: {1}".format(id_beacon, self._database[id_beacon]))
        if id_beacon in self._database:
            if id_beacon not in self._log:
                self._log[id_beacon] = [dt.utcnow().strftime(database_dt_format)]
            else:
                self._log[id_beacon].append(dt.utcnow().strftime(database_dt_format))
            with open(self._log_path, 'w') as j:
                json.dump(self._log, j, indent=0)
        else:
            update_execution_log(["Invalid Beacon", id_beacon])

    def add_beacon(self, id_beacon, info):
        """
        stores a new id_beacon with info into AuthorityBackend database
        :param id_beacon: identifies the new beacon added
        :param info: info regarding the new patient
        :return: None
        """
        update_execution_log(["New Beacon", id_beacon, info])
        self._database[id_beacon] = info
        with open(self._database_path, 'w') as j:
            json.dump(self._database, j, indent=0)

    def server_session(self):
        """
        server session of AuthorityBackend
        used to retrieve messages from AppBackend
        key, certificate, ca_certificate required to establish connection
        :return: None
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("127.0.0.1", self._authority_port))
        server_socket.listen(0)

        while True:
            client_socket, address = server_socket.accept()
            secure_socket = ssl.wrap_socket(
                client_socket,
                keyfile=self._key_path,
                certfile=self._certificate_path,
                server_side=True,
                cert_reqs=ssl.CERT_REQUIRED,
                ssl_version=ssl.PROTOCOL_TLS_SERVER,
                ca_certs=self._ca_certificate_path,
                ciphers=self._ciphers)

            data = secure_socket.read().decode().split(separator)
            if data[0] == app_header:
                self._add_datetime(data[1])
            secure_socket.close()
