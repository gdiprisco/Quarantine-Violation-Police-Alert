from datetime import datetime as dt
from numpy import random
from utils import update_execution_log
import socket
import ssl
import os
import json

separator = ","  # separator for transmitted strings
smartphone_header = "Smartphone"  # header for SmartPhone's transmitted strings
health_authority_header = "HealthAuthority"  # header for HealthAuthority's transmitted strings
database_dt_format = "%Y-%m-%d %H:%M:%S.%f"  # datetime string format, json do not support datetime objects
ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:TLS_CHACHA20_POLY1305_SHA256"
packets_directory = "beacon_packets"  # header.txt files root directory
smartphone_directory = "smartphone"  # SmartPhone root directory
ca_certificate_filename = "ca_certificate.pem"  # AppBackend certificate
smartphone_log_filename = "log.json"  # Smartphone offline logfile


class Client:
    def __init__(self, path, app_port):
        """
        constructor of basic Client class, not used in practice
        serves as a solution for code redundancy
        :param path: path for client data
        :param app_port: port number of AppBackend
        """
        self._app_port = app_port  # port number of AppBackend
        self._ca_certificate_path = os.path.join(path, ca_certificate_filename)  # path of AppBackend certificate
        self._ciphers = ciphers  # suite of adopted ciphers

    def _check_ca_certificate(self):
        """
        checks if the client has the certificate of AppBackend
        :return: None
        """
        if not os.path.exists(self._ca_certificate_path):
            with open(self._ca_certificate_path, "w") as f:
                f.write(ssl.get_server_certificate(("127.0.0.1", self._app_port), ssl_version=ssl.PROTOCOL_TLSv1_2))

    def _client_session(self, data):
        """
        client session of Client
        used to communicate new patients of encrypted tokens
        ca_certificate required to establish connection
        string of health_authority_header, id_phone, id_beacon, key for HealthAuthority
        string of smartphone_header, id_phone, ciphertext for Smartphone
        :param data: string type, changes according to client
        :return: None
        """
        self._check_ca_certificate()
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("127.0.0.1", self._app_port))
        secure_socket = ssl.wrap_socket(
            client_socket,
            cert_reqs=ssl.CERT_REQUIRED,
            ssl_version=ssl.PROTOCOL_TLSv1_2,
            ca_certs=self._ca_certificate_path,
            ciphers=self._ciphers)

        secure_socket.write(str.encode(data))
        secure_socket.close()
        client_socket.close()


class HealthAuthority(Client):
    def __init__(self, root, app_port):
        """
        overrides basic class constructor
        HealthAuthority communicates new patients to AppBackend
        :param root: root directory for HealthAuthority data
        :param app_port: port number of AppBackend
        """
        path = os.path.join(os.curdir, root)
        os.mkdir(path) if not os.path.exists(path) else None
        super().__init__(path, app_port)

    def routine(self, id_phone, id_beacon, key):
        """
        Health Authority starts a client session to communicate a new patient
        :param id_phone: skt of the new patient's phone
        :param id_beacon: identifies the beacon associated to the patient
        :param key: key for symmetric encryption
        :return: None
        """
        update_execution_log([health_authority_header, id_phone, id_beacon, key])
        self._client_session(separator.join([health_authority_header, id_phone, id_beacon, key]))


class SmartPhone(Client):
    def __init__(self, id_phone, header, app_port):
        """
        overrides basic class constructor
        SmartPhone receives encrypted tokens from SmartBeacon
        encrypted tokens are forwarded to AppBackend
        :param id_phone: skt of the phone
        :param header: bluetooth header of incoming packets
        :param app_port: port number of AppBackend
        """
        path = os.path.join(os.curdir, smartphone_directory)
        os.mkdir(path) if not os.path.exists(path) else None
        path = os.path.join(path, id_phone)
        os.mkdir(path) if not os.path.exists(path) else None
        super().__init__(path, app_port)

        self._on = True  # smartphone initialized always on
        self._bluetooth = True  # bluetooth initialized always on
        self._wifi = True  # wifi initialized always on
        self._id_phone = id_phone  # skt of the phone
        self._header = header  # header of bluetooth packets
        self._log_path = os.path.join(path, smartphone_log_filename)  # path of smartphone's offline logfile
        self._packets_root = os.path.join(os.curdir, packets_directory)  # packets' root directory

        if os.path.exists(self._log_path):
            with open(self._log_path, "r") as j:
                self._log = json.load(j)  # offline logfile load from json file
        else:
            self._log = dict()  # offline logfile initialization

    def get_on(self):
        """
        checks whether the phone is on or not
        :return: phone on/off status
        """
        return self._on

    def get_bluetooth(self):
        """
        checks whether the phone's bluetooth is on or not
        :return: phone's bluetooth on/off status
        """
        return self._bluetooth

    def get_wifi(self):
        """
        checks whether the phone's wifi is on or not
        :return: phone's wifi on/off status
        """
        return self._wifi

    def random_on(self, prob=0.5):
        """
        called when the phone is off
        :param prob: probability of phone turning on
        :return: None
        """
        update_execution_log(["Smartphone Off", self._id_phone])
        self._on = False if random.rand() < prob else True

    def random_bluetooth(self, prob=0.5):
        """
        called when the phone's bluetooth is off
        :param prob: probability of phone's bluetooth turning on
        :return:
        """
        update_execution_log(["Smartphone Bluetooth Off", self._id_phone])
        self._bluetooth = False if random.rand() < prob else True

    def routine(self, wifi=True, prob=0.5):
        """
        if wifi is on, forwards the last token received
        if wifi is off, stores all incoming tokens into a log file
        if wifi turns on, last stored token is sent to AppBackend
        :param wifi: routine changes according to phone's wifi on/off status
        :param prob: probability of phone's wifi turning on
        :return: None
        """
        last_ciphertext = None
        for packet in [packet for packet in os.listdir(self._packets_root) if packet.startswith(self._header)]:
            if os.path.getsize(os.path.join(self._packets_root, packet)) > 0:
                with open(os.path.join(self._packets_root, packet), "r") as f:
                    ciphertext = f.read()
                    if wifi:
                        update_execution_log([smartphone_header, self._id_phone, ciphertext])
                        self._client_session(separator.join([smartphone_header, self._id_phone, ciphertext]))
                    else:
                        last_ciphertext = ciphertext
                        with open(self._log_path, "w") as j:
                            self._log[dt.utcnow().strftime(database_dt_format)] = last_ciphertext
                            json.dump(self._log, j, indent=0)

        if not wifi:
            update_execution_log(["Smartphone WiFi Off", self._id_phone])
            self._wifi = False if random.rand() < prob else True
            if self._wifi and last_ciphertext is not None:
                update_execution_log([smartphone_header, self._id_phone, last_ciphertext])
                self._client_session(separator.join([smartphone_header, self._id_phone, last_ciphertext]))
