from backend import AppBackend, AuthorityBackend
from client import HealthAuthority, SmartPhone
from beacon import SmartBeacon
from cryptography.fernet import Fernet
from utils import init_execution_log
from numpy import random
import threading
import os

os.chdir(os.path.dirname(__file__))  # set current directory to main.py directory, all project data is here
app_port = 1234  # fixed port number of AppBackend
auth_port = 5678  # fixed port number of AuthorityBackend
app_root = "app"  # AppBackend root directory name
auth_root = "auth"  # AuthorityBackend root directory name
health_authority_root = "health"  # HealthAuthority root directory name
beacon_prob = 0.9  # probability of beacon being on
phone_prob = 0.9  # probability of phone being on
phone_bluetooth_prob = 0.9  # probability of phone's bluetooth being on
phone_wifi_prob = 0.9  # probability of phone's wifi being on
switch_status_prob = 0.5  # probability of status change from off to on
data_routine_timing = 3  # timer refresh for data routine, in seconds
control_routine_timing = 15  # timer refresh for control routine, in seconds
td_expire = 15  # time threshold for quarantine violation


class Demo:
    def __init__(self):
        """
        constructor of Demo
        Demo supports only one instance of (AppBackend, AuthorityBackend, HealthAuthority)
        multiple instances may be supported according to some changes in the code
        eventually, this demo is sufficient for the purpose of the project
        AppBackend and AuthorityBackend do not perform certificate requests
        certificates are acquired manually, with the assumption of being already provided
        an arbitrary number of beacons and smartphones may be used
        """
        self._beacon = list()  # list of registered beacon
        self._phone = list()  # list of registered phones
        self._app = AppBackend(app_root, app_port, auth_port)  # instance of AppBackend
        self._authority = AuthorityBackend(auth_root, app_port, auth_port)  # instance of AuthorityBackend
        self._health_authority = HealthAuthority(health_authority_root, app_port)  # instance of HealthAuthority

        self._app.get_ca_certificate(self._authority.get_cert_path())  # certificate acquisition
        self._authority.get_ca_certificate(self._app.get_cert_path())  # certificate acquisition

    def _health_authority_init(self, key, id_beacon, id_phone, header, info):
        """
        HealthAuthority communicates new patients to AppBackend
        AuthorityBackend stores manually a new id_beacon and info for each new patient
        this is an initialization, so it's just performed once
        eventually, it may be started as a thread with a timer, adding patients gradually
        alternatively, some patient may not be registered and see what happens
        :param key: list of new keys for symmetric encryption
        :param id_beacon: list of new beacons' identifiers
        :param id_phone: list of of new phones' skt
        :param header: list of bluetooth headers for each pair (Beacon, SmartPhone)
        :param info: list of each patient's info
        :return: None
        """
        for i in range(len(key)):
            self._beacon.append(SmartBeacon(id_beacon[i], header[i], key[i]))
            self._phone.append(SmartPhone(id_phone[i], header[i], app_port))
            self._health_authority.routine(id_phone[i], id_beacon[i], key[i])
            self._authority.add_beacon(id_beacon[i], info[i])

    def _beacon_routine(self):
        """
        each Beacon sends a new encrypted plaintext to his paired SmartPhone
        each Beacon's routine changes according to his on/off status
        eventually their status my change according to a fixed probability
        :return: None
        """
        for i in range(len(self._beacon)):
            if random.rand() < beacon_prob and self._beacon[i].get_on():
                self._beacon[i].routine(on=True)
            else:
                self._beacon[i].routine(on=False, prob=0.5)

    def _smartphone_routine(self):
        """
        each SmartPhone forwards a new token to AppBackend
        each SmartPhone routine changes according to his wifi's on/off status
        nothing is performed when the phone or the phone's bluetooth are off
        eventually their status my change according to a fixed probability
        :return: None
        """
        for i in range(len(self._phone)):
            if random.rand() < phone_prob and self._phone[i].get_on():
                if random.rand() < phone_bluetooth_prob and self._phone[i].get_bluetooth():
                    if random.rand() < phone_wifi_prob and self._phone[i].get_wifi():
                        self._phone[i].routine(wifi=True)
                    else:
                        self._phone[i].routine(wifi=False, prob=switch_status_prob)
                else:
                    self._phone[i].random_bluetooth(prob=switch_status_prob)
            else:
                self._phone[i].random_on(prob=switch_status_prob)

    def _data_routine(self):
        """
        performs routine of both Beacon and SmartPhone
        after a fixed period of time, the routine starts again
        :return: None
        """
        self._beacon_routine()
        self._smartphone_routine()
        threading.Timer(data_routine_timing, self._data_routine).start()

    def _control_routine(self):
        """
        performs the control routine of AppBackend
        after a fixed period of time, the routine starts again
        :return: None
        """
        self._app.control_routine(td_expire)
        threading.Timer(control_routine_timing, self._control_routine).start()

    def run(self, key, id_beacon, id_phone, header, info):
        """
        starts the server_session of both AppBackend and AuthorityBackend
        sessions are loop-performed with two different threads
        starts both _data_routine() and _control_routine() onto two different threads
        both data anc control routine auto-refresh automatically with a timer
        :param key: list of new keys for symmetric encryption
        :param id_beacon: list of new beacons' identifiers
        :param id_phone: list of of new phones' skt
        :param header: list of bluetooth headers for each pair (Beacon, SmartPhone)
        :param info: list of each patient's info
        :return: None
        """
        init_execution_log()

        threading.Thread(target=self._app.server_session).start()
        threading.Thread(target=self._authority.server_session).start()

        self._health_authority_init(key, id_beacon, id_phone, header, info)

        threading.Thread(target=self._data_routine).start()
        threading.Thread(target=self._control_routine).start()


"""
this demo is performed with just three patients
first two patient have the same key, beacon and info
eventually, we have two beacon instances, due to the different header
they have two different skt
third patient has his own key, beacon, skt, header and info
"""
demo = Demo()
key_01 = Fernet.generate_key().decode()
key_03 = Fernet.generate_key().decode()
key_list = [key_01, key_01, key_03]
beacon_list = ["beacon_01", "beacon_01", "beacon_02"]
phone_list = ["skt_01", "skt_02", "skt_03"]
header_list = ["header_01", "header_02", "header_03"]
info_list = ["info_beacon_01", "info_beacon_01", "info_beacon_02"]
demo.run(key_list, beacon_list, phone_list, header_list, info_list)
