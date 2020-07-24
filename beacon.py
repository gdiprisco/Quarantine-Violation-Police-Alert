from cryptography.fernet import Fernet
from datetime import datetime as dt
from numpy import random
from utils import update_execution_log
import os

database_dt_format = "%Y-%m-%d %H:%M:%S.%f"  # datetime string format, json do not support datetime objects
packets_directory = "beacon_packets"  # header.txt files root directory


class SmartBeacon:
    def __init__(self, id_beacon, header, key):
        """
        constructor of Beacon
        Beacon encrypts plaintext for SmartPhone
        :param id_beacon: identifies the beacon for both AppBackend and AuthorityBackend
        :param header: header of bluetooth packets
        :param key: key for symmetric encryption
        """
        path = os.path.join(os.curdir, packets_directory)
        os.mkdir(path) if not os.path.exists(path) else None

        self._on = True  # beacon initialized always on
        self._id_beacon = id_beacon  # identifies the beacon, used for Debug purpose only
        self._header = header  # header of bluetooth packets
        self._key = key  # key for symmetric encryption
        self._packet = os.path.join(path, header + ".txt")  # path of beacon's packet

    def get_on(self):
        """
        checks whether the beacon is on or not
        :return: beacon on/off status
        """
        return self._on

    def routine(self, on=True, prob=0.5):
        """
        can't build up properly Bluetooth transmission
        transmissions are simulated through a header.txt file
        if beacon is on, encrypts a plaintext for the SmartPhone on the header.txt file
        if beacon is off, there's no encryption and the file is truncated
        :param on: routine changes according to beacon on/off status
        :param prob: probability of beacon turning on
        :return: None
        """
        if on:
            plaintext = str.encode(dt.utcnow().strftime(database_dt_format))
            ciphertext = Fernet(self._key).encrypt(plaintext).decode()
            update_execution_log(["New Encryption", self._id_beacon, self._header, ciphertext])
            with open(self._packet, "w") as f:
                f.write(ciphertext)
        else:
            update_execution_log(["Beacon Off", self._id_beacon, self._header])
            open(self._packet, "w").close()
            self._on = False if random.rand() < prob else True
