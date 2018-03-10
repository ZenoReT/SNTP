#!/usr/bin/env python3
import datetime
import sys
from sntpmessage import LeapIndicator, Mode, SNTPMessage
from socket import socket, AF_INET, SOCK_DGRAM


class Server:
    def __init__(self, hostname='localhost', port=123, deviation=0):
        self._hostname = hostname
        self._port = port
        self._deviation = datetime.timedelta(seconds=deviation)
        self._server = None
        self.buffer = 1024

    def start(self):
        self._server = socket(AF_INET, SOCK_DGRAM)
        self._server.bind((self._hostname, self._port))

        print('Deviation of server time: +- {0}'.format(self._deviation))
        print('Started server at {0}: {1}'.format(self._hostname, self._port))

        try:
            while True:
                message, address = self._server.recvfrom(self.buffer)
                self.treat_message(message, address)
        finally:
            print('The session was terminated!')
            self._server.close()
            self._server = None

    def treat_message(self, message, address):
        print('Received message from {0}\n'.format(address))
        try:
            receive_timestamp = datetime.datetime.utcnow() + self._deviation
            SNTPMessage.initilize_message_from_bytes(message, Mode.CLIENT)
            answer = self.get_server_answer(receive_timestamp, message[40:48])
            self._server.sendto(answer, address)
        except ValueError as e:
            sys.stderr.write("Something's gone wrong: {0}\n".format(e))
        else:
            print('Exchange was successful')

    def get_server_answer(self, receive_timestamp, origin_timestamp_bytes):
        current_time = datetime.datetime.utcnow() + self._deviation
        result = SNTPMessage(
            leap_indicator=LeapIndicator.NO_CORRECTION,
            version=4,
            mode=Mode.SERVER,
            stratum=1,
            poll=4,
            precision=-18,
            root_delay=0,
            root_dispersion=0,
            reference_id=b'\x00\x00\x00\x00',
            reference_timestamp=current_time,
            origin_timestamp=None,
            receive_timestamp=receive_timestamp,
            transmit_timestamp=current_time).get_bytes_from_message()
        result[24:32] = origin_timestamp_bytes
        return result
