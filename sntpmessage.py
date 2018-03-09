#!/usr/bin/env python3
import datetime
from enum import IntEnum

# For causes, when fields "Digest of the message" or "Identification key"
# could(could not) be exist
SNTP_MESSAGE_LENGTHS = [48, 52, 64, 68]
# Allowable time deviations, else - time can't be synchronized
MIN_DATETIME = datetime.datetime(year=1968, month=1, day=1,
                                 hour=0, minute=0, second=0)
MAX_DATETIME = datetime.datetime(year=2036, month=2, day=7,
                                 hour=6, minute=28, second=16)
INITIAL_TIME = datetime.datetime(year=1900, month=1, day=1)


class LeapIndicator(IntEnum):
    NO_CORRECTION = 0
    SIXTY_ONE_SECONDS_IN_LAST_MINUTE = 1
    FIFTY_NINE_SECONDS_IN_LAST_MINUTE = 2
    NOT_SYNCHRONIZED = 3


class Mode(IntEnum):
    RESERVED = 0
    SYMMETRICAL_ACTIVE = 1
    SYMMETRICAL_PASSIVE = 2
    CLIENT = 3
    SERVER = 4
    BROADCAST = 5
    CONTROL_NTP_MESSAGE = 6
    PRIVATE_RESERVED = 7


class SNTPMessage:
    def __init__(
            self,
            leap_indicator=LeapIndicator.NO_CORRECTION,
            version=4,
            mode=Mode.PRIVATE_RESERVED,
            stratum=255,
            poll=6,
            precision=-18,
            root_delay=0.0,
            root_dispersion=0.0,
            reference_id=b'\x00\x00\x00\x00',
            reference_timestamp=None,
            origin_timestamp=None,
            receive_timestamp=None,
            transmit_timestamp=None):
        self.leap_indicator = leap_indicator
        self.version = version
        self.mode = mode
        self.stratum = stratum
        self.poll = poll
        self.precision = precision
        self.root_delay = root_delay
        self.root_dispersion = root_dispersion
        self.reference_id = reference_id
        self.reference_timestamp = reference_timestamp
        self.origin_timestamp = origin_timestamp
        self.receive_timestamp = receive_timestamp
        self.transmit_timestamp = transmit_timestamp

    @staticmethod
    def from_bytes(bytes_array, expected_modes):
        message_length = len(bytes_array)
        if message_length not in SNTP_MESSAGE_LENGTHS:
            raise ValueError(
                'Invalid message length: expected: {0}, actually {1}'
                .format(SNTP_MESSAGE_LENGTHS, message_length))
        leap_indicator = LeapIndicator((bytes_array[0] & 0b11000000) >> 6)
        version = (bytes_array[0] & 0b00100000) >> 3
        mode = Mode(bytes_array[0] & 0b00000111)
        if mode not in expected_modes:
            raise ValueError('Unexpected mode was found:'
                             ' expected: {0} actually: {1}'
                             .format(expected_modes, mode))
        stratum = bytes_array[1]
        poll = bytes_array[2]
        precision = bytes_array[3]
        if precision > 127:
            precision -= 256
        root_delay = SNTPMessage._from_signed_bytes_to_float(
            bytes_array[4:8], fraction_start=16, signed=True)
        root_dispersion = SNTPMessage._from_signed_bytes_to_float(
            bytes_array[8:12], 16, signed=False)
        reference_id = bytes_array[12:16]
        reference_timestamp = SNTPMessage._datetime_from_bytes(
            bytes_array[16:24])
        origin_timestamp = SNTPMessage._datetime_from_bytes(
            bytes_array[24:32])
        receive_timestamp = SNTPMessage._datetime_from_bytes(
            bytes_array[32:40])
        transmit_timestamp = SNTPMessage._datetime_from_bytes(
            bytes_array[40:48])
        return SNTPMessage(
            leap_indicator,
            version,
            mode,
            stratum,
            poll,
            precision,
            root_delay,
            root_dispersion,
            reference_id,
            reference_timestamp,
            origin_timestamp,
            receive_timestamp,
            transmit_timestamp)

    def to_bytes(self):
        message = bytearray(48)
        message[0] = (((self.leap_indicator & 0b11) << 6) |
                      ((self.version & 0b111) << 3) |
                      (self.mode & 0b111))
        message[1] = self.stratum & 0xff
        message[2] = self.poll & 0xff
        message[3] = self.precision.to_bytes(1, "big", signed=True)[0]
        message[4:8] = self._from_float_to_signed_bytes(
            self.root_delay, 4, 16, signed=True)
        message[8:12] = self._from_float_to_signed_bytes(
            self.root_dispersion, 4, 16, signed=False)
        message[12:16] = self.reference_id
        message[16:24] = self._datetime_to_bytes(self.reference_timestamp)
        message[24:32] = self._datetime_to_bytes(self.origin_timestamp)
        message[32:40] = self._datetime_to_bytes(self.receive_timestamp)
        message[40:48] = self._datetime_to_bytes(self.transmit_timestamp)
        return message

    @staticmethod
    def _from_signed_bytes_to_float(bytes_array, fraction_start=16, signed=False):
        bites_count = 8 * len(bytes_array)
        result = 0
        start_from = 1 if signed else 0
        for i in range(start_from, fraction_start):
            temp = 1 if (bytes_array[i // 8] & (1 << (7 - (i % 8)))) else 0
            result = result * 2 + temp

        fraction = 0.5
        for i in range(fraction_start, bites_count):
            if bytes_array[i // 8] & (1 << (7 - (i % 8))):
                result += fraction
            fraction /= 2

        if signed:
            result = -result
        return result

    @staticmethod
    def _from_float_to_signed_bytes(float_num, bytes_count=4, fraction_start=16, signed=False):
        if not signed and float_num < 0:
            raise ValueError('Not correct value for unsigned number: {0}'.format(float_num))
        bits_count = 8 * bytes_count
        if (
                fraction_start < 0 or
                fraction_start > bits_count or
                fraction_start == 0 and signed):
            raise ValueError(
                'Fractions start is out of range: '
                'bits count: {0} fraction start: {1}'
                    .format(bits_count, fraction_start))

        fraction_length = bits_count - fraction_start
        int_length = bits_count - fraction_length
        if signed:
            int_length -= 1

        float_int_part = abs(float_num) & (2 << (int_length - 1)) - 1

        shifted = float_int_part * (2 ** fraction_length)

        shifted = int(shifted)

        result = shifted.to_bytes(bytes_count, byteorder='big', signed=False)
        result = bytearray(result)

        if signed and float_num < 0:
            result[0] = result[0] | 0b10000000

        return bytes(result)

    @staticmethod
    def _datetime_from_bytes(bytes_array):
        seconds = int.from_bytes(bytes_array[0:4], byteorder="big", signed=False)
        sec_fractions = int.from_bytes(bytes_array[4:8], byteorder="big",
                                       signed=False) / (2 ** 32)
        milliseconds = int(sec_fractions * 1000)
        microseconds = (sec_fractions * 1000000) % 1000

        signed = bool(bytes_array[0] & 0b10000000)
        initial_time = INITIAL_TIME if signed else MAX_DATETIME

        return initial_time + datetime.timedelta(
            seconds=seconds,
            milliseconds=milliseconds,
            microseconds=microseconds)

    @staticmethod
    def _datetime_to_bytes(time):
        if time is None:
            return b"\x00" * 8

        if time < MIN_DATETIME:
            raise ValueError(
                "Cannot encode dates sooner than {0}".format(MIN_DATETIME))

        start_is_max_datetime = time >= MAX_DATETIME

        initial_time = MAX_DATETIME if start_is_max_datetime else INITIAL_TIME

        delta = time - initial_time
        delta_seconds = delta.total_seconds()

        seconds_int = int(delta_seconds)
        if start_is_max_datetime and seconds_int >= 0x80000000:
            raise ValueError("Cannot encode dates that late")

        seconds_fraction = int((delta_seconds - seconds_int) * (2 ** 32))

        return (seconds_int.to_bytes(4, byteorder='big', signed=False) +
                seconds_fraction.to_bytes(4, byteorder='big', signed=False))
