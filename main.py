#!/usr/bin/env python3
import sys
from sntp_server import Server


def main(config_file):
    deviation = 0
    try:
        with open('config.txt', 'r') as config:
            deviation = int(config.readline())
    except IOError:
        sys.stderr.write('Not correct path or file is not supported {0}'
                         .format(config_file))
    try:
        server = Server(hostname='localhost', port=123, deviation=deviation)
        server.start()
    except Exception as e:
        sys.stderr.write("Something's gone wrong: {0}".format(e))
        return


if __name__ == '__main__':
    main('config.txt')
