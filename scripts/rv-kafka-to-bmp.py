#!/usr/bin/env python3
"""
    Copyright (c) 2021-2022 Cisco Systems, Inc. and Others.  All rights reserved.

    Program to mirror RouteViews OpenBMP RAW topic(s) to a OpenBMP collector.

  .. moduleauthor:: Tim Evens <tim@evensweb.com>
"""
import click
import sys
import socket
import struct
import logging
import time

from pykafka import KafkaClient

logging.basicConfig(format='%(asctime)s | %(levelname)-8s | %(name)s[%(lineno)s] | %(message)s', level=logging.INFO)
LOG = logging.getLogger("mirror-RouteViews")

class BMPRawParse:
    """ Parse the BMP RAW binary header and extract the BMP data message

            0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                   Magic Number (0x4F424D50)                   |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Major Ver.  |   Minor Ver.  |         Header Length         |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                        Message Length                         |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |     Flags     |   Obj. Type   |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                   Coll. Timestamp (seconds)                   |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                 Coll. Timestamp (microseconds)                |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                   Collector Hash (16 bytes)                   |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |     Coll. Admin ID Length     |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                   Coll. Admin ID (variable)                   |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                    Router Hash (16 bytes)                     |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                     Router IP (16 bytes)                      |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |      Router Group Length      |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                    Router Group (variable)                    |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                           Row Count                           |
         +---------------------------------------------------------------+
    """
    def parse(self, data):
        """
        Get the BMP data from the OBMP binary header encoded BMP_RAW stream message


        :param data:        Raw Kafka message data from bmp_raw topic
        :return:            True if parsed, false if not
        """
        i = 4

        try:
            if (data[0] == 0x4f and data[1] == 0x42 and data[2] == 0x4d and data[3] == 0x50):
                self.collector_version_major = struct.unpack("B", data[i:i + 1])[0]
                i += 1

                self.collector_version_minor = struct.unpack("B", data[i:i + 1])[0]
                i += 1

                self.header_length = struct.unpack("!H", data[i: i+2])[0]
                i += 2

                self.message_length = struct.unpack("!I", data[i: i+4])[0]
                i += 4

                self.flags = struct.unpack("B", data[i:i + 1])[0]
                i += 1

                self.obj_type = struct.unpack("B", data[i:i + 1])[0]
                i += 1

                self.ts = struct.unpack("!I", data[i:i + 4])[0]
                i += 4

                self.ts_msec = struct.unpack("!I", data[i:i + 4])[0]
                i += 4

                self.collector_hash = data[i:i + 16]
                i += 16

                self.admin_len = struct.unpack("!H", data[i:i + 2])[0]
                i += 2

                self.admin_id = data[i:i + self.admin_len]
                i += self.admin_len

                self.router_hash = data[i:i + 16]
                i += 16

                self.router_ip = data[i:i + 16]
                i += 16

                self.router_group_len = struct.unpack("!H", data[i:i + 2])[0]
                i += 2

                self.router_group = data[i:i + self.router_group_len]
                i += self.router_group_len

                self.row_count = struct.unpack("!I", data[i:i + 4])[0]
                i += 4

                self.data = data[i:]
                return True
            else:
                return False
        except IndexError as e:
            return False

class BMPConnection:
    """ BMP connection class"""
    def __init__(self, log):
        """ Constructor

            :param log:             Existing logger to use
        """
        self.init_message = None
        self.term_message = None
        self.peer_up_messages = None

        self.LOG = log
        self._isConnected = False
        self._sock = None
        self.collector_host = None
        self.collector_port = 0
        self.router_name = None
        self.router_descr = None

    def createBmpCommonHeader(self, version, data_length, msg_type):

        """
        BMP Common Header:

          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+
         |    Version    |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                        Message Length                         |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Msg. Type   |
         +---------------+

        Message Types:
          *  Type = 0: Route Monitoring
          *  Type = 1: Statistics Report
          *  Type = 2: Peer Down Notification
          *  Type = 3: Peer Up Notification
          *  Type = 4: Initiation Message
          *  Type = 5: Termination Message
          *  Type = 6: Route Mirroring Message

        """

        return struct.pack("!B I B", version, data_length, msg_type)

    def getInitMessage(self):
        # Generate information TLVs about monitored router.
        """
         TLV Structure:

          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |          Information Type     |       Information Length      |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                 Information (variable)                        |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

         Type = 0: String
         Type = 1: sysDescr
         Type = 2: sysName

         sysDescr and sysName are must to sent.
        """

        router_descr = self.router_descr.encode('utf-8')
        router_name = self.router_name.encode('utf-8')

        # sysDescr tlv creation
        f1 = '!H H ' + str(len(router_descr)) + 's'
        s1 = struct.calcsize(f1)
        sysDescr_data = struct.pack(f1, 1, len(router_descr), router_descr)

        # sysName tlv creation
        f2 = '!H H ' + str(len(self.router_name)) + 's'
        s2 = struct.calcsize(f2)
        sysName_data = struct.pack(f2, 2, len(router_name), router_name)

        common_header = self.createBmpCommonHeader(3, s1 + s2 + 6, 4)

        init_msg = common_header + sysDescr_data + sysName_data

        return init_msg

    def getTerminationMessage(self):
        # Generate information TLVs about monitored router.
        """
         TLV Structure:

          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |          Information Type     |       Information Length      |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                 Information (variable)                        |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

         Type = 0: String
         Type = 1: reason

        """

        # Creation of Type 1 reason tlv
        information = struct.pack("!H", 0) # value is 2 byte reason code, 0 in this case.
        reason_tlv = struct.pack("!H H", 1, len(information)) + information

        common_header = self.createBmpCommonHeader(3, len(reason_tlv) + 6, 5)

        term_msg = common_header + reason_tlv

        return term_msg

    def connect(self, host=None, port=None, router_name=None, router_descr="OBMP RouteViews Mirror 1.0"):
        """ Connect to remote collector

            :param host:            FQDN for collector
            :param port:            PORT to connect to
            :param router_name:     Router name to advertise to collector
            :param router_descr:    Router sysDescr to advertise to collector
        :return: True if connected, False otherwise/error
        """
        try:
            if host:
                self.collector_host = host
                self.collector_port = port
                self.router_name = router_name
                self.router_descr = router_descr

            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.connect((self.collector_host, self.collector_port))
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self._isConnected = True
            self.LOG.info("Connected to remote collector: %s:%d", self.collector_host, self.collector_port)

            # Send INIT message.
            sent = False
            while not sent:
                sent = self.send(self.getInitMessage())

            LOG.info("sleeping for 5 seconds after initial connection")
            time.sleep(5)

        except socket.error as msg:
            self.LOG.error("Failed to connect to remote collector: %r", msg)
            self._isConnected = False

        except KeyboardInterrupt:
            pass

    def send(self, msg):
        """ Send BMP message to socket.

            :param msg:     Message to send/write

            :return: True if sent, False if not sent
        """
        sent = False

        try:
            self._sock.sendall(msg)
            sent = True

        except socket.error as msg:
            self.LOG.error("Failed to send message to collector: %r", msg)
            self.disconnect(send_term_msg=False)
            time.sleep(1)
            self.connect()

        finally:
            return sent

    def disconnect(self, send_term_msg=True):
        """ Disconnect from remote collector
        """

        # Send TERM message to the collector.
        if send_term_msg:
            self.send(self.getTerminationMessage())

        if self._sock:
            self._sock.close()
            self._sock = None
            self.LOG.info("Connection is disconnected to remote collector: %s:%d",
                          self.collector_host, self.collector_port)

            time.sleep(1)
        self._isConnected = False

    def isConnected(self):
        return self._isConnected


# Program args
@click.command(context_settings=dict(help_option_names=['-h', '--help'], max_content_width=200))
@click.option('-kh', '--kafka_host', 'kafka_host',
              help="RouteViews kafka hostname", metavar='<fqdn>', default="stream.routeviews.org")
@click.option('-kp', '--kafka_port', 'kafka_port',
              help="RouteViews kafka port", metavar='<port>', default="9092")
@click.option('-ch', '--collector_host', 'collector_host', required=True,
              help="BMP collector host", metavar='<fqdn>')
@click.option('-cp', '--collector_port', 'collector_port',
              help="BMP collector port", metavar='<port>', default="5000")
@click.option('--router_name', 'router_name', required=True,
              help="Router Name being monitored", metavar='<string>')
@click.option('--router_descr', 'router_descr',
              help="Router description", metavar='<string>')
@click.option('--debug', 'debug',
              help="Enable debug logging",
              is_flag=True, default=False)
def main(kafka_host, kafka_port, collector_host, collector_port, debug, router_name, router_descr):

    if debug:
        LOG.setLevel(logging.DEBUG)

    client = KafkaClient(hosts=kafka_host + ':' + str(kafka_port))

    router_fqdn = router_name + '.routeviews.org'

    conn = BMPConnection(LOG)
    conn.connect(collector_host, int(collector_port), router_name)

    for topic in client.topics:
        print(f"Topic: {topic}")

    consumer = client.topics['bmp.rv.routeviews.' + router_name].get_simple_consumer()
    msg = BMPRawParse()
    for message in consumer:
        if message is not None:
            #print (f"offset: {message.offset} value: {message.value}")
            if not msg.parse(message.value):
                print ("ERROR parsing message")
                print (f"offset: {message.offset} value: {message.value}")
                continue

            conn.send(msg.data)
            #print (f"version: {msg.collector_version_major}.{msg.collector_version_major}")
            #print (f"admin_id: {msg.admin_id} group: {msg.router_group} rows: {msg.row_count}")

    conn.disconnect()

if __name__ == '__main__':
    main()

