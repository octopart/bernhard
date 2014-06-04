# -*- coding: utf-8 -

import random
import socket
import struct
import time

import pb

class TransportError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class TCPTransport(object):
    def __init__(self, host, port, timeout=None):
        self.sock = socket.create_connection((host, port), timeout)

    def close(self):
        self.sock.close()

    def write(self, message):
        try:
            # Tx length header and message
            self.sock.sendall(struct.pack('!I', len(message)) + message)

            # Rx length header
            rxlen = struct.unpack('!I', self.sock.recv(4))[0]
            # Rx entire response
            response = self.sock.recv(rxlen, socket.MSG_WAITALL)
            return response
        except (IOError, struct.error), e:
            raise TransportError(str(e))


class SSLTransport(TCPTransport):
    def __init__(self, host, port, keyfile=None, certfile=None, ca_certs=None):
        import ssl
        TCPTransport.__init__(self, host, port)

        self.sock = ssl.wrap_socket(self.sock,
                                    keyfile=keyfile,
                                    certfile=certfile,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ssl_version=ssl.PROTOCOL_TLSv1,
                                    ca_certs=ca_certs)


class UDPTransport(object):
    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def close(self):
        self.sock.close()

    def write(self, message):
        try:
            self.sock.sendto(message, (self.host, self.port))
        except socket.error, e:
            raise TransportError(str(e))


class Event(object):
    def __init__(self, event=None, params=None):
        if event:
            self.event = event
        elif params:
            self.event = pb.Event()
            for key, value in params.iteritems():
                setattr(self, key, value)
        else:
            self.event = pb.Event()

    def __getattr__(self, name):
        if name == 'metric':
            name = 'metric_f'
        if name in set(f.name for f in pb.Event.DESCRIPTOR.fields):
            return getattr(self.event, name)

    def __setattr__(self, name, value):
        if name == 'metric':
            name = 'metric_f'
        if name == 'tags':
            self.event.tags.extend(value)
        elif name == 'attributes':
            if type(value) == dict:
                for key in iter(value):
                    a = self.event.attributes.add()
                    a.key = key
                    if isinstance(value[key], basestring):
                        a.value = value[key]
                    else:
                        a.value = str(value[key])
            else:
                raise TypeError("'attributes' parameter must be type 'dict'")
        elif name in set(f.name for f in pb.Event.DESCRIPTOR.fields):
            object.__setattr__(self.event, name, value)
        else:
            object.__setattr__(self, name, value)


class Message(object):
    def __init__(self, message=None, events=None, raw=None, query=None):
        if raw:
            self.message = pb.Msg().FromString(raw)
        elif message:
            self.message = message
        elif events:
            self.message = pb.Msg()
            self.message.events.extend([e.event for e in events])
        elif query:
            self.message = pb.Msg()
            self.message.query.string = str(query)
        else:
            self.message = pb.Msg()

    def __getattr__(self, name):
        if name in set(f.name for f in pb.Msg.DESCRIPTOR.fields):
            return getattr(self.message, name)

    def __setattr__(self, name, value):
        if name in set(f.name for f in pb.Msg.DESCRIPTOR.fields):
            object.__setattr__(self.message, name, value)
        else:
            object.__setattr__(self, name, value)

    # Special-case the `events` field so we get boxed objects
    @property
    def events(self):
        return [Event(event=e) for e in self.message.events]

    @property
    def raw(self):
        return self.message.SerializeToString()


class Client(object):
    def __init__(self, host='127.0.0.1', port=5555, transport=TCPTransport, tcp_timeout=2):
        self.host = host
        self.port = port
        self.transport = transport
        self.tcp_timeout = tcp_timeout
        self.connection = None
        self.attempts = 0
        self.retry_after = None

    def connect(self):
        self.connection = self.transport(self.host, self.port, self.tcp_timeout)

    def disconnect(self):
        try:
            self.connection.close()
        except:
            pass
        self.connection = None

    def _failed(self):
        self.attempts += 1
        self.retry_after = time.time() + random.randint(0, 2 ** self.attempts)

    def _reset(self):
        self.attempts = 0
        self.retry_after = None

    def _throttled(self):
        return time.time() < self.retry_after

    def transmit(self, message):
        if self._throttled():
            return Message()

        if not self.connection:
            try:
                self.connect()
            except IOError:
                self._failed()
                return Message()
            else:
                self._reset()

        try:
            raw = self.connection.write(message.raw)
        except TransportError:
            self._failed()
            self.disconnect()
            return Message()
        else:
            self._reset()

        return Message(raw=raw)

    def send(self, event):
        message = Message(events=[Event(params=event)])
        response = self.transmit(message)
        return response.ok

    def query(self, q):
        message = Message(query=q)
        response = self.transmit(message)
        return response.events


class SSLClient(Client):
    def __init__(self, host='127.0.0.1', port=5554,
                 keyfile=None, certfile=None, ca_certs=None):
        Client.__init__(self, host=host, port=port, transport=SSLTransport)

        self.keyfile = keyfile
        self.certfile = certfile
        self.ca_certs = ca_certs

    def connect(self):
        self.connection = self.transport(self.host, self.port, self.keyfile,
                                         self.certfile, self.ca_certs)
