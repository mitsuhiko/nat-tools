# -*- coding: utf-8 -*-
import os
import socket
import binascii
import struct

STUN_SERVER = 'stunserver.org'
STUN_PORT = 3478

FAMILY_IPv4 = '\x01'
FAMILY_IPv6 = '\x02'

# 0b00: Request
# 0b01: Binding
BINDING_REQUEST_SIGN = '\x00\x01' # 16bit (2bytes)

BINDING_RESPONSE_ERROR = '\x01\x11'
BINDING_RESPONSE_SUCCESS = '\x01\x01'
MAGIC_COOKIE = '\x21\x12\xA4\x42' # 32bit (4bytes)

# STUN Attribute Registry.
# From here: http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
# special note on XOR_MAPPED_ADDRESS_ALT and XOR_MAPPED_ADDRESS_ALT2:
# that's what I get back from some stun servers and it seems to match
# what other people do.
MAPPED_ADDRESS = '\x00\x01'
RESPONSE_ADDRESS = '\x00\x02'
CHANGE_REQUEST = '\x00\x03'
SOURCE_ADDRESS = '\x00\x04'
CHANGED_ADDRESS = '\x00\x05'
USERNAME = '\x00\x06'
PASSWORD = '\x00\x07'
MESSAGE_INTEGRITY = '\x00\x08'
ERROR_CODE = '\x00\x09'
UNKNOWN_ATTRIBUTES = '\x00\x0A'
REFLECTED_FROM = '\x00\x0B'
REALM = '\x00\x14'
NONCE = '\x00\x15'
XOR_MAPPED_ADDRESS_ALT = '\x00\x20'
XOR_MAPPED_ADDRESS = '\x80\x82'
XOR_MAPPED_ADDRESS_ALT2 = '\x80\x20'
SOFTWARE = '\x80\x22'

STUN_ATTRIBUTE_NAMES = {
    MAPPED_ADDRESS: 'MAPPED-ADDRESS',
    RESPONSE_ADDRESS: 'RESPONSE-ADDRESS',
    CHANGE_REQUEST: 'CHANGE-REQUEST',
    SOURCE_ADDRESS: 'SOURCE-ADDRESS',
    CHANGED_ADDRESS: 'CHANGED-ADDRESS',
    USERNAME: 'USERNAME',
    PASSWORD: 'PASSWORD',
    MESSAGE_INTEGRITY: 'MESSAGE-INTEGRITY',
    ERROR_CODE: 'ERROR-CODE',
    UNKNOWN_ATTRIBUTES: 'UNKNOWN-ATTRIBUTES',
    REFLECTED_FROM: 'REFLECTED-FROM',
    REALM: 'REALM',
    NONCE: 'NONCE',
    XOR_MAPPED_ADDRESS: 'XOR-MAPPED-ADDRESS',
    XOR_MAPPED_ADDRESS_ALT: 'XOR-MAPPED-ADDRESS',
    XOR_MAPPED_ADDRESS_ALT2: 'XOR-MAPPED-ADDRESS',
    SOFTWARE: 'SOFTWARE'
}

def build_binding_request(transaction_id):
    if len(transaction_id) != 12:
        raise RuntimeError('Invalid transaction id')
    body_length = '\x00\x00'
    return ''.join([BINDING_REQUEST_SIGN, body_length,
                    MAGIC_COOKIE, transaction_id])


def validate_response(buf, transaction_id):
    if not buf or len(buf) < 20:
        raise RuntimeError('Response too shoot')

    response_sign = buf[:2]
    if response_sign != BINDING_RESPONSE_SUCCESS:
        if response_sign == BINDING_RESPONSE_ERROR:
            raise RuntimeError('BINDING_RESPONSE_ERROR')
        raise RuntimeError('Invalid Response')

    response_magic_cookie = buf[4:8]
    if MAGIC_COOKIE != response_magic_cookie:
        raise RuntimeError('Invalid magic cookie')

    response_transaction_id = buf[8:20]
    if transaction_id != response_transaction_id:
        raise RuntimeError('invalid transaction id')


def ip_to_bytes(ip, xor):
    octets = [binascii.a2b_hex('%02x' % int(o)) for o in ip.split('.')]
    addr_int = struct.unpack('!I', ''.join(octets))[0]
    if xor:
        addr_int = int(binascii.b2a_hex(MAGIC_COOKIE), 16) ^ addr_int
    return binascii.a2b_hex('%08x' % addr_int)


def port_to_bytes(port, xor):
    if xor:
        port = int(binascii.b2a_hex(MAGIC_COOKIE[:2]), 16) ^ port

    port_bytes = binascii.a2b_hex('%04x' % port)
    return port_bytes


def read_mapped_address(attr_type, attr_body, attr_len):
    family_bytes = attr_body[1:2]
    port_bytes = attr_body[2:4]
    addr_bytes = attr_body[4:attr_len]

    if family_bytes == FAMILY_IPv4:
        family = socket.AF_INET
    elif family_bytes == FAMILY_IPv6:
        family = socket.AF_INET6
    else:
        family = -1

    # XXX: IPv6
    port = int(binascii.b2a_hex(port_bytes), 16)
    addr_int = int(binascii.b2a_hex(addr_bytes), 16)

    if is_xor_mapped(attr_type):
        port = int(binascii.b2a_hex(MAGIC_COOKIE[:2]), 16) ^ port
        addr_int = int(binascii.b2a_hex(MAGIC_COOKIE), 16) ^ addr_int

    octets = struct.pack('!I', addr_int)
    ip = '.'.join(str(ord(c)) for c in octets)
    return {
        'ip': ip,
        'port': port,
        'family': family
    }


def is_address_attribute(attr_type):
    return attr_type in (MAPPED_ADDRESS, SOURCE_ADDRESS, CHANGED_ADDRESS,
        XOR_MAPPED_ADDRESS, XOR_MAPPED_ADDRESS_ALT,
        XOR_MAPPED_ADDRESS_ALT2)


def is_xor_mapped(attr_type):
    return attr_type in (XOR_MAPPED_ADDRESS, XOR_MAPPED_ADDRESS_ALT,
                         XOR_MAPPED_ADDRESS_ALT2)


def read_attributes(attributes, body_length):
    pos = 0

    while pos < body_length:
        attr_type = attributes[pos:pos + 2]
        attr_len = int(binascii.b2a_hex(attributes[pos + 2:pos + 4]), 16)
        attr_body = attributes[pos + 4:pos + 4 + attr_len]

        response = {'name': STUN_ATTRIBUTE_NAMES.get(attr_type)}

        if is_address_attribute(attr_type):
            response.update(read_mapped_address(attr_type, attr_body, attr_len))
        elif attr_type == SOFTWARE:
            response['string'] = attr_body.rstrip('\x00')
        else:
            response.update({
                'attr_type': attr_type,
                'attr_body': attr_body,
                'attr_len': attr_len,
            })
        yield response

        remain = attr_len % 4
        padding = 4 - remain if remain else 0
        pos += 4 + attr_len + padding


class StunClient(object):
    """A simple stun client that yields responses."""

    def __init__(self, host='0.0.0.0', port=0, timeout=10):
        self.sock = None
        self.client_addr = (host, port)
        self.transaction_id = None
        self.timeout = timeout
        self.req = None

    def send_request(self, host=None, port=None):
        if host is None:
            host = STUN_SERVER
        if port is None:
            port = STUN_PORT
        self.transaction_id = os.urandom(12)
        self.req = build_binding_request(self.transaction_id)
        sock = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(self.client_addr)

            sock.sendto(self.req, (host, port))

            buf, addr = sock.recvfrom(2048)
            validate_response(buf, self.transaction_id)
            body_length = int(binascii.b2a_hex(buf[2:4]), 16)
            attributes = buf[20:]
            return read_attributes(attributes, body_length)
        finally:
            if sock is not None:
                sock.close()


def get_public_addr(host='0.0.0.0', port=0, stun_host=None,
                    stun_port=None, timeout=10,
                    family=None):
    """Returns the public IP address and port for a given IP
    address and port.  `host` can also be a socket.  This might
    return `None` if STUN fails.  If no port is provided a random
    port is picked.
    """
    if hasattr(host, 'getsockname'):
        host, port = host.getsockname()
        family = host.family
    if family is None:
        family = socket.AF_INET

    if family not in (socket.AF_INET, socket.AF_INET6):
        raise TypeError('Only IP sockets are supported')

    client = StunClient(host, port, timeout=timeout)
    for response in client.send_request(stun_host, stun_port):
        this_response_family = response.get('family')
        if this_response_family == family:
            return response['ip'], response['port']


def main():
    import json
    import optparse
    parser = optparse.OptionParser()
    parser.add_option('--host', type=str, help='Stun server host name',
                      default=STUN_SERVER)
    parser.add_option('--port', type=int, help='Stun server port',
                      default=STUN_PORT)
    parser.add_option('--client-host', help='Stun client host',
                      default='0.0.0.0')
    parser.add_option('--client-port', type=int, help='Stun client port',
                      default=0)

    opts, args = parser.parse_args()
    if args:
        parser.error('stun client does not accept arguments')

    client = StunClient(opts.client_host, opts.client_port)
    print json.dumps(list(client.send_request(opts.host, opts.port)), indent=2)


if __name__ == '__main__':
    main()
