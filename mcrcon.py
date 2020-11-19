import socket
import struct
import collections

BUFSIZE = 4096
Packet = collections.namedtuple('Packet', ('ident', 'kind', 'payload'))

class IncompletePacket(Exception):
    def __init__(self, minimum):
        self.minimum = minimum

class McRcon:
    def __init__(self, host:str='localhost', port:int=25575):
        self._sock:socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((host, port))

    @staticmethod
    def _decode_packet(data) -> Packet:
        """
        Decodes a packet from the beginning of the given byte string. Returns a
        2-tuple, where the first element is a ``Packet`` instance and the second
        element is a byte string containing any remaining data after the packet.
        """
        if len(data) < 14:
            raise IncompletePacket(14)

        length = struct.unpack('<i', data[:4])[0] + 4
        if len(data) < length:
            raise IncompletePacket(length)

        ident, kind = struct.unpack('<ii', data[4:12])
        payload, padding = data[12:length-2], data[length-2:length]
        assert padding == b'\x00\x00'
        return Packet(ident, kind, payload)

    @staticmethod
    def _encode_packet(packet) -> bytes:
        """
        Encodes a packet from the given ``Packet` instance. Returns a byte string.
        """
        data = struct.pack('<ii', packet.ident, packet.kind) + packet.payload + b'\x00\x00'
        return struct.pack('<i', len(data)) + data

    def _receive_packet(self) -> Packet:
        """
        Receive a packet from the given socket. Returns a ``Packet`` instance.
        """
        data = b''
        while True:
            try:
                return McRcon._decode_packet(data)
            except IncompletePacket as e:
                while len(data) < e.minimum:
                    data += self._sock.recv(e.minimum - len(data))

    def _send_packet(self, packet):
        """
        Send a packet to the given socket.
        """
        self._sock.sendall(McRcon._encode_packet(packet))

    def login(self, password) -> bool:
        """
        Send a "login" packet to the server. Returns a boolean indicating whether
        the login was successful.
        """
        self._send_packet(Packet(0, 3, password.encode('utf8')))
        packet = self._receive_packet()
        return packet.ident == 0

    def command(self, text) -> str:
        """
        Sends a "command" packet to the server. Returns the response as a string.
        """
        self._send_packet(Packet(0, 2, text.encode('utf8')))
        self._send_packet(Packet(1, 0, b''))
        response = b''
        while True:
            packet = self._receive_packet()
            if packet.ident != 0:
                break
            response += packet.payload
        return response.decode('utf8')

    def close(self):
        self._sock.close()
