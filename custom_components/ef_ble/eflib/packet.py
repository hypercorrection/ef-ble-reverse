import logging
import struct

from .crc import crc8, crc16

_LOGGER = logging.getLogger(__name__)


class Packet:
    """Needed to parse and make the internal packet structure"""

    PREFIX = b"\xaa"

    NET_BLE_COMMAND_CMD_CHECK_RET_TIME = 0x53
    NET_BLE_COMMAND_CMD_SET_RET_TIME = 0x52

    def __init__(
        self,
        src,
        dst,
        cmd_set,
        cmd_id,
        payload=b"",
        dsrc=1,
        ddst=1,
        version=3,
        seq=None,
        product_id=0,
    ):
        self._src = src
        self._dst = dst
        self._cmd_set = cmd_set
        self._cmd_id = cmd_id
        self._payload = payload
        self._dsrc = dsrc
        self._ddst = ddst
        self._version = version
        self._seq = seq if seq is not None else b"\x00\x00\x00\x00"
        self._product_id = product_id

        # For representation
        self._payload_hex = bytearray(self._payload).hex()

    @property
    def src(self):
        return self._src

    @property
    def dst(self):
        return self._dst

    @property
    def cmdSet(self):
        return self._cmd_set

    @property
    def cmdId(self):
        return self._cmd_id

    @property
    def payload(self):
        return self._payload

    @property
    def payloadHex(self):
        return self._payload_hex

    @property
    def dsrc(self):
        return self._dsrc

    @property
    def ddst(self):
        return self._ddst

    @property
    def version(self):
        return self._version

    @property
    def seq(self):
        return self._seq

    @property
    def productId(self):
        return self._product_id

    @staticmethod
    def fromBytes(data, is_xor=False):
        """Deserializes bytes stream into internal data"""
        # if len(data) < 20:
        #     _LOGGER.error(
        #         "Unable to parse packet - too small: %s", bytearray(data).hex()
        #     )
        #     return None

        if not data.startswith(Packet.PREFIX):
            _LOGGER.error(
                "Unable to parse packet - prefix is incorrect: %s",
                bytearray(data).hex(),
            )
            return None

        version = data[1]
        if (version == 2 and len(data) < 18) or (version == 3 and len(data) < 20):
            _LOGGER.error(
                "Unable to parse packet - too small: %s", bytearray(data).hex()
            )
            return None

        payload_length = struct.unpack("<H", data[2:4])[0]

        if version >= 2:
            # Check whole packet CRC16
            if crc16(data[:-2]) != struct.unpack("<H", data[-2:])[0]:
                _LOGGER.error(
                    "Unable to parse packet - incorrect CRC16: %s",
                    bytearray(data).hex(),
                )
                return None

        # Check header CRC8
        if crc8(data[:4]) != data[4]:
            _LOGGER.error(
                "Unable to parse packet - incorrect header CRC8: %s",
                bytearray(data).hex(),
            )
            return None

        # data[4] # crc8 of header
        # product_id = data[5] # We can't determine the product id from the bytestream

        # Seq is used for multiple purposes, so leaving as is
        seq = data[6:10]
        # data[10:12] # static zeroes?
        src = data[12]
        dst = data[13]

        if version == 2:
            dsrc = 0
            ddst = 0
            cmd_set = data[14]
            cmd_id = data[15]
        else:
            dsrc = data[14]
            ddst = data[15]
            cmd_set = data[16]
            cmd_id = data[17]

        payload = b""
        if payload_length > 0:
            if version == 2:
                payload = data[16 : 16 + payload_length]
            else:
                payload = data[18 : 18 + payload_length]
            # If first byte of seq is set - we need to xor payload with it to get the real data
            if is_xor is True and seq[0] != b"\x00":
                payload = bytes([c ^ seq[0] for c in payload])

            if version == 19 and payload[-2:] == b"\xbb\xbb":
                payload = payload[:-2]

        return Packet(src, dst, cmd_set, cmd_id, payload, dsrc, ddst, version, seq)

    def toBytes(self):
        """Will serialize the internal data to bytes stream"""
        # Header
        data = Packet.PREFIX
        data += struct.pack("<B", self._version) + struct.pack("<H", len(self._payload))
        # Header crc
        data += struct.pack("<B", crc8(data))
        # Additional data
        data += self.productByte() + self._seq
        data += b"\x00\x00"  # Unknown static zeroes, no strings attached right now

        data += struct.pack("<B", self._src) + struct.pack("<B", self._dst)

        # V3+ includes dsrc/ddst fields, V2 does not
        if self._version >= 0x03:
            data += struct.pack("<B", self._dsrc) + struct.pack("<B", self._ddst)

        data += struct.pack("<B", self._cmd_set) + struct.pack("<B", self._cmd_id)
        # Payload
        data += self._payload
        # Packet crc
        data += struct.pack("<H", crc16(data))

        return data

    def productByte(self):
        """Returns magics depends on product id"""
        if self._product_id >= 0:
            return b"\x0d"
        return b"\x0c"

    def __repr__(self):
        return "Packet(0x{_src:02X}, 0x{_dst:02X}, 0x{_cmd_set:02X}, 0x{_cmd_id:02X}, bytes.fromhex('{_payload_hex}'), 0x{_dsrc:02X}, 0x{_ddst:02X}, 0x{_version:02X}, {_seq}, 0x{_product_id:02X})".format(
            **vars(self)
        )
