# common/protocol.py
import struct

MSG_TYPE_DATA = 0
MSG_TYPE_HEARTBEAT = 1
MSG_TYPE_AUTH = 2
MSG_TYPE_PROXY_CONNECT = 3
MSG_TYPE_AUTH_REQ = 4   # NEW: Client sends credentials
MSG_TYPE_AUTH_RESP = 5  # NEW: Server replies with SUCCESS or ERROR

FLAG_NONE = 0x00
FLAG_FRAGMENTED = 0x01
FLAG_LAST_FRAGMENT = 0x02

# Header Format:
# 1 byte: Type
# 2 bytes: Session ID (for multiplexing)
# 1 byte: Flags (for fragmentation)
# 2 bytes: Payload Length
HEADER_FORMAT = "!B H B H"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_PAYLOAD_SIZE = 1024

def pack_message(msg_type: int, session_id: int, flags: int, payload: bytes) -> bytes:
    header = struct.pack(HEADER_FORMAT, msg_type, session_id, flags, len(payload))
    return header + payload

def pack_data_messages(session_id: int, payload: bytes) -> list[bytes]:
    if len(payload) <= MAX_PAYLOAD_SIZE:
        return [pack_message(MSG_TYPE_DATA, session_id, FLAG_NONE, payload)]
    
    frames = []
    for i in range(0, len(payload), MAX_PAYLOAD_SIZE):
        chunk = payload[i:i+MAX_PAYLOAD_SIZE]
        flags = FLAG_FRAGMENTED
        if i + MAX_PAYLOAD_SIZE >= len(payload):
            flags |= FLAG_LAST_FRAGMENT
        frames.append(pack_message(MSG_TYPE_DATA, session_id, flags, chunk))
    return frames

def unpack_header(header_data: bytes):
    if len(header_data) < HEADER_SIZE:
        raise ValueError("Header data too short")
    return struct.unpack(HEADER_FORMAT, header_data)