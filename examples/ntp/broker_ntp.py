import argparse
import base64
import http.client
import json
import logging
import socket
import ssl
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NTP_HEADER_LEN = 48
NTP_EXTENSION_TYPE = 0xBEEF
MAX_NTP_PACKET = 65535
NTP_UNIX_EPOCH_OFFSET = 2_208_988_800  # seconds between 1900-01-01 and 1970-01-01

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# These are all set from CLI args in main()
CLI_HOST: Optional[str] = None      # outbound HTTP(S) host (from --host)
CLI_PORT: Optional[int] = None      # outbound HTTP(S) port (from --port)
LISTEN_HOST: Optional[str] = None   # local UDP listen host (from --listen-host)
LISTEN_PORT: Optional[int] = None   # local UDP listen port (from --listen-port)


# ---------------------------------------------------------------------------
# Core HTTP bridge logic (decode → parse → send HTTP → encode)
# ---------------------------------------------------------------------------

def decode_request(encoded_request: str) -> Dict[str, Any]:
    """
    Decode the base64-encoded JSON request into a Python dictionary.
    """
    logging.debug("Decoding incoming request (length: %d).", len(encoded_request))
    decoded_bytes = base64.b64decode(encoded_request)
    decoded_str = decoded_bytes.decode("utf-8")
    logging.debug("Decoded request JSON: %s", decoded_str)
    return json.loads(decoded_str)


def build_headers(header_lines: Optional[List[str]]) -> Dict[str, str]:
    """
    Build a headers dictionary from a list of 'Name: Value' strings.
    """
    headers: Dict[str, str] = {}
    if not header_lines:
        logging.debug("No headers provided in request.")
        return headers

    for line in header_lines:
        if not line:
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            name = name.strip()
            value = value.strip()
            headers[name] = value
            logging.debug("Parsed header: %s: %s", name, value)
        else:
            logging.warning("Skipping malformed header line (no colon found): %r", line)

    logging.info("Built %d request headers.", len(headers))
    return headers


def send_http_request(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send an HTTP/HTTPS request based on the decoded request dictionary.
    Uses CLI_HOST / CLI_PORT for the destination.
    """
    scheme = request.get("scheme", "http")
    host = CLI_HOST
    port = CLI_PORT
    path = request.get("path", "/")
    method = request.get("method", "GET")
    headers = build_headers(request.get("headers"))
    body_b64 = request.get("body", "")
    body = base64.b64decode(body_b64) if body_b64 else None

    if not host:
        raise ValueError("Destination host (--host) is required.")
    if port is None:
        raise ValueError("Destination port (--port) is required.")

    logging.info(
        "Preparing %s request to %s://%s:%s%s",
        method,
        scheme,
        host,
        port,
        path,
    )
    logging.debug("Request headers: %r", headers)
    if body is not None:
        logging.info("Request has a body (%d bytes).", len(body))

    connection_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection

    if scheme == "https":
        logging.debug("Creating HTTPS connection with unverified SSL context.")
        conn = connection_cls(host, port, context=ssl._create_unverified_context(), timeout=10)
    else:
        logging.debug("Creating HTTP connection.")
        conn = connection_cls(host, port, timeout=10)

    try:
        conn.request(method, path, body=body, headers=headers)
        logging.info("Request sent, awaiting response...")
        resp = conn.getresponse()
        resp_body = resp.read()
        logging.info(
            "Received response: %s %s (%d bytes).",
            resp.status,
            resp.reason,
            len(resp_body),
        )
        resp_headers_list = [f"{k}: {v}" for k, v in resp.getheaders()]
        logging.debug("Response headers: %r", resp_headers_list)
    finally:
        conn.close()
        logging.debug("Connection to %s:%s closed.", host, port)

    return {
        "status_code": resp.status,
        "status_text": resp.reason,
        "headers": resp_headers_list,
        "body": base64.b64encode(resp_body).decode("ascii"),
    }


def encode_response(response_obj: Dict[str, Any]) -> str:
    """
    Encode a response dictionary as base64-encoded JSON.
    """
    json_bytes = json.dumps(response_obj).encode("utf-8")
    logging.debug("Encoding response JSON (%d bytes) to base64.", len(json_bytes))
    return base64.b64encode(json_bytes).decode("ascii")


def process_encoded_request(encoded_request: str) -> str:
    """
    High-level core processing function.

    Takes raw encoded request data and returns raw encoded response data.

    Steps:
      1. Decode base64 → JSON → dict
      2. Perform HTTP/HTTPS request based on dict
      3. Encode response dict → JSON → base64
    """
    logging.info("Processing encoded request (length: %d).", len(encoded_request))
    request_obj = decode_request(encoded_request)
    logging.debug("Decoded request object: %r", request_obj)

    response_obj = send_http_request(request_obj)
    encoded_response = encode_response(response_obj)
    logging.info("Encoded response (length: %d).", len(encoded_response))

    return encoded_response


# ---------------------------------------------------------------------------
# NTP framing helpers
# ---------------------------------------------------------------------------

def _align_to_dword(length: int) -> int:
    return (length + 3) & ~3


def _pack_timestamp(ts: float) -> bytes:
    seconds = int(ts)
    fraction = int((ts - seconds) * (1 << 32))
    return seconds.to_bytes(4, "big") + fraction.to_bytes(4, "big")


def _now_ntp_timestamp() -> float:
    return time.time() + NTP_UNIX_EPOCH_OFFSET


def build_ntp_response(payload: bytes, version: int, originate_ts: Tuple[int, int]) -> bytes:
    extension_len = _align_to_dword(len(payload) + 4)
    response = bytearray(NTP_HEADER_LEN + extension_len)

    recv_time = _now_ntp_timestamp()
    recv_bytes = _pack_timestamp(recv_time)
    tx_bytes = _pack_timestamp(_now_ntp_timestamp())
    ref_bytes = recv_bytes

    leap_indicator = 0
    mode = 4  # server reply
    response[0] = (leap_indicator << 6) | ((version & 0x7) << 3) | mode
    response[1] = 1  # stratum
    response[2] = 6  # poll
    response[3] = 0xEC  # precision (-20)
    response[12:16] = b"GPS\x00"
    response[16:24] = ref_bytes
    response[24:32] = originate_ts[0].to_bytes(4, "big") + originate_ts[1].to_bytes(4, "big")
    response[32:40] = recv_bytes
    response[40:48] = tx_bytes

    start = NTP_HEADER_LEN
    response[start:start + 2] = NTP_EXTENSION_TYPE.to_bytes(2, "big")
    response[start + 2:start + 4] = extension_len.to_bytes(2, "big")
    response[start + 4:start + 4 + len(payload)] = payload

    return bytes(response)


def parse_ntp_request(packet: bytes) -> Optional[Dict[str, Any]]:
    if len(packet) < NTP_HEADER_LEN + 8:
        logging.warning("Received NTP packet too small to contain extension field (%d bytes).", len(packet))
        return None

    li_vn_mode = packet[0]
    mode = li_vn_mode & 0x7
    version = (li_vn_mode >> 3) & 0x7
    if mode != 3:
        logging.warning("Unexpected NTP mode: %d (expected client mode 3)", mode)
        return None

    ext_type = int.from_bytes(packet[NTP_HEADER_LEN:NTP_HEADER_LEN + 2], byteorder="big")
    ext_len = int.from_bytes(packet[NTP_HEADER_LEN + 2:NTP_HEADER_LEN + 4], byteorder="big")

    if ext_type != NTP_EXTENSION_TYPE:
        logging.warning("Unexpected NTP extension type: 0x%X", ext_type)
        return None

    if ext_len < 8 or (ext_len % 4) != 0:
        logging.warning("NTP extension length invalid: %d", ext_len)
        return None

    end_of_extension = NTP_HEADER_LEN + ext_len
    if len(packet) < end_of_extension:
        logging.warning(
            "Truncated NTP packet (expected %d bytes for extension, have %d).",
            ext_len,
            len(packet) - NTP_HEADER_LEN,
        )
        return None

    value = packet[NTP_HEADER_LEN + 4:end_of_extension]
    if len(value) < 4:
        logging.warning("NTP extension value too small to hold length prefix (%d bytes).", len(value))
        return None

    msg_len = int.from_bytes(value[:4], byteorder="big")
    if msg_len == 0 or msg_len > len(value) - 4:
        logging.warning(
            "Invalid message length in NTP payload: %d (available: %d)",
            msg_len,
            len(value) - 4,
        )
        return None

    transmit_seconds = int.from_bytes(packet[40:44], "big")
    transmit_fraction = int.from_bytes(packet[44:48], "big")

    try:
        return {
            "payload": value[4:4 + msg_len].decode("utf-8"),
            "version": version,
            "transmit_ts": (transmit_seconds, transmit_fraction),
        }
    except UnicodeDecodeError:
        logging.warning("Failed to decode NTP payload as UTF-8.")
        return None


# ---------------------------------------------------------------------------
# handle a callback
#
# This function is what you modify!
#
# ---------------------------------------------------------------------------

def handleCallback(process_func: Callable[[str], str] = process_encoded_request) -> bool:
    """
    Handle a single callback cycle over NTP (UDP).

    Listens on LISTEN_HOST:LISTEN_PORT for one NTP-like datagram carrying a
    length-prefixed payload inside an extension field, processes it, and
    responds using the same framing.
    """

    if LISTEN_HOST is None or LISTEN_PORT is None:
        raise RuntimeError("LISTEN_HOST and LISTEN_PORT must be set before calling handleCallback().")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind((LISTEN_HOST, LISTEN_PORT))
            server.settimeout(1.0)

            try:
                packet, addr = server.recvfrom(MAX_NTP_PACKET)
            except socket.timeout:
                return False

            logging.info("Received NTP packet from %s:%s (%d bytes).", addr[0], addr[1], len(packet))
            parsed = parse_ntp_request(packet)
            if parsed is None:
                return False

            encoded_response = process_func(parsed["payload"])
            response_payload = len(encoded_response).to_bytes(4, byteorder="big") + encoded_response.encode("utf-8")
            response_packet = build_ntp_response(
                response_payload,
                version=parsed["version"],
                originate_ts=parsed["transmit_ts"],
            )
            server.sendto(response_packet, addr)
            logging.info("Sent NTP response to %s:%s (%d bytes).", addr[0], addr[1], len(response_packet))

        return True

    except Exception as exc:  # noqa: BLE001
        logging.exception("Error in handleCallback: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Entry point. Repeatedly calls handleCallback to process requests.
    """
    global CLI_HOST, CLI_PORT, LISTEN_HOST, LISTEN_PORT

    parser = argparse.ArgumentParser(description="HTTP bridge broker.")
    parser.add_argument(
        "--host",
        dest="host",
        required=True,
        help="Destination host for outgoing HTTP/HTTPS requests (required).",
    )
    parser.add_argument(
        "--port",
        dest="port",
        type=int,
        required=True,
        help="Destination port for outgoing HTTP/HTTPS requests (required).",
    )
    parser.add_argument(
        "--listen-host",
        dest="listen_host",
        required=True,
        help="Host/interface to listen on for incoming UDP callbacks (e.g. 0.0.0.0).",
    )
    parser.add_argument(
        "--listen-port",
        dest="listen_port",
        type=int,
        required=True,
        help="Port to listen on for incoming UDP callbacks.",
    )

    args = parser.parse_args()

    CLI_HOST = args.host
    CLI_PORT = args.port
    LISTEN_HOST = args.listen_host
    LISTEN_PORT = args.listen_port

    logging.info("Destination (teamserver) host: %s", CLI_HOST)
    logging.info("Destination (teamserver) port: %s", CLI_PORT)
    logging.info("Listening on %s:%s for NTP callbacks.", LISTEN_HOST, LISTEN_PORT)

    while True:
        handled = handleCallback(process_encoded_request)


if __name__ == "__main__":
    main()
