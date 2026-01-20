#!/usr/bin/env python3
"""
MOD-SOM logger + TCP forwarder

Threads:
1) SerialReaderThread: opens/closes serial port, reads bytes continuously -> byte_queue
2) ParserThread: runs EpsiStateMachineParser state machine on bytes, prints header/payload status,
   and for each GOOD record emits the *raw record bytes* (header+payload+payload_cksum) to good_queue
3) FileRotatorThread: consumes good records and writes to modsom_N.modraw, rotates at ~5MB
4) TCPBroadcasterThread: consumes good records and broadcasts to multiple TCP clients

Design goals:
- Write/forward the exact same bytes your parser can read later.
- Never lose "good" data: file rotation uses flush+fsync and closes only after write completes.
- TCP fanout: multiple listeners can connect (like `nc <host> <port>`).

Usage:
  python modsom_logger.py --serial /dev/tty.usbserial --baud 115200 --tcp-listen 9000 --out-prefix modsom --max-mb 5

Notes:
- TCP is byte stream; clients receive concatenated records.
- If no TCP clients are connected, data is simply dropped for TCP (still logged to file).
"""

import argparse
import queue
import socket
import select
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple, List

try:
    import serial  # type: ignore
except ImportError:
    serial = None


# ----------------------------
# Helpers
# ----------------------------
def parse_hostport(s: str) -> Tuple[str, int]:
    """
    Parse 'HOST:PORT' into (host, port).
    Accepts ':9000' meaning '0.0.0.0:9000'
    """
    s = s.strip()
    if s.startswith(":"):
        host = "0.0.0.0"
        port = int(s[1:])
        return host, port

    if ":" not in s:
        raise argparse.ArgumentTypeError("Expected HOST:PORT (e.g. 0.0.0.0:9000)")

    host, port_s = s.rsplit(":", 1)
    host = host.strip()
    port = int(port_s.strip())
    if not host:
        host = "0.0.0.0"
    return host, port


def xor_u8(data: bytes) -> int:
    c = 0
    for b in data:
        c ^= b
    return c & 0xFF


def _is_crlf_pair(buf: bytearray, idx: int) -> int:
    """
    If buf[idx:idx+2] is \r\n or \n\r, return 2 else 0.
    """
    if idx + 2 <= len(buf):
        pair = bytes(buf[idx:idx + 2])
        if pair in (b"\r\n", b"\n\r"):
            return 2
    return 0


# ----------------------------
# Data classes
# ----------------------------
@dataclass
class ParsedGoodRecord:
    """
    What we pass to writer/broadcaster: the exact bytes of the record,
    including the trailing CRLF separator if present (or synthesized).
    """
    raw_bytes: bytes
    inst_tag: str


# ----------------------------
# Reader threads
# ----------------------------
class SerialSourceThread(threading.Thread):
    """
    Reads from a serial port and pushes raw bytes to byte_queue.
    Sends som.start on start and som.stop on stop if provided.
    """
    def __init__(
        self,
        ser,
        out_queue: queue.Queue,
        stop_event: threading.Event,
        chunk_size: int = 4096,
        start_command: Optional[bytes] = b"som.start\r\n",
        stop_command: Optional[bytes] = b"som.stop\r\n",
    ):
        super().__init__(daemon=True)
        self.ser = ser
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.chunk_size = chunk_size
        self.start_command = start_command
        self.stop_command = stop_command

    def run(self):
        # send start
        if self.start_command:
            try:
                if hasattr(self.ser, "reset_input_buffer"):
                    self.ser.reset_input_buffer()
                self.ser.write(self.start_command)
                if hasattr(self.ser, "flush"):
                    self.ser.flush()
            except Exception as e:
                print(f"[SerialSource] Warning: could not send start command: {e}")

        try:
            while not self.stop_event.is_set():
                data = self.ser.read(self.chunk_size)
                if data:
                    self.out_queue.put(data)
                else:
                    time.sleep(0.01)
        except Exception as e:
            print(f"[SerialSource] Error: {e}")
        finally:
            # best-effort stop command
            if self.stop_command:
                try:
                    self.ser.write(self.stop_command)
                    if hasattr(self.ser, "flush"):
                        self.ser.flush()
                except Exception:
                    pass
            self.out_queue.put(None)


class TCPInputSourceThread(threading.Thread):
    """
    Listens on HOST:PORT, accepts a single client at a time,
    reads raw bytes and pushes into byte_queue.
    If client disconnects, it goes back to accept another.
    """
    def __init__(
        self,
        host: str,
        port: int,
        out_queue: queue.Queue,
        stop_event: threading.Event,
        chunk_size: int = 4096,
    ):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.chunk_size = chunk_size

        self._srv: Optional[socket.socket] = None

    def run(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(100)
            srv.settimeout(0.01) # it was .5 before
            self._srv = srv
            print(f"[TCPInput] Listening on {self.host}:{self.port}")

            while not self.stop_event.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                print(f"[TCPInput] Client connected from {addr}")
                conn.settimeout(0.01)

                try:
                    while not self.stop_event.is_set():
                        try:
                            data = conn.recv(self.chunk_size)
                        except socket.timeout:
                            continue
                        if not data:
                            break
                        self.out_queue.put(data)
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    print(f"[TCPInput] Client disconnected")

        except Exception as e:
            print(f"[TCPInput] Error: {e}")
        finally:
            try:
                if self._srv:
                    self._srv.close()
            except Exception:
                pass
            self.out_queue.put(None)


# ----------------------------
# MOD-SOM State Machine Parser
# ----------------------------
class EpsiStateMachineParser:
    """
    Parses stream of bytes into MOD-SOM records:

      $TAG tttttttttttttttt AAAAAAAA *CC <payload> *PP [\\r\\n optional]

    Where:
      - $TAG: 1 + 4 bytes ASCII
      - timestamp t: 16 ASCII hex (ms since 1970)
      - payload size A: 8 ASCII hex bytes
      - CC: 2 ASCII hex digits = XOR of bytes from '$' to last byte of payload size
      - payload: raw bytes length payload_size
      - PP: 2 ASCII hex digits = XOR of payload bytes
      - After PP there is often \\r\\n; we preserve it if present.
    """

    STATE_SYNC = 0
    STATE_TAG = 1
    STATE_HEADER = 2
    STATE_PAYLOAD = 3

    VALID_TAGS = {
        b"EFE4", b"TTV1", b"TTV2", b"TTV3",
        b"VNAV", b"SB49", b"SB41", b"ECOP", b"SOM3",
    }

    # '$'(1) + TAG(4) + ts(16) + size(8) + '*'(1) + CC(2)
    HEADER_LEN = 1 + 4 + 16 + 8 + 1 + 2

    def __init__(self, good_out_queue: queue.Queue):
        self.good_out_queue = good_out_queue
        self.buffer = bytearray()
        self.state = self.STATE_SYNC
        self.current_tag: Optional[bytes] = None
        self.current_ts_ms: Optional[int] = None
        self.current_payload_size: Optional[int] = None
        self.current_header_bytes: Optional[bytes] = None  # exact header bytes we validated

    def feed(self, data: bytes):
        self.buffer.extend(data)
        while True:
            if self.state == self.STATE_SYNC:
                if not self._phase_sync():
                    return
            elif self.state == self.STATE_TAG:
                if not self._phase_tag():
                    return
            elif self.state == self.STATE_HEADER:
                if not self._phase_header():
                    return
            elif self.state == self.STATE_PAYLOAD:
                if not self._phase_payload():
                    return
            else:
                self.state = self.STATE_SYNC

    def _phase_sync(self) -> bool:
        idx = self.buffer.find(b"$")
        if idx == -1:
            self.buffer.clear()
            return False
        if idx > 0:
            del self.buffer[:idx]
        if len(self.buffer) < 1 + 4:
            return False
        self.state = self.STATE_TAG
        return True

    def _phase_tag(self) -> bool:
        if len(self.buffer) < 1 + 4:
            return False

        if self.buffer[0] != ord("$"):
            del self.buffer[0]
            self.state = self.STATE_SYNC
            return True

        tag = bytes(self.buffer[1:5])
        if tag not in self.VALID_TAGS:
            # skip '$' and resync
            del self.buffer[0]
            self.state = self.STATE_SYNC
            return True

        self.current_tag = tag
        self.state = self.STATE_HEADER
        return True

    def _phase_header(self) -> bool:
        if len(self.buffer) < self.HEADER_LEN:
            return False

        header = bytes(self.buffer[:self.HEADER_LEN])

        if header[0] != ord("$"):
            del self.buffer[0]
            self.state = self.STATE_SYNC
            return True

        # '*' location: after '$TAG'(5) + ts(16) + size(8) => index 29
        if header[29] != ord("*"):
            print(f"[HEADER] malformed (no '*'): {header!r}")
            del self.buffer[0]
            self.state = self.STATE_SYNC
            return True

        tag = header[1:5]
        ts_hex = header[5:21].decode("ascii", errors="ignore")
        size_hex = header[21:29].decode("ascii", errors="ignore")
        cksum_hex = header[30:32].decode("ascii", errors="ignore")

        try:
            ts_ms = int(ts_hex, 16)
            payload_size = int(size_hex, 16)
            published = int(cksum_hex, 16)
        except ValueError:
            print(f"[HEADER] invalid hex fields: {header!r}")
            del self.buffer[0]
            self.state = self.STATE_SYNC
            return True

        computed = xor_u8(header[0:29])  # XOR from '$' through last size byte
        tag_str = tag.decode("ascii", errors="ignore")

        if computed == published:
            print(f"[HEADER] tag={tag_str} OK checksum header={header!r}")
            self.current_ts_ms = ts_ms
            self.current_payload_size = payload_size
            self.current_header_bytes = header
            del self.buffer[:self.HEADER_LEN]
            self.state = self.STATE_PAYLOAD
        else:
            print(
                f"[HEADER] tag={tag_str} BAD checksum "
                f"(computed=0x{computed:02X}, published=0x{published:02X}) header={header!r}"
            )
            del self.buffer[0]
            self.state = self.STATE_SYNC

        return True

    def _phase_payload(self) -> bool:
        if self.current_tag is None or self.current_payload_size is None or self.current_header_bytes is None:
            self._reset()
            self.state = self.STATE_SYNC
            return True

        # need: payload + '*' + 2 hex checksum
        needed = self.current_payload_size + 1 + 2
        if len(self.buffer) < needed:
            return False

        payload = bytes(self.buffer[:self.current_payload_size])
        star = self.buffer[self.current_payload_size]
        cksum_bytes = bytes(self.buffer[self.current_payload_size + 1:self.current_payload_size + 3])

        tag_str = self.current_tag.decode("ascii", errors="ignore")

        if star != ord("*"):
            print(f"[PAYLOAD] tag={tag_str} malformed (no '*') near: {bytes(self.buffer[:needed])!r}")
            # resync by skipping one byte
            del self.buffer[0]
            self._reset()
            self.state = self.STATE_SYNC
            return True

        try:
            published = int(cksum_bytes.decode("ascii", errors="ignore"), 16)
        except ValueError:
            print(f"[PAYLOAD] tag={tag_str} invalid checksum hex: {cksum_bytes!r}")
            del self.buffer[0]
            self._reset()
            self.state = self.STATE_SYNC
            return True

        computed = xor_u8(payload)

        # consume payload + *PP
        del self.buffer[:needed]

        # preserve CRLF if present immediately after
        delim_len = _is_crlf_pair(self.buffer, 0)
        delim = b""
        if delim_len:
            delim = bytes(self.buffer[:delim_len])
            del self.buffer[:delim_len]
        else:
            # if input didn't include it, still enforce record separation
            delim = b"\r\n"

        if computed == published:
            print(f"[PAYLOAD] tag={tag_str} OK record len={self.current_payload_size} checksum=0x{computed:02X}")

            raw = self.current_header_bytes + payload + b"*" + f"{published:02X}".encode("ascii") + delim
            self.good_out_queue.put(ParsedGoodRecord(raw_bytes=raw, inst_tag=tag_str))
        else:
            print(
                f"[PAYLOAD] tag={tag_str} BAD record checksum "
                f"(computed=0x{computed:02X}, published=0x{published:02X})"
            )

        self._reset()
        self.state = self.STATE_SYNC
        return True

    def _reset(self):
        self.current_tag = None
        self.current_ts_ms = None
        self.current_payload_size = None
        self.current_header_bytes = None


# ----------------------------
# Parser thread
# ----------------------------
class ParserThread(threading.Thread):
    """
    Consumes byte_queue, feeds state machine parser.
    """
    def __init__(self, byte_queue: queue.Queue, parser: EpsiStateMachineParser, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.byte_queue = byte_queue
        self.parser = parser
        self.stop_event = stop_event

    def run(self):
        while not self.stop_event.is_set():
            chunk = self.byte_queue.get()
            if chunk is None:
                break
            self.parser.feed(chunk)


# ----------------------------
# Rotating file writer thread
# ----------------------------
class RotatingFileWriterThread(threading.Thread):
    """
    Writes good records to modsom_N.modraw, rotating at max_bytes.
    """
    def __init__(self, good_queue: queue.Queue, stop_event: threading.Event,
                 prefix: str = "modsom", max_mb: float = 5.0):
        super().__init__(daemon=True)
        self.good_queue = good_queue
        self.stop_event = stop_event
        self.prefix = prefix
        self.max_bytes = int(max_mb * 1024 * 1024)
        self.idx = 0
        self.f = None
        self.written = 0

    def _open_new(self):
        if self.f:
            try:
                self.f.flush()
                self.f.close()
            except Exception:
                pass
        path = f"{self.prefix}_{self.idx}.modraw"
        self.f = open(path, "ab", buffering=0)
        self.written = 0
        print(f"[FILE] Opened {path}")

    def run(self):
        self._open_new()
        while not self.stop_event.is_set():
            item = self.good_queue.get()
            if item is None:
                break
            if not isinstance(item, ParsedGoodRecord):
                continue

            data = item.raw_bytes
            try:
                self.f.write(data)
                self.written += len(data)
            except Exception as e:
                print(f"[FILE] Write error: {e}")

            if self.written >= self.max_bytes:
                self.idx += 1
                self._open_new()

        # close
        try:
            if self.f:
                self.f.flush()
                self.f.close()
        except Exception:
            pass
        print("[FILE] Writer stopped")


# ----------------------------
# TCP broadcast output thread (multi-client)
# ----------------------------
class TCPBroadcastThread(threading.Thread):
    """
    Listens on host:port and broadcasts every good record to all connected clients.
    Multiple listeners supported.
    """
    def __init__(self, host: str, port: int, good_queue: queue.Queue, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.good_queue = good_queue
        self.stop_event = stop_event

        self.srv: Optional[socket.socket] = None
        self.clients: List[socket.socket_toggle] = []  # type: ignore
        self.lock = threading.Lock()

    def run(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(8)
            srv.setblocking(False)
            self.srv = srv
            print(f"[TCPOUT] Broadcasting on {self.host}:{self.port} (clients can connect)")

            while not self.stop_event.is_set():
                # Accept any new client
                try:
                    conn, addr = srv.accept()
                    conn.setblocking(False)
                    with self.lock:
                        self.clients.append(conn)
                    print(f"[TCPOUT] Client connected: {addr}")
                except BlockingIOError:
                    pass
                except Exception as e:
                    # server might be closing
                    if not self.stop_event.is_set():
                        print(f"[TCPOUT] Accept error: {e}")

                # Send pending record (non-blocking: pull with timeout)
                try:
                    item = self.good_queue.get(timeout=0.05)
                except queue.Empty:
                    continue

                if item is None:
                    break
                if not isinstance(item, ParsedGoodRecord):
                    continue

                data = item.raw_bytes
                dead = []

                with self.lock:
                    for i, c in enumerate(self.clients):
                        try:
                            c.sendall(data)
                        except Exception:
                            dead.append(i)

                    # remove dead in reverse
                    for i in reversed(dead):
                        try:
                            self.clients[i].close()
                        except Exception:
                            pass
                        del self.clients[i]

        except Exception as e:
            print(f"[TCPOUT] Error: {e}")
        finally:
            with self.lock:
                for c in self.clients:
                    try:
                        c.close()
                    except Exception:
                        pass
                self.clients.clear()
            try:
                if self.srv:
                    self.srv.close()
            except Exception:
                pass
            print("[TCPOUT] Broadcaster stopped")


# ----------------------------
# Main
# ----------------------------
def main():
    ap = argparse.ArgumentParser(
        description="MODSOM logger: Serial or TCP input → parse/validate → rotate files → optional TCP broadcast output"
    )

    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--serial", help="Serial port (e.g. /dev/tty.usbserial)")
    src.add_argument("--tcp-in", type=parse_hostport,
                     help="TCP input listen HOST:PORT (e.g. 0.0.0.0:9000 or :9000)")

    ap.add_argument("--baud", type=int, default=115200, help="Serial baudrate (serial mode)")
    ap.add_argument("--out-prefix", default="modsom", help="Output file prefix (default: modsom)")
    ap.add_argument("--max-mb", type=float, default=5.0, help="Rotate output file after N MB (default: 5)")
    ap.add_argument("--tcp-out", type=parse_hostport,
                    help="Optional TCP broadcast output HOST:PORT (e.g. 0.0.0.0:9100)")

    args = ap.parse_args()

    byte_queue: queue.Queue = queue.Queue()
    good_queue: queue.Queue = queue.Queue()

    stop_event = threading.Event()

    # Start writer thread
    file_writer = RotatingFileWriterThread(
        good_queue=good_queue,
        stop_event=stop_event,
        prefix=args.out_prefix,
        max_mb=args.max_mb,
    )
    file_writer.start()

    # Optional TCP broadcast thread
    tcp_broadcaster = None
    if args.tcp_out:
        out_host, out_port = args.tcp_out
        tcp_broadcaster = TCPBroadcastThread(out_host, out_port, good_queue, stop_event)
        tcp_broadcaster.start()

    # Parser
    parser = EpsiStateMachineParser(good_queue)
    parser_thread = ParserThread(byte_queue, parser, stop_event)
    parser_thread.start()

    # Source
    source_thread = None
    ser = None

    if args.serial:
        if serial is None:
            print("pyserial not installed. Install with: pip install pyserial")
            sys.exit(1)

        ser = serial.Serial(args.serial, args.baud, timeout=0.1)
        source_thread = SerialSourceThread(
            ser=ser,
            out_queue=byte_queue,
            stop_event=stop_event,
            start_command=b"som.start\r\n",
            stop_command=b"som.stop\r\n",
        )
        source_thread.start()
        print(f"[MAIN] Reading from serial {args.serial} @ {args.baud}")

    else:
        in_host, in_port = args.tcp_in
        source_thread = TCPInputSourceThread(
            host=in_host,
            port=in_port,
            out_queue=byte_queue,
            stop_event=stop_event,
        )
        source_thread.start()
        print(f"[MAIN] Waiting TCP input on {in_host}:{in_port}")

    # Run loop: Ctrl-C or 'q'
    print("[MAIN] Press Ctrl-C or type 'q' + Enter to stop.")
    try:
        while True:
            time.sleep(0.2)
            # non-blocking stdin check for 'q'
            if sys.stdin and sys.stdin.isatty():
                r, _, _ = select.select([sys.stdin], [], [], 0)
                if r:
                    line = sys.stdin.readline().strip().lower()
                    if line == "q":
                        break
    except KeyboardInterrupt:
        pass

    print("[MAIN] Stopping...")
    stop_event.set()

    # ensure serial gets som.stop (best effort)
    if ser is not None:
        try:
            if ser.is_open:
                ser.write(b"som.stop\r\n")
                ser.flush()
        except Exception:
            pass

    # unblock queues
    byte_queue.put(None)
    good_queue.put(None)

    # join threads
    try:
        if source_thread:
            source_thread.join(timeout=2.0)
    except Exception:
        pass

    try:
        parser_thread.join(timeout=2.0)
    except Exception:
        pass

    try:
        file_writer.join(timeout=2.0)
    except Exception:
        pass

    if tcp_broadcaster:
        try:
            tcp_broadcaster.join(timeout=2.0)
        except Exception:
            pass

    # close serial
    if ser is not None:
        try:
            ser.close()
        except Exception:
            pass

    print("[MAIN] Done.")


if __name__ == "__main__":
    main()

