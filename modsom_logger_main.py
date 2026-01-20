#!/usr/bin/env python3
"""
MOD-SOM logger + TCP forwarder (FAST / RELIABLE)

Threads:
1) SerialSourceThread (optional): reads bytes from serial -> byte_queue
2) TCPInputSourceThread (optional): listens, accepts a single client at a time -> byte_queue
3) ParserThread: EpsiStateMachineParser consumes byte_queue, emits ParsedGoodRecord -> parse_queue
4) FanoutThread: duplicates each ParsedGoodRecord to:
   - file_queue (writer gets ALL records)
   - tcp_queue  (broadcaster gets ALL records)
5) RotatingFileWriterThread: consumes file_queue, writes modsom_N.modraw, rotates at ~max-mb
6) TCPBroadcastThread: consumes tcp_queue, broadcasts to multiple clients (blocking sockets + timeout)
7) StatsThread: prints 1 Hz health/rate stats (throttled output)

Implemented items:
(1) Fix queue bug via pub/sub fanout (no more split stream)
(2) Broadcaster uses BLOCKING sockets with timeout (robust sendall)
(3) TCP batching (coalesce multiple records into a single send)
(4) Print throttling (no per-record spam; 1 Hz stats; optional --debug parser prints)
(5) Socket options: TCP_NODELAY + optional SO_SNDBUF

Usage examples:
  python modsom_logger.py --serial /dev/tty.usbserial --baud 115200 --tcp-out :9100 --out-prefix modsom
  python modsom_logger.py --tcp-in :9000 --tcp-out :9100 --out-prefix modsom --max-mb 50

Notes:
- TCP is byte stream; clients receive concatenated records.
- If no TCP clients are connected, broadcaster drops nothing internally (it still drains tcp_queue);
  the data is always written to disk if file writer is running.
"""

import argparse
import queue
import socket
import select
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
    """If buf[idx:idx+2] is \\r\\n or \\n\\r, return 2 else 0."""
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
    What we pass to writer/broadcaster: exact bytes of the record
    including the trailing CRLF separator if present (or synthesized).
    """
    raw_bytes: bytes
    inst_tag: str


# ----------------------------
# Shared stats
# ----------------------------
class Counters:
    def __init__(self):
        self.lock = threading.Lock()
        # parser
        self.bytes_in = 0
        self.good_records = 0
        self.bad_header = 0
        self.bad_payload = 0
        self.resync = 0
        # file
        self.file_bytes = 0
        self.file_records = 0
        # tcp out
        self.tcp_batches = 0
        self.tcp_bytes = 0
        self.tcp_records = 0
        self.tcp_clients = 0
        self.tcp_drop_clients = 0

    def add(self, **kwargs):
        with self.lock:
            for k, v in kwargs.items():
                setattr(self, k, getattr(self, k) + v)

    def set(self, **kwargs):
        with self.lock:
            for k, v in kwargs.items():
                setattr(self, k, v)

    def snapshot(self):
        with self.lock:
            return {
                "bytes_in": self.bytes_in,
                "good_records": self.good_records,
                "bad_header": self.bad_header,
                "bad_payload": self.bad_payload,
                "resync": self.resync,
                "file_bytes": self.file_bytes,
                "file_records": self.file_records,
                "tcp_batches": self.tcp_batches,
                "tcp_bytes": self.tcp_bytes,
                "tcp_records": self.tcp_records,
                "tcp_clients": self.tcp_clients,
                "tcp_drop_clients": self.tcp_drop_clients,
            }


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
        counters: Counters,
        chunk_size: int = 4096,
        start_command: Optional[bytes] = b"som.start\r\n",
        stop_command: Optional[bytes] = b"som.stop\r\n",
    ):
        super().__init__(daemon=True)
        self.ser = ser
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.counters = counters
        self.chunk_size = chunk_size
        self.start_command = start_command
        self.stop_command = stop_command

    def run(self):
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
                    self.counters.add(bytes_in=len(data))
                    self.out_queue.put(data)
                else:
                    time.sleep(0.005)
        except Exception as e:
            print(f"[SerialSource] Error: {e}")
        finally:
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
        counters: Counters,
        chunk_size: int = 65536,
    ):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.counters = counters
        self.chunk_size = chunk_size
        self._srv: Optional[socket.socket] = None

    def run(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(64)
            srv.settimeout(0.05)
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

                try:
                    # Keep reads responsive, but allow big chunks
                    conn.settimeout(0.05)
                    try:
                        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except Exception:
                        pass

                    while not self.stop_event.is_set():
                        try:
                            data = conn.recv(self.chunk_size)
                        except socket.timeout:
                            continue
                        if not data:
                            break
                        self.counters.add(bytes_in=len(data))
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

    def __init__(self, good_out_queue: queue.Queue, counters: Counters, debug: bool = False):
        self.good_out_queue = good_out_queue
        self.counters = counters
        self.debug = debug

        self.buffer = bytearray()
        self.state = self.STATE_SYNC
        self.current_tag: Optional[bytes] = None
        self.current_payload_size: Optional[int] = None
        self.current_header_bytes: Optional[bytes] = None

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
            self.counters.add(resync=1)
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
            self.counters.add(resync=1)
            return True

        tag = bytes(self.buffer[1:5])
        if tag not in self.VALID_TAGS:
            # skip '$' and resync
            del self.buffer[0]
            self.state = self.STATE_SYNC
            self.counters.add(resync=1)
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
            self.counters.add(resync=1)
            return True

        # '*' location after '$TAG'(5) + ts(16) + size(8) => index 29
        if header[29] != ord("*"):
            self.counters.add(bad_header=1)
            if self.debug:
                print(f"[HEADER] malformed (no '*'): {header!r}")
            del self.buffer[0]
            self.state = self.STATE_SYNC
            self.counters.add(resync=1)
            return True

        ts_hex = header[5:21].decode("ascii", errors="ignore")
        size_hex = header[21:29].decode("ascii", errors="ignore")
        cksum_hex = header[30:32].decode("ascii", errors="ignore")

        try:
            _ts_ms = int(ts_hex, 16)  # parsed to validate, but unused for forwarding
            payload_size = int(size_hex, 16)
            published = int(cksum_hex, 16)
        except ValueError:
            self.counters.add(bad_header=1)
            if self.debug:
                print(f"[HEADER] invalid hex fields: {header!r}")
            del self.buffer[0]
            self.state = self.STATE_SYNC
            self.counters.add(resync=1)
            return True

        computed = xor_u8(header[0:29])  # XOR from '$' through last size byte
        if computed == published:
            self.current_payload_size = payload_size
            self.current_header_bytes = header
            del self.buffer[:self.HEADER_LEN]
            self.state = self.STATE_PAYLOAD
        else:
            self.counters.add(bad_header=1)
            if self.debug:
                tag_str = header[1:5].decode("ascii", errors="ignore")
                print(
                    f"[HEADER] tag={tag_str} BAD checksum "
                    f"(computed=0x{computed:02X}, published=0x{published:02X}) header={header!r}"
                )
            del self.buffer[0]
            self.state = self.STATE_SYNC
            self.counters.add(resync=1)

        return True

    def _phase_payload(self) -> bool:
        if self.current_tag is None or self.current_payload_size is None or self.current_header_bytes is None:
            self._reset()
            self.state = self.STATE_SYNC
            self.counters.add(resync=1)
            return True

        needed = self.current_payload_size + 1 + 2  # payload + '*' + 2 hex checksum
        if len(self.buffer) < needed:
            return False

        payload = bytes(self.buffer[:self.current_payload_size])
        star = self.buffer[self.current_payload_size]
        cksum_bytes = bytes(self.buffer[self.current_payload_size + 1:self.current_payload_size + 3])

        if star != ord("*"):
            self.counters.add(bad_payload=1)
            if self.debug:
                tag_str = self.current_tag.decode("ascii", errors="ignore")
                print(f"[PAYLOAD] tag={tag_str} malformed (no '*') near: {bytes(self.buffer[:needed])!r}")
            del self.buffer[0]
            self._reset()
            self.state = self.STATE_SYNC
            self.counters.add(resync=1)
            return True

        try:
            published = int(cksum_bytes.decode("ascii", errors="ignore"), 16)
        except ValueError:
            self.counters.add(bad_payload=1)
            if self.debug:
                tag_str = self.current_tag.decode("ascii", errors="ignore")
                print(f"[PAYLOAD] tag={tag_str} invalid checksum hex: {cksum_bytes!r}")
            del self.buffer[0]
            self._reset()
            self.state = self.STATE_SYNC
            self.counters.add(resync=1)
            return True

        computed = xor_u8(payload)

        # consume payload + *PP
        del self.buffer[:needed]

        # preserve CRLF if present immediately after
        delim_len = _is_crlf_pair(self.buffer, 0)
        if delim_len:
            delim = bytes(self.buffer[:delim_len])
            del self.buffer[:delim_len]
        else:
            delim = b"\r\n"

        if computed == published:
            tag_str = self.current_tag.decode("ascii", errors="ignore")
            raw = self.current_header_bytes + payload + b"*" + f"{published:02X}".encode("ascii") + delim
            self.good_out_queue.put(ParsedGoodRecord(raw_bytes=raw, inst_tag=tag_str))
            self.counters.add(good_records=1)
        else:
            self.counters.add(bad_payload=1)
            if self.debug:
                tag_str = self.current_tag.decode("ascii", errors="ignore")
                print(
                    f"[PAYLOAD] tag={tag_str} BAD record checksum "
                    f"(computed=0x{computed:02X}, published=0x{published:02X})"
                )

        self._reset()
        self.state = self.STATE_SYNC
        return True

    def _reset(self):
        self.current_tag = None
        self.current_payload_size = None
        self.current_header_bytes = None


# ----------------------------
# Parser thread
# ----------------------------
class ParserThread(threading.Thread):
    """Consumes byte_queue, feeds state machine parser."""
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
# Fanout thread (pub/sub)
# ----------------------------
class FanoutThread(threading.Thread):
    """
    Duplicates each item from in_queue to all out_queues (pub/sub).
    """
    def __init__(self, in_queue: queue.Queue, out_queues: List[queue.Queue], stop_event: threading.Event):
        super().__init__(daemon=True)
        self.in_queue = in_queue
        self.out_queues = out_queues
        self.stop_event = stop_event

    def run(self):
        while not self.stop_event.is_set():
            item = self.in_queue.get()
            if item is None:
                for q in self.out_queues:
                    q.put(None)
                break
            for q in self.out_queues:
                q.put(item)


# ----------------------------
# Rotating file writer thread
# ----------------------------
class RotatingFileWriterThread(threading.Thread):
    """Writes good records to modsom_N.modraw, rotating at max_bytes."""
    def __init__(
        self,
        good_queue: queue.Queue,
        stop_event: threading.Event,
        counters: Counters,
        prefix: str = "modsom",
        max_mb: float = 5.0,
    ):
        super().__init__(daemon=True)
        self.good_queue = good_queue
        self.stop_event = stop_event
        self.counters = counters
        self.prefix = prefix
        self.max_bytes = int(max_mb * 1024 * 1024)
        self.idx = 0
        self.f = None
        self.written = 0

    def _open_new(self):
        if self.f:
            try:
                self.f.flush()
                # NOTE: if you want stronger durability, add os.fsync(self.f.fileno())
                self.f.close()
            except Exception:
                pass
        path = f"{self.prefix}_{self.idx}.modraw"
        # Unbuffered to ensure each write hits OS immediately (safe but can be slower)
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
                self.counters.add(file_bytes=len(data), file_records=1)
            except Exception as e:
                print(f"[FILE] Write error: {e}")

            if self.written >= self.max_bytes:
                self.idx += 1
                self._open_new()

        try:
            if self.f:
                self.f.flush()
                self.f.close()
        except Exception:
            pass
        print("[FILE] Writer stopped")


# ----------------------------
# TCP broadcast output thread (multi-client) with batching
# ----------------------------
class TCPBroadcastThread(threading.Thread):
    """
    Listens on host:port and broadcasts every good record to all connected clients.

    Item (2): uses blocking sockets with timeout (safe sendall).
    Item (3): batches multiple records into a single send per loop.
    Item (5): sets TCP_NODELAY and optional SO_SNDBUF.
    """
    def __init__(
        self,
        host: str,
        port: int,
        good_queue: queue.Queue,
        stop_event: threading.Event,
        counters: Counters,
        max_batch_bytes: int = 256 * 1024,
        accept_timeout_s: float = 0.05,
        client_timeout_s: float = 0.2,
        sndbuf_bytes: Optional[int] = 1 << 20,  # 1MB, set None to skip
    ):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.good_queue = good_queue
        self.stop_event = stop_event
        self.counters = counters

        self.max_batch_bytes = max_batch_bytes
        self.accept_timeout_s = accept_timeout_s
        self.client_timeout_s = client_timeout_s
        self.sndbuf_bytes = sndbuf_bytes

        self.srv: Optional[socket.socket] = None
        self.clients: List[socket.socket] = []
        self.lock = threading.Lock()

    def _configure_client(self, conn: socket.socket):
        # Blocking socket with timeout (item 2)
        conn.settimeout(self.client_timeout_s)
        # Low-latency (item 5)
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        # Larger OS send buffer can help (item 5)
        if self.sndbuf_bytes:
            try:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(self.sndbuf_bytes))
            except Exception:
                pass

    def run(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(32)
            srv.settimeout(self.accept_timeout_s)
            self.srv = srv
            print(f"[TCPOUT] Broadcasting on {self.host}:{self.port} (clients can connect)")

            while not self.stop_event.is_set():
                # Accept any new client(s) quickly
                while not self.stop_event.is_set():
                    try:
                        conn, addr = srv.accept()
                    except socket.timeout:
                        break
                    except OSError:
                        break
                    except Exception as e:
                        if not self.stop_event.is_set():
                            print(f"[TCPOUT] Accept error: {e}")
                        break

                    try:
                        self._configure_client(conn)
                    except Exception:
                        pass

                    with self.lock:
                        self.clients.append(conn)
                        self.counters.set(tcp_clients=len(self.clients))
                    print(f"[TCPOUT] Client connected: {addr}")

                # Get at least one record (blocking briefly)
                try:
                    item = self.good_queue.get(timeout=0.05)
                except queue.Empty:
                    continue

                if item is None:
                    break
                if not isinstance(item, ParsedGoodRecord):
                    continue

                # Item (3): batch multiple records
                buf = bytearray(item.raw_bytes)
                rec_count = 1
                while len(buf) < self.max_batch_bytes:
                    try:
                        nxt = self.good_queue.get_nowait()
                    except queue.Empty:
                        break
                    if nxt is None:
                        # propagate stop after sending current buffer
                        self.stop_event.set()
                        break
                    if not isinstance(nxt, ParsedGoodRecord):
                        continue
                    buf.extend(nxt.raw_bytes)
                    rec_count += 1

                data = bytes(buf)

                # Broadcast
                dead_idxs: List[int] = []
                with self.lock:
                    for i, c in enumerate(self.clients):
                        try:
                            c.sendall(data)
                        except (socket.timeout, BrokenPipeError, ConnectionResetError, OSError):
                            dead_idxs.append(i)
                        except Exception:
                            dead_idxs.append(i)

                    # remove dead clients in reverse order
                    if dead_idxs:
                        for i in reversed(dead_idxs):
                            try:
                                self.clients[i].close()
                            except Exception:
                                pass
                            del self.clients[i]
                        self.counters.add(tcp_drop_clients=len(dead_idxs))
                        self.counters.set(tcp_clients=len(self.clients))

                self.counters.add(
                    tcp_batches=1,
                    tcp_bytes=len(data),
                    tcp_records=rec_count,
                )

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
                self.counters.set(tcp_clients=0)
            try:
                if self.srv:
                    self.srv.close()
            except Exception:
                pass
            print("[TCPOUT] Broadcaster stopped")


# ----------------------------
# Stats thread (throttled prints)
# ----------------------------
class StatsThread(threading.Thread):
    def __init__(
        self,
        stop_event: threading.Event,
        counters: Counters,
        byte_queue: queue.Queue,
        parse_queue: queue.Queue,
        file_queue: queue.Queue,
        tcp_queue: queue.Queue,
        period_s: float = 1.0,
    ):
        super().__init__(daemon=True)
        self.stop_event = stop_event
        self.counters = counters
        self.byte_queue = byte_queue
        self.parse_queue = parse_queue
        self.file_queue = file_queue
        self.tcp_queue = tcp_queue
        self.period_s = period_s

        self._last = self.counters.snapshot()
        self._last_t = time.time()

    def run(self):
        while not self.stop_event.is_set():
            time.sleep(self.period_s)
            now = time.time()
            snap = self.counters.snapshot()
            dt = max(1e-6, now - self._last_t)

            # rates
            bin_rate = (snap["bytes_in"] - self._last["bytes_in"]) / dt
            good_rate = (snap["good_records"] - self._last["good_records"]) / dt
            fbytes_rate = (snap["file_bytes"] - self._last["file_bytes"]) / dt
            tcp_bytes_rate = (snap["tcp_bytes"] - self._last["tcp_bytes"]) / dt
            tcp_rec_rate = (snap["tcp_records"] - self._last["tcp_records"]) / dt

            # queue sizes (best-effort; may raise on some implementations)
            try:
                bq = self.byte_queue.qsize()
            except Exception:
                bq = -1
            try:
                pq = self.parse_queue.qsize()
            except Exception:
                pq = -1
            try:
                fq = self.file_queue.qsize()
            except Exception:
                fq = -1
            try:
                tq = self.tcp_queue.qsize()
            except Exception:
                tq = -1

            print(
                "[STATS] "
                f"in={bin_rate/1024:.1f} KB/s, "
                f"good={good_rate:.1f} rec/s, "
                f"badH={snap['bad_header']}, badP={snap['bad_payload']}, resync={snap['resync']} | "
                f"file={fbytes_rate/1024:.1f} KB/s ({snap['file_records']} rec) | "
                f"tcp={tcp_bytes_rate/1024:.1f} KB/s ({tcp_rec_rate:.1f} rec/s), "
                f"clients={snap['tcp_clients']} dropped={snap['tcp_drop_clients']} | "
                f"q(byte={bq}, parse={pq}, file={fq}, tcp={tq})"
            )

            self._last = snap
            self._last_t = now


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

    ap.add_argument("--debug", action="store_true", help="Enable parser debug prints (can reduce throughput)")
    ap.add_argument("--no-stats", action="store_true", help="Disable 1 Hz stats prints")
    ap.add_argument("--tcp-batch-kb", type=int, default=256, help="Max TCP batch size in KB (default 256)")
    ap.add_argument("--tcp-sndbuf-kb", type=int, default=1024, help="TCP SO_SNDBUF in KB (default 1024; 0 disables)")

    args = ap.parse_args()

    counters = Counters()
    stop_event = threading.Event()

    # Queues
    byte_queue: queue.Queue = queue.Queue()
    parse_queue: queue.Queue = queue.Queue()
    file_queue: queue.Queue = queue.Queue()
    tcp_queue: queue.Queue = queue.Queue()

    # Writer thread
    file_writer = RotatingFileWriterThread(
        good_queue=file_queue,
        stop_event=stop_event,
        counters=counters,
        prefix=args.out_prefix,
        max_mb=args.max_mb,
    )
    file_writer.start()

    # Optional TCP broadcast thread
    tcp_broadcaster = None
    if args.tcp_out:
        out_host, out_port = args.tcp_out
        sndbuf_bytes = None if args.tcp_sndbuf_kb <= 0 else int(args.tcp_sndbuf_kb * 1024)
        tcp_broadcaster = TCPBroadcastThread(
            out_host,
            out_port,
            tcp_queue,
            stop_event,
            counters=counters,
            max_batch_bytes=int(args.tcp_batch_kb * 1024),
            sndbuf_bytes=sndbuf_bytes,
        )
        tcp_broadcaster.start()

    # Parser
    parser = EpsiStateMachineParser(parse_queue, counters=counters, debug=args.debug)
    parser_thread = ParserThread(byte_queue, parser, stop_event)
    parser_thread.start()

    # Fanout (item 1)
    fanout = FanoutThread(parse_queue, [file_queue, tcp_queue], stop_event)
    fanout.start()

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
            counters=counters,
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
            counters=counters,
        )
        source_thread.start()
        print(f"[MAIN] Waiting TCP input on {in_host}:{in_port}")

    # Stats thread (item 4)
    stats_thread = None
    if not args.no_stats:
        stats_thread = StatsThread(
            stop_event=stop_event,
            counters=counters,
            byte_queue=byte_queue,
            parse_queue=parse_queue,
            file_queue=file_queue,
            tcp_queue=tcp_queue,
            period_s=1.0,
        )
        stats_thread.start()

    # Run loop: Ctrl-C or 'q'
    print("[MAIN] Press Ctrl-C or type 'q' + Enter to stop.")
    try:
        while True:
            time.sleep(0.2)
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

    # best-effort som.stop
    if ser is not None:
        try:
            if ser.is_open:
                ser.write(b"som.stop\r\n")
                ser.flush()
        except Exception:
            pass

    # unblock queues
    byte_queue.put(None)
    parse_queue.put(None)
    # fanout will propagate None to file_queue/tcp_queue

    # join threads
    for t in [source_thread, parser_thread, fanout, file_writer, tcp_broadcaster, stats_thread]:
        if t is None:
            continue
        try:
            t.join(timeout=2.0)
        except Exception:
            pass

    if ser is not None:
        try:
            ser.close()
        except Exception:
            pass

    print("[MAIN] Done.")


if __name__ == "__main__":
    main()

