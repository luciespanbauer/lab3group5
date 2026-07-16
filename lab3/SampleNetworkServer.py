"""Secure UDP thermometers and the command-line incubator simulation."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import hmac
import secrets
import socket
import threading
import time
from typing import Any, Callable

from secure_transport import (
    MAX_PACKET_BYTES,
    PROTOCOL_VERSION,
    ConfigurationError,
    PacketError,
    decrypt_packet,
    encrypt_packet,
    load_auth_password,
    load_transport_key,
)


DEFAULT_SESSION_TTL = 15 * 60
DEFAULT_MAX_SESSIONS = 100
DEFAULT_REQUEST_WINDOW = 60
DEFAULT_MAX_REPLAY_ENTRIES = 1024


class RequestRejected(ValueError):
    """Internal signal for a generic, encrypted rejection response."""

    def __init__(self, public_message: str = "Invalid request") -> None:
        super().__init__(public_message)
        self.public_message = public_message


@dataclass
class SessionRecord:
    token_digest: str
    created_at: float
    last_used_at: float
    client_address: tuple[str, int]


class SmartNetworkThermometer(threading.Thread):
    """A thermometer with encrypted requests and bounded authenticated sessions."""

    PROTECTED_COMMANDS = frozenset(
        {"SET_DEGF", "SET_DEGC", "SET_DEGK", "GET_TEMP", "UPDATE_TEMP"}
    )

    def __init__(
        self,
        source: Any,
        updatePeriod: float,
        port: int,
        *,
        host: str = "127.0.0.1",
        session_ttl: float = DEFAULT_SESSION_TTL,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        request_window: float = DEFAULT_REQUEST_WINDOW,
        max_replay_entries: int = DEFAULT_MAX_REPLAY_ENTRIES,
        time_fn: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(daemon=True)
        if updatePeriod <= 0:
            raise ValueError("updatePeriod must be positive")
        if session_ttl <= 0:
            raise ValueError("session_ttl must be positive")
        if type(max_sessions) is not int or max_sessions <= 0:
            raise ValueError("max_sessions must be a positive integer")
        if request_window <= 0:
            raise ValueError("request_window must be positive")
        if type(max_replay_entries) is not int or max_replay_entries <= 0:
            raise ValueError("max_replay_entries must be a positive integer")

        # Configuration is loaded before the socket is created, so failure is closed.
        self.auth_password = load_auth_password()
        self.transport_key = load_transport_key()
        self.source = source
        self.updatePeriod = updatePeriod
        self.session_ttl = session_ttl
        self.max_sessions = max_sessions
        self.request_window = request_window
        self.max_replay_entries = max_replay_entries
        self._time = time_fn
        self._session_lock = threading.RLock()
        self.sessions: OrderedDict[str, SessionRecord] = OrderedDict()
        self._seen_requests: OrderedDict[str, float] = OrderedDict()
        self._stop_event = threading.Event()
        self.deg = "K"
        self.curTemperature = 0.0
        self.updateTemperature()

        self.serverSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.serverSocket.bind((host, port))
        self.serverSocket.settimeout(updatePeriod)
        self.host, self.port = self.serverSocket.getsockname()

    def setSource(self, source: Any) -> None:
        self.source = source

    def setUpdatePeriod(self, updatePeriod: float) -> None:
        if updatePeriod <= 0:
            raise ValueError("updatePeriod must be positive")
        self.updatePeriod = updatePeriod
        self.serverSocket.settimeout(updatePeriod)

    def setDegreeUnit(self, unit: str) -> None:
        self.deg = unit if unit in {"F", "K", "C"} else "K"

    def updateTemperature(self) -> None:
        self.curTemperature = float(self.source.getTemperature())

    def getTemperature(self) -> float:
        if self.deg == "C":
            return self.curTemperature - 273
        if self.deg == "F":
            return (self.curTemperature - 273) * 9 / 5 + 32
        return self.curTemperature

    @staticmethod
    def _token_digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _cleanup_sessions(self, now: float | None = None) -> None:
        current = self._time() if now is None else now
        with self._session_lock:
            expired = [
                digest
                for digest, record in self.sessions.items()
                if current - record.last_used_at >= self.session_ttl
            ]
            for digest in expired:
                self.sessions.pop(digest, None)

            replay_cutoff = current - self.request_window
            while self._seen_requests:
                _request_id, seen_at = next(iter(self._seen_requests.items()))
                if seen_at >= replay_cutoff:
                    break
                self._seen_requests.popitem(last=False)

    @property
    def active_session_count(self) -> int:
        self._cleanup_sessions()
        with self._session_lock:
            return len(self.sessions)

    def _mark_request_seen(self, request_id: str, now: float) -> None:
        self._cleanup_sessions(now)
        with self._session_lock:
            if request_id in self._seen_requests:
                raise RequestRejected("Invalid request")
            if len(self._seen_requests) >= self.max_replay_entries:
                # Keep still-live IDs so an attacker cannot force early replay eviction.
                raise RequestRejected("Invalid request")
            self._seen_requests[request_id] = now

    def _issue_session(self, address: tuple[str, int]) -> str:
        now = self._time()
        self._cleanup_sessions(now)
        with self._session_lock:
            if len(self.sessions) >= self.max_sessions:
                # The ordered dictionary is maintained in least-recently-used order.
                self.sessions.popitem(last=False)
            for _attempt in range(10):
                token = secrets.token_urlsafe(32)
                digest = self._token_digest(token)
                if digest not in self.sessions:
                    self.sessions[digest] = SessionRecord(
                        token_digest=digest,
                        created_at=now,
                        last_used_at=now,
                        client_address=address,
                    )
                    return token
        raise RequestRejected("Authentication failed")

    def _validate_session(
        self, token: str, address: tuple[str, int]
    ) -> SessionRecord:
        now = self._time()
        self._cleanup_sessions(now)
        digest = self._token_digest(token)
        with self._session_lock:
            record = self.sessions.get(digest)
            if record is None or not hmac.compare_digest(record.token_digest, digest):
                raise RequestRejected("Invalid or expired session")
            if record.client_address != address:
                raise RequestRejected("Invalid or expired session")
            record.last_used_at = now
            self.sessions.move_to_end(digest)
            return record

    def _validate_request(self, request: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request, dict):
            raise RequestRejected()
        request_type = request.get("type")
        common = {"version", "type", "request_id", "timestamp"}
        allowed_fields = {
            "AUTH": common | {"password"},
            "LOGOUT": common | {"token"},
            "COMMAND": common | {"token", "command"},
        }
        if request_type not in allowed_fields or set(request) != allowed_fields[request_type]:
            raise RequestRejected()
        if type(request.get("version")) is not int or request["version"] != PROTOCOL_VERSION:
            raise RequestRejected()
        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not 16 <= len(request_id) <= 128:
            raise RequestRejected()
        timestamp = request.get("timestamp")
        now = self._time()
        if type(timestamp) is not int or abs(now - timestamp) > self.request_window:
            raise RequestRejected()

        if request_type == "AUTH":
            password = request.get("password")
            if not isinstance(password, str) or not password or len(password) > 1024:
                raise RequestRejected("Authentication failed")
        elif request_type == "LOGOUT":
            token = request.get("token")
            if not isinstance(token, str) or not token:
                raise RequestRejected("Authentication required")
        else:
            token = request.get("token")
            command = request.get("command")
            if not isinstance(token, str) or not token:
                raise RequestRejected("Authentication required")
            if not isinstance(command, str) or command not in self.PROTECTED_COMMANDS:
                raise RequestRejected("Invalid request")
        return request

    def _response(self, request_id: str, ok: bool, **fields: Any) -> dict[str, Any]:
        return {
            "version": PROTOCOL_VERSION,
            "type": "RESPONSE",
            "request_id": request_id,
            "timestamp": int(self._time()),
            "ok": ok,
            **fields,
        }

    def processCommands(
        self, request: dict[str, Any], address: tuple[str, int]
    ) -> dict[str, Any]:
        """Validate, authorize, and dispatch exactly one structured request."""

        request = self._validate_request(request)
        now = self._time()
        self._mark_request_seen(request["request_id"], now)
        self._cleanup_sessions(now)
        request_type = request["type"]

        if request_type == "AUTH":
            supplied_password = request["password"].encode("utf-8")
            configured_password = self.auth_password.encode("utf-8")
            if not hmac.compare_digest(supplied_password, configured_password):
                raise RequestRejected("Authentication failed")
            return self._response(
                request["request_id"], True, token=self._issue_session(address)
            )

        if request_type == "LOGOUT":
            self._validate_session(request["token"], address)
            digest = self._token_digest(request["token"])
            with self._session_lock:
                self.sessions.pop(digest, None)
            self._cleanup_sessions()
            return self._response(request["request_id"], True, logged_out=True)

        self._validate_session(request["token"], address)
        command = request["command"]
        if command == "GET_TEMP":
            return self._response(
                request["request_id"],
                True,
                temperature=self.getTemperature(),
                unit=self.deg,
            )
        if command == "SET_DEGC":
            self.setDegreeUnit("C")
            return self._response(request["request_id"], True, unit=self.deg)
        if command == "SET_DEGF":
            self.setDegreeUnit("F")
            return self._response(request["request_id"], True, unit=self.deg)
        if command == "SET_DEGK":
            self.setDegreeUnit("K")
            return self._response(request["request_id"], True, unit=self.deg)
        if command == "UPDATE_TEMP":
            self.updateTemperature()
            return self._response(request["request_id"], True, updated=True)
        raise RequestRejected()

    def handle_datagram(self, packet: bytes, address: tuple[str, int]) -> bytes:
        """Return one encrypted response and never dispatch an invalid datagram."""

        request_id = secrets.token_urlsafe(16)
        try:
            request = decrypt_packet(packet, self.transport_key)
            candidate_id = request.get("request_id")
            if isinstance(candidate_id, str) and 16 <= len(candidate_id) <= 128:
                request_id = candidate_id
            response = self.processCommands(request, address)
        except RequestRejected as exc:
            response = self._response(request_id, False, error=exc.public_message)
        except (PacketError, TypeError, ValueError):
            response = self._response(request_id, False, error="Invalid request")
        return encrypt_packet(response, self.transport_key)

    def close(self) -> None:
        self._stop_event.set()
        try:
            self.serverSocket.close()
        except OSError:
            pass

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                packet, address = self.serverSocket.recvfrom(MAX_PACKET_BYTES)
            except socket.timeout:
                packet = None
            except OSError:
                if self._stop_event.is_set():
                    break
                packet = None

            if packet is not None:
                response = self.handle_datagram(packet, address)
                try:
                    self.serverSocket.sendto(response, address)
                except OSError:
                    if self._stop_event.is_set():
                        break
            self.updateTemperature()


class SimpleClient:
    """The original local plotting client, loaded only when explicitly created."""

    def __init__(self, therm1: Any, therm2: Any) -> None:
        import matplotlib.animation as animation
        import matplotlib.pyplot as plt

        self.plt = plt
        self.fig, self.ax = plt.subplots()
        now = time.time()
        self.lastTime = now
        self.times = [
            time.strftime("%H:%M:%S", time.localtime(now - i))
            for i in range(30, 0, -1)
        ]
        self.infTemps = [0.0] * 30
        self.incTemps = [0.0] * 30
        (self.infLn,) = plt.plot(range(30), self.infTemps, label="Infant Temperature")
        (self.incLn,) = plt.plot(range(30), self.incTemps, label="Incubator Temperature")
        plt.xticks(range(30), self.times, rotation=45)
        plt.ylim((20, 50))
        plt.legend(handles=[self.infLn, self.incLn])
        self.infTherm = therm1
        self.incTherm = therm2
        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)

    def updateTime(self) -> None:
        now = time.time()
        if int(now) > int(self.lastTime):
            self.times.append(time.strftime("%H:%M:%S", time.localtime(now)))
            self.times = self.times[-30:]
            self.lastTime = now
            self.plt.xticks(range(30), self.times, rotation=45)
            self.plt.title(time.strftime("%A, %Y-%m-%d", time.localtime(now)))

    def updateInfTemp(self, _frame: Any) -> tuple[Any]:
        self.updateTime()
        self.infTemps.append(self.infTherm.getTemperature() - 273)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return (self.infLn,)

    def updateIncTemp(self, _frame: Any) -> tuple[Any]:
        self.updateTime()
        self.incTemps.append(self.incTherm.getTemperature() - 273)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return (self.incLn,)


def main() -> None:
    """Start the original simulator and GUI only for direct execution."""

    import matplotlib

    matplotlib.use("TkAgg")
    import matplotlib.pyplot as plt
    import infinc

    update_period = 0.05
    simulation_step = 0.1
    bob_thermo: SmartNetworkThermometer | None = None
    inc_thermo: SmartNetworkThermometer | None = None
    try:
        bob = infinc.Human(mass=8, length=1.68, temperature=36 + 273)
        bob_thermo = SmartNetworkThermometer(bob, update_period, 23456)

        inc = infinc.Incubator(
            width=1,
            depth=1,
            height=1,
            temperature=37 + 273,
            roomTemperature=20 + 273,
        )
        inc_thermo = SmartNetworkThermometer(inc, update_period, 23457)

        inc_heater = infinc.SmartHeater(
            powerOutput=1500,
            setTemperature=45 + 273,
            thermometer=inc_thermo,
            updatePeriod=update_period,
        )
        inc.setHeater(inc_heater)
        simulator = infinc.Simulator(
            infant=bob,
            incubator=inc,
            roomTemp=20 + 273,
            timeStep=simulation_step,
            sleepTime=simulation_step / 10,
        )

        bob_thermo.start()
        inc_thermo.start()
        inc_heater.start()
        simulator.start()
        SimpleClient(bob_thermo, inc_thermo)
        plt.grid()
        plt.show()
    except ConfigurationError as exc:
        raise SystemExit(f"Security configuration error: {exc}") from exc
    finally:
        if bob_thermo is not None:
            bob_thermo.close()
        if inc_thermo is not None:
            inc_thermo.close()


if __name__ == "__main__":
    main()
