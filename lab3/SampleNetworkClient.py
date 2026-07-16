"""Client for the authenticated and encrypted incubator UDP protocol."""

from __future__ import annotations

import math
import secrets
import socket
import threading
import time
from typing import Any

from secure_transport import (
    MAX_PACKET_BYTES,
    PROTOCOL_VERSION,
    PacketError,
    decrypt_packet,
    encrypt_packet,
    load_transport_key,
)


class NetworkClientError(RuntimeError):
    """Raised when a secure network operation cannot be completed."""


class AuthenticationError(NetworkClientError):
    """Raised when authentication or session validation fails."""


class SimpleNetworkClient:
    """Synchronous UDP client with a persistent, timeout-protected socket."""

    COMMANDS = {"GET_TEMP", "SET_DEGC", "SET_DEGF", "SET_DEGK", "UPDATE_TEMP"}

    def __init__(
        self,
        port1: int,
        port2: int,
        *,
        host: str = "127.0.0.1",
        timeout: float = 2.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.transport_key = load_transport_key()
        self.host = host
        self.infPort = port1
        self.incPort = port2
        self.infToken: str | None = None
        self.incToken: str | None = None
        self._socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self._socket.settimeout(timeout)
        self._lock = threading.Lock()
        self._closed = False

        now = time.time()
        self.lastTime = now
        self.times = [
            time.strftime("%H:%M:%S", time.localtime(now - i))
            for i in range(30, 0, -1)
        ]
        self.infTemps = [0.0] * 30
        self.incTemps = [0.0] * 30

    def close(self) -> None:
        if not self._closed:
            self._socket.close()
            self._closed = True

    def __enter__(self) -> "SimpleNetworkClient":
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.close()

    def _request(self, port: int, payload: dict[str, Any]) -> dict[str, Any]:
        if self._closed:
            raise NetworkClientError("Network client is closed")
        request_id = secrets.token_urlsafe(16)
        request = {
            "version": PROTOCOL_VERSION,
            "request_id": request_id,
            "timestamp": int(time.time()),
            **payload,
        }
        packet = encrypt_packet(request, self.transport_key)
        try:
            with self._lock:
                self._socket.sendto(packet, (self.host, port))
                response_packet, address = self._socket.recvfrom(MAX_PACKET_BYTES)
        except (OSError, socket.timeout) as exc:
            raise NetworkClientError("Secure incubator request failed") from exc

        expected_host = socket.gethostbyname(self.host)
        if address != (expected_host, port):
            raise NetworkClientError("Response came from an unexpected endpoint")
        try:
            response = decrypt_packet(response_packet, self.transport_key)
        except PacketError as exc:
            raise NetworkClientError("Server returned an invalid encrypted response") from exc

        required = {"version", "type", "request_id", "timestamp", "ok"}
        if (
            not required.issubset(response)
            or response.get("version") != PROTOCOL_VERSION
            or response.get("type") != "RESPONSE"
            or response.get("request_id") != request_id
            or type(response.get("timestamp")) is not int
            or type(response.get("ok")) is not bool
        ):
            raise NetworkClientError("Server returned an invalid response payload")
        if not response["ok"]:
            error = response.get("error", "Request rejected")
            if not isinstance(error, str):
                error = "Request rejected"
            raise AuthenticationError(error)
        return response

    def authenticate(self, port: int, password: str | bytes) -> str:
        """Authenticate with a password supplied explicitly by the caller."""

        if isinstance(password, bytes):
            try:
                password = password.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("password must be valid UTF-8") from exc
        if not isinstance(password, str) or not password:
            raise ValueError("password must be a non-empty string")
        response = self._request(port, {"type": "AUTH", "password": password})
        token = response.get("token")
        if not isinstance(token, str) or not token:
            raise NetworkClientError("Authentication response did not contain a token")
        return token

    def _command(self, port: int, token: str, command: str) -> dict[str, Any]:
        if not isinstance(token, str) or not token:
            raise AuthenticationError("Authentication required")
        if command not in self.COMMANDS:
            raise ValueError("Unsupported command")
        return self._request(
            port,
            {"type": "COMMAND", "token": token, "command": command},
        )

    def getTemperatureFromPort(self, port: int, token: str) -> float:
        response = self._command(port, token, "GET_TEMP")
        temperature = response.get("temperature")
        if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
            raise NetworkClientError("Temperature response was invalid")
        return float(temperature)

    def setTemperatureC(self, port: int, token: str) -> bool:
        return self._command(port, token, "SET_DEGC").get("unit") == "C"

    def setTemperatureF(self, port: int, token: str) -> bool:
        return self._command(port, token, "SET_DEGF").get("unit") == "F"

    def setTemperatureK(self, port: int, token: str) -> bool:
        return self._command(port, token, "SET_DEGK").get("unit") == "K"

    def updateTemperature(self, port: int, token: str) -> bool:
        return bool(self._command(port, token, "UPDATE_TEMP").get("updated"))

    def logout(self, port: int, token: str) -> bool:
        if not isinstance(token, str) or not token:
            raise AuthenticationError("Authentication required")
        response = self._request(port, {"type": "LOGOUT", "token": token})
        return bool(response.get("logged_out"))

    def updateTime(self) -> None:
        now = time.time()
        if math.floor(now) > math.floor(self.lastTime):
            self.times.append(time.strftime("%H:%M:%S", time.localtime(now)))
            self.times = self.times[-30:]
            self.lastTime = now

    def updateInfTemp(self, _frame: Any, password: str) -> tuple[Any, ...]:
        """Plot callback; callers must provide the authentication password."""

        self.updateTime()
        if self.infToken is None:
            self.infToken = self.authenticate(self.infPort, password)
        self.infTemps.append(
            self.getTemperatureFromPort(self.infPort, self.infToken) - 273
        )
        self.infTemps = self.infTemps[-30:]
        if hasattr(self, "infLn"):
            self.infLn.set_data(range(30), self.infTemps)
            return (self.infLn,)
        return ()

    def updateIncTemp(self, _frame: Any, password: str) -> tuple[Any, ...]:
        """Plot callback; callers must provide the authentication password."""

        self.updateTime()
        if self.incToken is None:
            self.incToken = self.authenticate(self.incPort, password)
        self.incTemps.append(
            self.getTemperatureFromPort(self.incPort, self.incToken) - 273
        )
        self.incTemps = self.incTemps[-30:]
        if hasattr(self, "incLn"):
            self.incLn.set_data(range(30), self.incTemps)
            return (self.incLn,)
        return ()
