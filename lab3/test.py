"""Manual secure-authentication smoke test for a running incubator server."""

from SampleNetworkClient import SimpleNetworkClient
from secure_transport import load_auth_password


def main() -> None:
    password = load_auth_password()
    with SimpleNetworkClient(23456, 23457) as client:
        token = client.authenticate(23457, password)
        if not token:
            raise RuntimeError("Authentication did not return a session")
        print("Secure authentication succeeded")
        client.logout(23457, token)


if __name__ == "__main__":
    main()
