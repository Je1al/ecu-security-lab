"""End-to-end attacks against the real C ECU over a virtual CAN bus.

Linux only, and only when ECU_E2E=1 (set in CI). The CI workflow brings up vcan0,
builds the ECU, and points ECU_BIN at it; this test starts the target, runs the
toolkit against it, and asserts the secret is recovered.
"""

import os
import subprocess
import sys
import time
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "toolkit")
)

_LINUX = sys.platform.startswith("linux")
_ENABLED = os.environ.get("ECU_E2E") == "1"


@unittest.skipUnless(_LINUX and _ENABLED, "requires Linux + vcan + ECU_E2E=1")
class E2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.iface = os.environ.get("ECU_IFACE", "vcan0")
        ecu_bin = os.environ["ECU_BIN"]
        cls.proc = subprocess.Popen([ecu_bin, "--iface", cls.iface, "--insecure"])
        time.sleep(0.6)  # let the server bind and start its loop

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()

    def test_read_vin(self):
        from ecutk import uds
        from ecutk.bus import CanBus
        from ecutk.client import UdsClient

        with CanBus(self.iface) as bus:
            client = UdsClient(bus)
            _sid, payload = client.request_parsed(uds.read_did(0xF190))
            self.assertEqual(payload[2:], b"WLAB1234567890123")

    def test_unlock_and_dump(self):
        from ecutk import attacks
        from ecutk.bus import CanBus
        from ecutk.client import UdsClient

        with CanBus(self.iface) as bus:
            client = UdsClient(bus)
            self.assertTrue(attacks.unlock(client), "SecurityAccess unlock failed")
            secret = attacks.dump_memory(client, 0xC0, 0x20)
            self.assertIn(b"FLAG{ecu_secret_unlocked}", secret)

    def test_full_exploit_chain(self):
        from ecutk import attacks
        from ecutk.bus import CanBus

        with CanBus(self.iface) as bus:
            secret = attacks.run_exploit(bus)
            self.assertIn(b"FLAG{ecu_secret_unlocked}", secret)


if __name__ == "__main__":
    unittest.main()
