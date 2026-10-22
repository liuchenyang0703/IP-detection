import unittest
from unittest.mock import patch

import app


SAMPLE_OUTPUT = """Starting Nmap
Nmap scan report for router.local (172.16.11.1)
Host is up (0.0010s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Example Vendor)
Nmap scan report for 172.16.11.20
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned
"""


class AppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()

    def test_parse_nmap_output(self):
        hosts = app.parse_nmap_output(SAMPLE_OUTPUT)
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]["hostname"], "router.local")
        self.assertEqual(hosts[0]["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(hosts[1]["ip"], "172.16.11.20")

    def test_rejects_invalid_network(self):
        with patch("app.shutil.which", return_value="/usr/bin/nmap"):
            response = self.client.post("/api/scan", json={"networks": ["not-a-network"]})
        self.assertEqual(response.status_code, 400)

    def test_access_log_contains_client_ip(self):
        with self.assertLogs("netscope.access", level="INFO") as captured:
            response = self.client.get("/api/health", environ_base={"REMOTE_ADDR": "192.168.1.50"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any("ip=192.168.1.50" in line for line in captured.output))

    @patch("app.get_primary_network_info", return_value={
        "ip": "172.16.11.20",
        "network": "172.16.11.0/24",
        "netmask": "255.255.255.0",
        "mac": "AA:BB:CC:DD:EE:FF",
        "interface": "Ethernet",
    })
    def test_gets_local_network(self, _get_network):
        response = self.client.get("/api/local-network")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["network"], "172.16.11.0/24")
        self.assertEqual(response.get_json()["ip"], "172.16.11.20")
        self.assertEqual(response.get_json()["mac"], "AA:BB:CC:DD:EE:FF")

    def test_normalizes_mac(self):
        self.assertEqual(app.normalize_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        self.assertIsNone(app.normalize_mac("00:00:00:00:00:00"))

    @patch('app.get_primary_network_info', return_value=None)
    @patch('app.subprocess.run')
    @patch('app.resolve_nmap', return_value='nmap.exe')
    def test_scan_hides_nmap_window_on_windows(self, _resolve_nmap, run, _get_network):
        run.return_value.returncode = 0
        run.return_value.stdout = ''
        run.return_value.stderr = ''

        app.scan_network('172.16.11.0/24')

        expected_flags = app.subprocess.CREATE_NO_WINDOW if app.os.name == 'nt' else 0
        self.assertEqual(run.call_args.kwargs['creationflags'], expected_flags)

    def test_exports_all_supported_formats(self):
        payload = {
            "networks": ["172.16.11.0/24"],
            "results": [{
                "network": "172.16.11.0/24",
                "hosts": [{
                    "ip": "172.16.11.20",
                    "hostname": "test-host",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "vendor": "Example Vendor",
                }],
            }],
        }
        signatures = {"xlsx": b"PK", "docx": b"PK", "pdf": b"%PDF", "md": b"\xef\xbb\xbf", "txt": b"\xef\xbb\xbf"}
        for export_format, signature in signatures.items():
            response = self.client.post("/api/export", json={**payload, "format": export_format})
            self.assertEqual(response.status_code, 200, export_format)
            self.assertTrue(response.data.startswith(signature), export_format)

    @patch("app.scan_network")
    @patch("app.shutil.which", return_value="/usr/bin/nmap")
    def test_scans_and_keeps_input_order(self, _which, mock_scan):
        mock_scan.side_effect = lambda network: {
            "network": network, "hosts": [], "count": 0, "status": "success"
        }
        response = self.client.post(
            "/api/scan",
            json={"networks": ["172.16.11.8/24", "172.16.10.0/24"]},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [item["network"] for item in response.get_json()["results"]],
            ["172.16.11.0/24", "172.16.10.0/24"],
        )
        self.assertGreaterEqual(response.get_json()["elapsed_ms"], 0)


if __name__ == "__main__":
    unittest.main()
