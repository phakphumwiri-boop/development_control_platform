import base64
import json
import unittest
from unittest.mock import patch

from tools.cloud_gateway import recon_api


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit=-1):
        return self.payload[:limit]


class ReconPublicAPIAdapterTests(unittest.TestCase):
    def test_routes_resolve_only_to_fixed_public_repository(self):
        self.assertEqual(
            recon_api.resolve_recon_url("/api/recon/repository"),
            "https://api.github.com/repos/phakphum12345/Drive-letter",
        )
        self.assertEqual(
            recon_api.resolve_recon_url("/api/recon/pulls"),
            "https://api.github.com/repos/phakphum12345/Drive-letter/pulls?state=open&per_page=100",
        )
        self.assertTrue(
            recon_api.resolve_recon_url("/api/recon/config/recon-policy.config.json").endswith(
                "/contents/current/recon-back-box/config/recon-policy.config.json?ref=main"
            )
        )

    def test_rejects_unknown_paths_and_unapproved_config_names(self):
        for path in (
            "/api/recon/",
            "/api/recon/../../private",
            "/api/recon/config/.env",
            "/api/recon/config/unknown.json",
            "/api/recon/actions/runs/not-a-number/artifacts",
            "/api/recon/repository?host=example.com",
        ):
            with self.subTest(path=path):
                with self.assertRaises(recon_api.ReconAPIError) as caught:
                    recon_api.resolve_recon_url(path)
                self.assertEqual(caught.exception.status, 404)

    @patch("tools.cloud_gateway.recon_api.urlopen")
    def test_fetches_public_metadata_without_credentials(self, mocked_urlopen):
        payload = {"full_name": "phakphum12345/Drive-letter", "private": False}
        mocked_urlopen.return_value = FakeResponse(json.dumps(payload).encode())
        result = recon_api.fetch_recon_resource("/api/recon/repository")
        self.assertEqual(result, payload)
        request = mocked_urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.github.com/repos/phakphum12345/Drive-letter")
        self.assertFalse(any(key.lower() == "authorization" for key in request.headers))

    @patch("tools.cloud_gateway.recon_api.urlopen")
    def test_decodes_only_allowlisted_config_json(self, mocked_urlopen):
        config = {"config_id": "recon-policy", "authority": "FINAL_GATE"}
        payload = {
            "encoding": "base64",
            "content": base64.b64encode(json.dumps(config).encode()).decode(),
        }
        mocked_urlopen.return_value = FakeResponse(json.dumps(payload).encode())
        self.assertEqual(
            recon_api.fetch_recon_resource("/api/recon/config/recon-policy.config.json"),
            config,
        )

    @patch("tools.cloud_gateway.recon_api.urlopen")
    def test_maps_missing_upstream_resource_without_leaking_details(self, mocked_urlopen):
        from urllib.error import HTTPError
        mocked_urlopen.side_effect = HTTPError(
            "https://api.github.com/example", 404, "Not Found", {}, None
        )
        with self.assertRaises(recon_api.ReconAPIError) as caught:
            recon_api.fetch_recon_resource("/api/recon/repository")
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(caught.exception.public_message, "Recon source record not found")


if __name__ == "__main__":
    unittest.main()
