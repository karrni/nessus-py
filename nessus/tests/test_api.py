from unittest import TestCase
from unittest.mock import Mock, patch

from nessus.api import NessusAPI


class TestNessusAPI(TestCase):
    def setUp(self):
        patcher = patch("nessus.api.requests.Session")
        self.mock_session = patcher.start()
        self.addCleanup(patcher.stop)

    def test_init(self):
        api = NessusAPI("https://nessus.local")

        # Ensure the URL has a trailing slash
        self.assertEqual(api.base_url, "https://nessus.local/")

        self.assertFalse(api._verify)
        self.assertFalse(api._authenticated)

    def test_get_api_token(self):
        mock_response = Mock()
        mock_response.text = (
            '[{key:"getApiToken",value:function(){return"9af16347-32e1-4895-b3b3-4076c4912be3"}},{key:"getApiHeaders"'
        )
        self.mock_session.return_value.get.return_value = mock_response

        api = NessusAPI("https://nessus.local/")
        token = api._get_api_token()

        self.assertEqual(token, "9af16347-32e1-4895-b3b3-4076c4912be3")
