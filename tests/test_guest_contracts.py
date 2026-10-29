import json
import unittest
from unittest.mock import patch

import magnum_api as wire


class GuestContractTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

    def transport(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        if url.endswith('/guest/login'):
            return json.dumps({'token': 'Bearer synthetic-guest-token'}).encode()
        return b'[]'

    def test_categories_uses_dio_null_and_boolean_and_guest_once(self):
        with patch.object(wire, '_http_request', side_effect=self.transport):
            client = wire.MagnumClient()
            client.categories(5001)
            client.categories(5001, 6007)
        self.assertEqual(len(self.calls), 3)
        self.assertTrue(self.calls[1][1].endswith('?includeChildNodes=true&parentId&platformId=5001'))
        self.assertTrue(self.calls[2][1].endswith('?includeChildNodes=true&parentId=6007&platformId=5001'))
        self.assertEqual(self.calls[1][2]['Authorization'], 'Bearer synthetic-guest-token')

    def test_suggest_sends_search_word_only(self):
        with patch.object(wire, '_http_request', side_effect=self.transport):
            wire.MagnumClient().suggest(5001, 'bread')
        self.assertTrue(self.calls[-1][1].endswith('/search/lean/items?searchWord=bread'))
        self.assertIsNone(self.calls[-1][3])

    def test_geo_is_public_and_never_creates_guest(self):
        with patch.object(wire, '_http_request', side_effect=self.transport):
            wire.MagnumClient().geo(43.2, 76.8)
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn('Authorization', self.calls[0][2])


if __name__ == '__main__':
    unittest.main()
