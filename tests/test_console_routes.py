"""Console deep links retain API authorization and serve the shared shell."""
import unittest
import urllib.request
import test_integrations as support
from test_app import LocalClient


class ConsoleRoutesTests(unittest.TestCase):
    def setUp(self):
        self.lab=support.IntegrationHTTPTests();self.lab.setUp()
    def tearDown(self):self.lab.tearDown()
    def test_console_deep_links_and_assets(self):
        for path in ['/alert?id=SE-example','/integrations','/console.css','/presentation.js','/integrations.js']:
            with urllib.request.urlopen(self.lab.base+path,timeout=5) as response:
                self.assertEqual(response.status,200)
                self.assertIn('no-store',response.headers['Cache-Control'])
                content=response.read().decode('utf-8')
                if path.startswith(('/alert','/integrations')) and not path.endswith('.js'):
                    self.assertIn('id="view-integrations"',content)
                    self.assertIn('/console.css',content)
    def test_deep_link_does_not_expand_employee_access(self):
        employee=LocalClient(self.lab.base).login('lab-001')
        self.assertEqual(employee.request('/api/alerts?id=SE-example')[0],403)
        self.assertEqual(employee.request('/api/integrations/keys')[0],403)
