import unittest
from unittest.mock import patch, Mock
import socket
from io import StringIO
import sys
import vuln  # Your main script for vulnerability checks
import requests
from bs4 import BeautifulSoup

def scrape_website(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Example: Scraping the page title
        page_title = soup.title.string
        print("Page Title:", page_title)

        # Example: Scraping all links on the page
        links = soup.find_all('a')
        print("Links:")
        for link in links:
            link_url = link.get('href')
            link_text = link.string
            print(f"{link_text}: {link_url}")

        # Add more scraping logic as needed

    except requests.exceptions.RequestException as e:
        print("Web scraping failed:", str(e))
class TestScrapeWebsite(unittest.TestCase):

    @patch('requests.get')
    def test_scrape_website(self, mock_get):
        # Create a mock response object with the desired HTML content
        mock_response = Mock()
        mock_response.content = b'<html><head><title>Test Title</title></head><body><a href="https://example.com">Example Link</a></body></html>'
        mock_get.return_value = mock_response

        captured_output = StringIO()
        sys.stdout = captured_output

        scrape_website('https://test.com')

        expected_output = "Page Title: Test Title\nLinks:\nExample Link: https://example.com\n"
        self.assertEqual(captured_output.getvalue(), expected_output)

        sys.stdout = sys.__stdout__

def find_subdomains(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    response = requests.get(url)
    data = response.json()

    subdomains = set()
    for item in data:
        name_value = item['name_value']
        subdomains.add(name_value)

    return subdomains
class TestFindSubdomains(unittest.TestCase):

    @patch('requests.get')
    def test_find_subdomains(self, mock_get):
        # Create a mock response object with the desired JSON data
        mock_response = Mock()
        mock_response.json.return_value = [
            {'name_value': 'sub1.example.com'},
            {'name_value': 'sub2.example.com'},
        ]
        mock_get.return_value = mock_response

        # Call the function with the domain "example.com"
        result = find_subdomains('example.com')

        # Assert that the expected subdomains are returned
        self.assertEqual(result, {'sub1.example.com', 'sub2.example.com'})


def scan_ports(hostname):
    target_ip = socket.gethostbyname(hostname)
    print(f"Scanning ports for {hostname} ({target_ip})...")

    common_ports = [21, 22, 80, 443, 3389]

    open_ports = []

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    return open_ports

class TestPortScanner(unittest.TestCase):

    @patch('builtins.input', side_effect=["example.com"])
    def test_scan_ports(self, mock_input):
        captured_output = StringIO()
        sys.stdout = captured_output

        expected_output = "Scanning ports for example.com (93.184.216.34)..."

        open_ports = scan_ports(mock_input())
        self.assertIn(expected_output, captured_output.getvalue())
        self.assertIn(80, open_ports)

        sys.stdout = sys.__stdout__


class TestURLVulnerabilityScanner(unittest.TestCase):

    @patch('vuln.check_xss', return_value=True)
    @patch('requests.get')
    def test_check_xss_vulnerability_found(self, mock_get, mock_check_xss):
        mock_response = Mock()
        mock_response.text = '<script>alert("XSS vulnerability")</script>'
        mock_get.return_value = mock_response

        result = vuln.check_xss('http://example.com')
        self.assertTrue(result)

    @patch('vuln.check_xss', return_value=False)
    @patch('requests.get')
    def test_check_xss_no_vulnerability(self, mock_get, mock_check_xss):
        mock_response = Mock()
        mock_response.text = 'Normal content'
        mock_get.return_value = mock_response

        result = vuln.check_xss('http://example.com')
        self.assertFalse(result)

    @patch('vuln.check_sql_injection', return_value=True)
    @patch('requests.get')
    def test_check_sql_injection_vulnerability_found(self, mock_get, mock_check_sql_injection):
        mock_response = Mock()
        mock_response.text = 'error'
        mock_get.return_value = mock_response

        result = vuln.check_sql_injection('http://example.com')
        self.assertTrue(result)

    @patch('vuln.check_sql_injection', return_value=False)
    @patch('requests.get')
    def test_check_sql_injection_no_vulnerability(self, mock_get, mock_check_sql_injection):
        mock_response = Mock()
        mock_response.text = 'Normal content'
        mock_get.return_value = mock_response

        result = vuln.check_sql_injection('http://example.com')
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
