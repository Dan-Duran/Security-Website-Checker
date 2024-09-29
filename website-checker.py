import time
import requests
from urllib.parse import urlparse
import re
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def check_website(url):
    try:
        start_time = time.time()
        headers = {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response_time = round((time.time() - start_time) * 1000, 2)

        # Check for Cloudflare protection
        cloudflare_headers = ['cf-ray', 'cf-cache-status', 'cf-request-id']
        is_cloudflare = any(header in response.headers for header in cloudflare_headers) or 'cloudflare' in response.headers.get('Server', '').lower()
        
        # Check security headers
        security_headers = check_security_headers(response.headers)
        
        # Check SSL/TLS
        ssl_info = check_ssl(urlparse(url).netloc)
        
        # Check for common vulnerabilities
        vulnerabilities = check_vulnerabilities(response)

        if is_cloudflare:
            if response.status_code == 403:
                status = 'CLOUDFLARE_STRICT'
            else:
                status = 'CLOUDFLARE_PERMISSIVE'
        else:
            status = 'UP'

        return status, response_time, response.status_code, response.headers, response.text[:1000], security_headers, ssl_info, vulnerabilities

    except requests.exceptions.RequestException as e:
        return 'DOWN', None, None, None, str(e), None, None, None

def check_security_headers(headers):
    security_headers = {
        'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not set'),
        'X-Frame-Options': headers.get('X-Frame-Options', 'Not set'),
        'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not set'),
        'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not set'),
        'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not set'),
        'Referrer-Policy': headers.get('Referrer-Policy', 'Not set'),
    }
    return security_headers

def check_ssl(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                return {
                    'Version': x509_cert.version,
                    'Serial Number': x509_cert.serial_number,
                    'Subject': x509_cert.subject.rfc4514_string(),
                    'Issuer': x509_cert.issuer.rfc4514_string(),
                    'Not Valid Before': x509_cert.not_valid_before,
                    'Not Valid After': x509_cert.not_valid_after,
                }
    except Exception as e:
        return {'Error': str(e)}

def check_vulnerabilities(response):
    vulnerabilities = []
    
    # Check for server information disclosure
    if 'Server' in response.headers:
        vulnerabilities.append('Server information disclosure')
    
    # Check for missing X-Frame-Options header (clickjacking vulnerability)
    if 'X-Frame-Options' not in response.headers:
        vulnerabilities.append('Potential clickjacking vulnerability (missing X-Frame-Options header)')
    
    # Check for insecure cookies
    for cookie in response.cookies:
        if not cookie.secure:
            vulnerabilities.append('Insecure cookie detected (missing Secure flag)')
        if not cookie.has_nonstandard_attr('HttpOnly'):
            vulnerabilities.append('Insecure cookie detected (missing HttpOnly flag)')
    
    return vulnerabilities

# Main function for user interaction
def main():
    print("Website Checker Utility")
    domain = input("Enter the website URL (e.g., https://example.com): ")

    # Validate URL
    url = f"https://{domain}" if not re.match(r'^https?://', domain) else domain
    domain_name = urlparse(url).netloc

    # Perform the website check
    status, response_time, status_code, headers, body_snippet, security_headers, ssl_info, vulnerabilities = check_website(url)

    # Output the results
    print(f"\nWebsite: {domain_name}")
    print(f"Status: {status}")
    print(f"Response Time: {response_time} ms")
    print(f"Status Code: {status_code}")
    print(f"\nSSL Information: {ssl_info}")
    print(f"\nSecurity Headers: {security_headers}")
    print(f"\nVulnerabilities: {vulnerabilities}")
    print(f"\nResponse Snippet:\n{body_snippet}")

if __name__ == "__main__":
    main()
