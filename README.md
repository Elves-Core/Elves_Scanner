
# Elves Scanner 1.432

Elves Scanner 1.432 is a simple Python tool that checks for OWASP Top 10 vulnerabilities in web applications using basic HTTP requests and responses. This script uses the `requests` library to perform these checks.

## Features

- Checks for OWASP Top 10 vulnerabilities.
- Uses simple HTTP requests and responses.
- Easy to configure and extend with additional payloads.

## Requirements

- Python 3.x
- `requests` library

## Installation

1. Ensure you have Python installed on your system.
2. Install the `requests` library using pip:
   ```sh
   pip install requests
   ```

## Usage

1. Save the script as `Elves_Scanner_1.432.py`.
2. Run the script:
   ```sh
   python Elves_Scanner_1.432.py
   ```
3. Enter the target URL when prompted.

## Example

```python
import requests

# List of common test payloads and endpoints
payloads = {
    "SQL Injection": ["' OR '1'='1", "'; DROP TABLE users; --"],
    "Cross-Site Scripting (XSS)": ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"],
    "Cross-Site Request Forgery (CSRF)": ["<form action='http://example.com' method='POST'><input type='submit'></form>"],
    "Security Misconfiguration": ["/.git/config", "/.env", "/wp-config.php"],
    "Sensitive Data Exposure": ["/.htpasswd", "/.aws/credentials", "/.ssh/id_rsa"],
    "XML External Entities (XXE)": ["<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><foo>&xxe;</foo>"],
    "Broken Access Control": ["/admin", "/users", "/private"],
    "Insecure Deserialization": ["O:8:\"DataTest\":2:{s:4:\"name\";s:4:\"test\";s:3:\"age\";i:20;}"],
    "Using Components with Known Vulnerabilities": ["/vendor/jquery/jquery.min.js", "/node_modules/lodash/lodash.js"],
    "Insufficient Logging and Monitoring": ["/logs", "/debug", "/trace"]
}

def check_vulnerability(url, payload):
    try:
        response = requests.get(url + payload, timeout=5)
        if response.status_code == 200:
            return True, response.text
        else:
            return False, response.status_code
    except requests.RequestException as e:
        return False, str(e)

def main():
    target_url = input("Enter the target URL (e.g., http://example.com): ")

    for vuln_name, test_payloads in payloads.items():
        print(f"Checking for {vuln_name}...")
        for payload in test_payloads:
            is_vulnerable, result = check_vulnerability(target_url, payload)
            if is_vulnerable:
                print(f"Potential {vuln_name} detected with payload: {payload}")
                print(f"Response: {result[:200]}...")  # Print first 200 chars of response
            else:
                print(f"No {vuln_name} vulnerability detected with payload: {payload}")

if __name__ == "__main__":
    main()
```

## Version

- 1.432
- Date: 2009 to 2024

## License

This project is licensed under the MIT License.
