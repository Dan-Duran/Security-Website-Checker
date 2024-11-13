# Security Website Checker

This Python terminal-based utility checks a website's status, response time, Cloudflare protection, security headers, SSL certificate information, and potential vulnerabilities. It provides essential insights for quick website security assessments.

- **👉 Checkout some more awesome tools at [GetCyber](https://getcyber.me/tools)**
- **👉 Subscribe to my YouTube Channel [GetCyber - YouTube](https://youtube.com/getCyber)**
- **👉 Discord Server [GetCyber - Discord](https://discord.gg/YUf3VpDeNH)**

## Features

- Website status and response time
- Cloudflare protection detection (strict or permissive)
- SSL/TLS certificate information
- Security headers inspection
- Vulnerability detection (server info leaks, insecure cookies, clickjacking risks)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Dan-Duran/Security-Website-Checker.git
cd Security-Website-Checker
```

### 2. Create a Virtual Environment

It is recommended to create a virtual environment to manage dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Linux/macOS
# For Windows
# .venv\Scripts\activate
```

### 3. Install Dependencies

Once the virtual environment is activated, install the required Python libraries:

```bash
pip install -r requirements.txt
```

## Usage

To run the utility, execute the Python script and enter the website URL when prompted:

```bash
python website_checker.py
```

The script will output:

- Website status (up/down)
- Response time
- HTTP status code
- Detected Cloudflare protection (strict or permissive)
- Security headers
- SSL/TLS certificate information
- Detected vulnerabilities

### Example:

```bash
Enter the website URL (e.g., https://example.com): https://example.com
```

## Dependencies

- `requests`: For HTTP requests and response handling
- `cryptography`: For SSL/TLS certificate inspection
- `urllib.parse`: For URL parsing
- `socket`, `ssl`: For establishing secure connections

You can install all dependencies using the `requirements.txt` file.

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

This software is provided for educational and informational purposes only. Use this tool responsibly and in compliance with all applicable laws. The developer assumes no responsibility for any consequences resulting from its use. The information retrieved by this tool should not be used for malicious purposes or activities that could cause harm to any entities.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
