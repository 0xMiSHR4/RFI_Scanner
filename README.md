# W3B_SC4NN3R

# Introduction
W3B_SC4NN3R is a Python tool designed for scanning websites to identify common vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), Remote Code Execution (RCE), Security Misconfiguration, Broken Authentication, and Cross-Site Request Forgery (CSRF).

## Features
- Detects SQL Injection vulnerabilities using predefined payloads.
- Identifies XSS vulnerabilities in forms with customizable payloads.
- Checks for Remote Code Execution vulnerabilities using potential command injection payloads.
- Detects Security Misconfigurations related to server software versions, frameworks, and insecure cookies.
- Identifies Broken Authentication by testing login forms with default credentials.
- Checks for CSRF vulnerabilities by sending POST requests with test data.

## Requirements
- Python 3.x
- Requests library
- Beautiful Soup 4 (bs4) library
- PyFiglet library (for ASCII banners)

## Disclaimer

This script is intended for educational and testing purposes only. Use it responsibly and only on web applications you have permission to test. The authors assume no liability for any misuse or damage caused by this script.

## Contribution

Contributions are welcome! If you find a bug or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
