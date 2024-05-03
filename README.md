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

## Installation

1. Ensure you have Python installed on your system. You can download it from [Python's official website](https://www.python.org/downloads/).
2. Clone this repository to your local machine using Git:
   ```bash
   git clone https://github.com/0xMiSHR4/W3B_SC4NN3R
   ```
3. Navigate to the cloned directory:
   ```bash
   cd W3B_SC4NN3R
   ```
4. Install the required Python libraries using pip:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the script with the following command-line arguments:
```bash
python3 W3B_SC4NN3R.py <target_url> [-t <timeout>]
```
Replace `<target_url>` with the URL of the website you want to scan.
Optionally, specify the timeout (in seconds) for each request using `-t`.

## Example

```bash
python3 W3B_SC4NN3R.py https://www.google.com/ -t 5
```

## Output
The tool generates a detailed vulnerability scan report in a text file named after the target URL.

## Disclaimer

This script is intended for educational and testing purposes only. Use it responsibly and only on web applications you have permission to test. The authors assume no liability for any misuse or damage caused by this script.

## Contribution

Contributions are welcome! If you find a bug or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
