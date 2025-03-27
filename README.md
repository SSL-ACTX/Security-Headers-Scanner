<div align="center">

░█▀▀░█░█░░░░░█▀▀░█▀▀░█▀█░█▀█░█▀█░█▀▀░█▀▄  
░▀▀█░█▀█░░░░░▀▀█░█░░░█▀█░█░█░█░█░█▀▀░█▀▄  
░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀░▀░▀  
A simple tool to scan a website for security headers and generate a detailed report.
</div>

## 🚀 Features
- Fetches security headers report from `securityheaders.com`
- Displays security grades w/ ASCII art
- Provides a detailed table of security headers
- Summarizes security report and raw headers
- Uses `rich` for simple formatted CLI output

## 📦 Dependencies
Ensure you have the following installed:
- `python 3.x`
- `curl_cffi`
- `beautifulsoup4`
- `rich`

Install dependencies using:
```sh
pip install curl_cffi beautifulsoup4 rich
```

## 🔧 Usage
Run the script with a target website URL:
```sh
python main.py <website_url>
```
Example:
```sh
python main.py https://github.com
```
## 🖥️ Sample Output
```
🔍 SECURITY HEADERS REPORT

██████     
██   ██
██   ██
██   ██
██████

+-------------------------+------------+
| Header                  |   Status   |
+-------------------------+------------+
| Content-Security-Policy | ✅ Present |
| X-Frame-Options         | ❌ Missing |
+-------------------------+------------+

📊 Summary:
    ...
```

## 📜 License
This project is open-source and available under the [MIT License](LICENSE)

---
👨‍💻 Created by [SSL-ACTX (Seuriin)](https://github.com/SSL-ACTX/)

