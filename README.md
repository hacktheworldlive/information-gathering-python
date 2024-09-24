# information-gathering-with-Python

# Website Information Gathering Tool

This script is designed to gather comprehensive information about a specified website. It retrieves details such as the IP address, open ports, technologies used, WHOIS information, and SSL certificate details.

## Features

### Enhancements Made:

- **Logging**: Added logging functionality to provide better feedback on the script's actions and errors. This is crucial for debugging and tracking the script's execution.

- **Error Handling**: Improved error handling across functions to catch exceptions and log appropriate messages instead of just returning None.

- **Modular Functions**: Each major action is encapsulated in a function, promoting cleaner code and making it easier to maintain and expand.

- **SSL Certificate Details**: Enhanced the `get_certificate_details` function to provide clearer output, including the certificate's Common Name (CN) as a part of the issuer and subject information.

- **Port Scanning Range**: Made the port range configurable in the `scan_ports` function, defaulting to scanning the first 1024 ports for efficiency. You can easily change the range.

- **User Input Validation**: The main function checks for empty input and logs an error message.

## Requirements

Make sure you have the necessary Python packages installed:

```bash
pip install python-nmap builtwith python-whois pyOpenSSL


Additionally, ensure that you have nmap installed on your system. You can check the installation guide for your operating system.

Usage
Run the script in your terminal or command prompt.
Enter a valid URL when prompted (e.g., https://example.com).
This script will provide a comprehensive overview of the specified website's technical details and security aspects while maintaining a clean and organized structure.
