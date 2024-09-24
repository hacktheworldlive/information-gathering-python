import socket
import nmap
import builtwith
import whois
import ssl
import OpenSSL
import logging
from urllib.parse import urlparse

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_ip_address(domain):
    """Get the IP address of the domain."""
    try:
        ip = socket.gethostbyname(domain)
        logging.info(f"IP Address: {ip}")
        return ip
    except socket.gaierror as e:
        logging.error(f"Error resolving IP address for {domain}: {e}")
        return None

def scan_ports(ip, port_range='1-1024'):
    """Scan for open ports on the given IP."""
    nm = nmap.PortScanner()
    try:
        logging.info(f"Scanning ports {port_range} on {ip}...")
        nm.scan(ip, port_range)
        open_ports = [(port, nm[ip]['tcp'][port]['state']) for port in nm[ip]['tcp']]
        return open_ports
    except Exception as e:
        logging.error(f"Error scanning ports: {e}")
        return []

def get_technologies(url):
    """Get the technologies used by the website."""
    try:
        tech = builtwith.parse(url)
        logging.info("Technologies Used:")
        for key, value in tech.items():
            logging.info(f"{key}: {', '.join(value)}")
        return tech
    except Exception as e:
        logging.error(f"Error detecting technologies: {e}")
        return {}

def get_whois_info(domain):
    """Get WHOIS information for the domain."""
    try:
        info = whois.whois(domain)
        logging.info("WHOIS Information:")
        logging.info(info)
        return info
    except Exception as e:
        logging.error(f"Error fetching WHOIS info: {e}")
        return {}

def get_ssl_info(domain):
    """Get SSL certificate details for the domain."""
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5.0)
        conn.connect((domain, 443))
        ssl_info = conn.getpeercert()
        logging.info("SSL Information:")
        logging.info(ssl_info)
        return ssl_info
    except Exception as e:
        logging.error(f"Error fetching SSL info: {e}")
        return {}

def get_certificate_details(domain):
    """Get detailed information from the SSL certificate."""
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        cert_info = {
            "issuer": x509.get_issuer().CN,
            "subject": x509.get_subject().CN,
            "serial_number": x509.get_serial_number(),
            "version": x509.get_version(),
            "not_before": x509.get_notBefore().decode(),
            "not_after": x509.get_notAfter().decode(),
        }
        logging.info("Certificate Details:")
        for key, value in cert_info.items():
            logging.info(f"{key}: {value}")
        return cert_info
    except Exception as e:
        logging.error(f"Error getting certificate details: {e}")
        return {}

def main(url):
    """Main function to gather information about the website."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]

    logging.info(f"[+] Gathering information about {domain}")

    # Get IP address
    ip_address = get_ip_address(domain)

    # Get Open Ports
    if ip_address:
        open_ports = scan_ports(ip_address, '1-1024')  # Change the port range as needed
        if open_ports:
            logging.info("Open Ports:")
            for port, state in open_ports:
                logging.info(f"Port {port}: {state}")
        else:
            logging.info("No open ports found.")

    # Get Technologies Used
    get_technologies(url)

    # Get WHOIS Information
    get_whois_info(domain)

    # Get SSL Information
    get_ssl_info(domain)

    # Get Certificate Details
    get_certificate_details(domain)

if __name__ == "__main__":
    url_input = input("Enter the website URL (e.g., https://example.com): ").strip()
    if url_input:
        main(url_input)
    else:
        logging.error("No URL provided.")
