import requests
from bs4 import BeautifulSoup
import socket
import re
import whois
import dns.resolver
import argparse

common_ports = [21,22,23,25,53,80,110,119,123,143,161,194,443,445,993,995]

def load_wordlist():
    wordlist = []
    try:
        file = open("subdomains_wordlist.txt", "r", encoding="utf-8")
        for khat in file:
            khat = khat.strip()
            if khat != "":
                wordlist.append(khat)
        file.close()
    except:
        print("Error reading file: subdomains_wordlist.txt")
    return wordlist
subdomains_wordlist = load_wordlist()

def simple_sitemap(url):
    links = []
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            tags = soup.find_all("a")
            for tag in tags:
                if tag.has_attr("href"):
                    href = tag["href"]
                    if href.startswith("/"):
                        full = url.rstrip("/") + href
                    elif href.startswith(url):
                        full = href
                    else:
                        continue
                    if full not in links:
                        links.append(full)
        # مرحله دوم
        temp_links = links.copy()
        for link in temp_links:
            try:
                r2 = requests.get(link, timeout=5)
                if r2.status_code == 200:
                    soup2 = BeautifulSoup(r2.text, "html.parser")
                    tags2 = soup2.find_all("a")
                    for tag2 in tags2:
                        if tag2.has_attr("href"):
                            href2 = tag2["href"]
                            if href2.startswith("/"):
                                full2 = url.rstrip("/") + href2
                            elif href2.startswith(url):
                                full2 = href2
                            else:
                                continue
                            if full2 not in links:
                                links.append(full2)
            except:
                pass
    except:
        print("خطا در اتصال به سایت")
    return links

def find_subdomains(domain):
    found = []
    for i in subdomains_wordlist:
        full = i + "." + domain
        try:
            result = dns.resolver.resolve(full, 'A')
            if full not in found:
                found.append(full)
        except:
            pass
    return found

def check_status_and_title(subdomains, protocol="https://"):
    result = {}
    for i in subdomains:
        full = protocol + i
        try:
            r = requests.get(full, timeout=3)
            status_code = r.status_code
            soup = BeautifulSoup(r.text, "html.parser")
            title_tag = soup.title
            if title_tag is not None and title_tag.string is not None:
                title = title_tag.string.strip()
            else:
                title = "No title"
            result[i] = (status_code, title)
        except:
            result[i] = ("No response", "No title")
    return result

def get_ip_of_subdomains(subdomains):
    result = {}
    for i in subdomains:
        try:
            ip = socket.gethostbyname(i)
            result[i] = ip
        except:
            result[i] = "Unknown"
    return result

def scan_ports_on_ips(ip_list):
    open_ports = {}
    for ip in ip_list:
        open_ports[ip] = []
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                sock.connect((ip, port))
                open_ports[ip].append(port)
            except:
                pass
            sock.close()
    return open_ports

def extract_emails_phones_ip(subdomains, protocol="https://"):
    result = {}
    email_regex = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    phone_regex = r"\+?\d[\d\s-]{7,}\d"
    for i in subdomains:
        url = protocol + i
        emails = []
        phones = []
        ip = "Unknown"
        try:
            ip = socket.gethostbyname(i)
        except:
            pass
        try:
            response = requests.get(url, timeout=3)
            text = response.text
            emails = re.findall(email_regex, text)
            phones = re.findall(phone_regex, text)
        except:
            pass
        result[i] = (emails, phones, ip)
    return result

def perform_whois(domain):
    try:
        w = whois.whois(domain)
        name = w.get("name")
        emails = w.get("emails")
        creation = w.get("creation_date")
        expiration = w.get("expiration_date")
        text = "Registrant Name: " + str(name) + "\n"
        text += "Contact Email(s): " + str(emails) + "\n"
        text += "Creation Date: " + str(creation) + "\n"
        text += "Expiration Date: " + str(expiration) + "\n"
        return text
    except:
        return "Error fetching WHOIS info"

def save_report_txt(filename, sitemap_links, subdomains, subdomains_info, subdomains_ip, ip_open_ports, contacts, whois_info, found_files):
    try:
        f = open(filename, "w", encoding="utf-8")
        f.write("گزارش ابزار ReconPy\n\n")

        f.write("=== لینک‌های سایت‌مپ ===\n")
        for link in sitemap_links:
            f.write("- " + link + "\n")
        f.write("\n")

        f.write("=== ساب‌دامین‌های شناسایی‌شده ===\n")
        for sub in subdomains:
            f.write("- " + sub + "\n")
        f.write("\n")

        f.write("=== وضعیت ساب‌دامین‌ها و عنوان صفحات ===\n")
        for sub in subdomains_info:
            status = subdomains_info[sub][0]
            title = subdomains_info[sub][1]
            f.write("- " + sub + " | وضعیت: " + str(status) + " | عنوان: " + title + "\n")
        f.write("\n")

        f.write("=== IP هر ساب‌دامین ===\n")
        for sub in subdomains_ip:
            f.write("- " + sub + " -> " + subdomains_ip[sub] + "\n")
        f.write("\n")

        f.write("=== پورت‌های باز هر IP ===\n")
        for ip in ip_open_ports:
            ports = ip_open_ports[ip]
            if len(ports) > 0:
                ports_str = ""
                for p in ports:
                    ports_str += str(p) + ", "
                ports_str = ports_str.rstrip(", ")
                f.write("- " + ip + " -> پورت‌های باز: " + ports_str + "\n")
            else:
                f.write("- " + ip + " -> پورت باز پیدا نشد\n")
        f.write("\n")

        f.write("=== ایمیل‌ها، شماره‌تلفن‌ها و IP ===\n")
        for sub in contacts:
            emails = contacts[sub][0]
            phones = contacts[sub][1]
            ip = contacts[sub][2]
            f.write("[" + sub + "] (IP: " + ip + ")\n")
            f.write("ایمیل‌ها:\n")
            if len(emails) > 0:
                for email in emails:
                    f.write("  - " + email + "\n")
            else:
                f.write("  - پیدا نشد\n")
            f.write("شماره‌تلفن‌ها:\n")
            if len(phones) > 0:
                for phone in phones:
                    f.write("  - " + phone + "\n")
            else:
                f.write("  - پیدا نشد\n")
            f.write("-" * 40 + "\n")
        f.write("\n")

        f.write("=== اطلاعات WHOIS ===\n")
        f.write(whois_info + "\n")

        f.write("=== فایل‌های یافت‌شده ===\n")
        for file_url in found_files:
            f.write("- " + file_url + "\n")
        f.write("\n")

        f.close()
    except:
        print("Error saving report")

def main():
    parser = argparse.ArgumentParser(description="ReconPy - Information Gathering Tool")
    parser.add_argument("-d", "--domain", help="Domain name (e.g. example.com)")
    parser.add_argument("-m", "--modules", nargs="+", help="Modules to run like m1 m2 m3 ...")
    args = parser.parse_args()

    if args.domain == None or args.modules == None:
        print("Please provide both -d (domain) and -m (modules) arguments.")
        parser.print_help()
        return

    domain = args.domain.strip()
    protocol = "https://"
    url = protocol + domain

    sitemap_links = []
    subdomains = []
    subdomains_info = {}
    subdomains_ip = {}
    ip_open_ports = {}
    contacts = {}
    whois_info = ""
    found_files = []

    for module in args.modules:
        if module == "m1":
            print("\nextracting sitemap ...")
            sitemap_links = simple_sitemap(url)
            for link in sitemap_links:
                print(link)

        elif module == "m2":
            print("\nfinding subdomains ...")
            subdomains = find_subdomains(domain)
            for sub in subdomains:
                print(sub)

        elif module == "m3":
            if len(subdomains) == 0:
                subdomains = find_subdomains(domain)
            print("\ngetting HTTP status and titles ...")
            subdomains_info = check_status_and_title(subdomains, protocol)
            for sub in subdomains_info:
                code = subdomains_info[sub][0]
                title = subdomains_info[sub][1]
                print(sub + " - Status Code: " + str(code) + " - Title: " + title)

        elif module == "m4":
            if len(subdomains) == 0:
                subdomains = find_subdomains(domain)
            print("\ngetting IPs of subdomains ...")
            subdomains_ip = get_ip_of_subdomains(subdomains)
            for sub in subdomains_ip:
                print(sub + " -> " + subdomains_ip[sub])

        elif module == "m5":
            if len(subdomains_ip) == 0:
                if len(subdomains) == 0:
                    subdomains = find_subdomains(domain)
                subdomains_ip = get_ip_of_subdomains(subdomains)
            ips = []
            for ip_val in subdomains_ip.values():
                if ip_val not in ips:
                    ips.append(ip_val)
            print("\nscanning common ports ...")
            ip_open_ports = scan_ports_on_ips(ips)
            for ip in ip_open_ports:
                ports = ip_open_ports[ip]
                if len(ports) > 0:
                    ports_str = ""
                    for p in ports:
                        ports_str += str(p) + ", "
                    ports_str = ports_str.rstrip(", ")
                    print(ip + " - Open ports: " + ports_str)
                else:
                    print(ip + " - No open ports found.")

        elif module == "m6":
            if len(subdomains) == 0:
                subdomains = find_subdomains(domain)
            print("\nextracting emails, phones, and IPs ...")
            contacts = extract_emails_phones_ip(subdomains, protocol)
            for sub in contacts:
                emails = contacts[sub][0]
                phones = contacts[sub][1]
                ip = contacts[sub][2]
                print(f"{sub} (IP: {ip})")
                print("Emails:")
                if len(emails) > 0:
                    for e in emails:
                        print(" - " + e)
                else:
                    print(" - None found")
                print("Phones:")
                if len(phones) > 0:
                    for p in phones:
                        print(" - " + p)
                else:
                    print(" - None found")
                print("-" * 40)

        elif module == "m7":
            print("\nperforming WHOIS lookup ...")
            whois_info = perform_whois(domain)
            print(whois_info)

        elif module == "m8":
            print("\nsearching for common files ...")
            common_files = ["robots.txt", "sitemap.xml", ".env", "config.php", "backup.zip", "admin.php"]
            found_files = []
            for file in common_files:
                full_url = url.rstrip("/") + "/" + file
                try:
                    r = requests.get(full_url, timeout=3)
                    if r.status_code == 200:
                        found_files.append(full_url)
                        print("Found: " + full_url)
                except:
                    pass
        else:
            print(f"Unknown module: {module}")

    # ذخیره گزارش در فایل
    save_report_txt("reconpy_report.txt", sitemap_links, subdomains, subdomains_info, subdomains_ip, ip_open_ports, contacts, whois_info, found_files)
    print("\report saved to reconpy_report.txt")

main()