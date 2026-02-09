#!/usr/bin/env python3

##############################################################################################
## sendEmail - Python3-Implementation
## Originally Written by: Brandon Zehm <caspian@dotconf.net>
## Modifications by: MegaV0lt @ github.com
##  - Convert original sendEmail.pl to Python 3
##  - Use Python's built-in email and mimetypes modules for message construction 
##      and MIME type detection 
##############################################################################################
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 2 of the License, or
## (at your option) any later version.
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
## GNU General Public License for more details.
## You should have received a copy of the GNU General Public License
## along with this program. If not, see <http://www.gnu.org/licenses/>.
##############################################################################################

import sys
import os
import base64
import socket
import ssl
import getpass
import re
import random
import string
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import mimetypes
import argparse
import logging

# Global variables
CRLF = "\r\n"
PROGRAM_NAME = os.path.basename(sys.argv[0])
VERSION = "1.56.2-tls1.2-dsn-python3"
AUTHOR_NAME = "Brandon Zehm"
AUTHOR_EMAIL = "caspian@dotconf.net"
TIMEZONE = "+0000"

# Color codes
class Colors:
    RED = "\033[31;1m"
    GREEN = "\033[32;1m"
    CYAN = "\033[36;1m"
    WHITE = "\033[37;1m"
    NORMAL = "\033[m"
    BOLD = "\033[1m"
    NO_BOLD = "\033[0m"
    
    @staticmethod
    def disable():
        Colors.RED = Colors.GREEN = Colors.CYAN = Colors.WHITE = ""
        Colors.NORMAL = Colors.BOLD = Colors.NO_BOLD = ""

# Disable colors on Windows
if sys.platform.startswith('win'):
    Colors.disable()

class Config:
    def __init__(self):
        self.server = 'localhost'
        self.port = 25
        self.bindaddr = ''
        self.timeout = 60
        self.tls = 'auto'
        self.username = ''
        self.password = ''
        self.fqdn = self._get_hostname(fqdn=True)
        self.hostname = self.fqdn.split('.')[0]
        self.debug = 0
        self.stdout = True
        self.logfile = ''
        self.logging = False
        self.dsnopts = ''
        self.dsnid = self._generate_random_string(16)
        self.message_id = f"{random.randint(1, 1000000)}-sendEmail"
        self.delimiter = f"----MIME delimiter for sendEmail-{random.randint(1, 1000000)}"
        self.tls_client = True
        self.tls_server = True
        self.error = ''
        self.smtp_response = ''
        self.socket = None
        self.ip = ''
        self.timezone = '+0000'
    
    def _get_hostname(self, fqdn=False):
        """Get system hostname"""
        try:
            import socket
            hostname = socket.getfqdn()
            if not fqdn:
                hostname = hostname.split('.')[0]
            return hostname.lower()
        except:
            return 'localhost'
    
    def _generate_random_string(self, length):
        """Generate random string of specified length"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

class EmailSender:
    def __init__(self, config):
        self.conf = config
        self.sender = ''
        self.to_addresses = []
        self.cc_addresses = []
        self.bcc_addresses = []
        self.subject = ''
        self.message = ''
        self.attachments = []
        self.reply_to = ''
        self.message_charset = 'iso-8859-1'
        self.message_content_type = 'auto'
        self.message_format = 'normal'
        self.message_header = ''
        self.logger = None
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging"""
        self.logger = logging.getLogger('sendEmail')
        self.logger.setLevel(logging.DEBUG)
        
        if not self.logger.handlers:
            if self.conf.logging and self.conf.logfile:
                handler = logging.FileHandler(self.conf.logfile)
                handler.setLevel(logging.DEBUG)
                formatter = logging.Formatter('%(asctime)s %(name)s: %(message)s')
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
    
    def printmsg(self, message, level=0):
        """Print message with debug level"""
        if self.conf.debug >= level:
            if self.conf.stdout or self.conf.debug >= 1:
                print(message)
            if self.conf.logging and self.conf.logfile:
                self.logger.info(message)
    
    def quit(self, message='', error_level=0):
        """Exit program"""
        if message:
            self.printmsg(message)
        sys.exit(error_level)
    
    def parse_address(self, address):
        """Parse email address into name and address parts"""
        if not address:
            return None, None
        
        # Check for format: "Name" <address@domain.com>
        match = re.match(r'^\s*(\S(?:.*\S)?)\s*<(\S+@\S+)>\s*$', address)
        if match:
            return match.group(1), match.group(2)
        
        # Check for format: <address@domain.com>
        match = re.search(r'<(\S+@\S+)>', address)
        if match:
            return match.group(1), match.group(1)
        
        # Check for format: address@domain.com
        match = re.search(r'(\S+@\S+)', address)
        if match:
            return match.group(1), match.group(1)
        
        self.printmsg(f"ERROR => Can't parse address: {address}", 0)
        return None, None
    
    def validate_address(self, address):
        """Validate email address"""
        name, addr = self.parse_address(address)
        if name and addr:
            return True
        return False
    
    def validate_addresses(self, addresses):
        """Validate list of email addresses"""
        for addr in addresses:
            if addr and not self.validate_address(addr):
                self.printmsg(f"ERROR => Invalid email address: {addr}", 0)
                return False
        return True
    
    def validate_files(self, files):
        """Validate that attachment files exist and are readable"""
        for file_path in files:
            if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
                self.printmsg(f"ERROR => File not found or not readable: {file_path}", 0)
                return False
        return True
    
    def get_mime_type(self, filename):
        """Detect MIME type based on file extension using Python's mimetypes module"""
        mime_type, _ = mimetypes.guess_type(filename)
        return mime_type or 'application/octet-stream'
    
    def connect_to_server(self):
        """Connect to SMTP server"""
        self.printmsg(f"DEBUG => Connecting to {self.conf.server}:{self.conf.port}", 1)
        
        try:
            self.conf.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conf.socket.settimeout(self.conf.timeout)
            
            if self.conf.bindaddr:
                self.conf.socket.bind((self.conf.bindaddr, 0))
            
            self.conf.socket.connect((self.conf.server, self.conf.port))
            self.conf.ip = self.conf.socket.getsockname()[0]
            self.printmsg(f"DEBUG => My IP address is: {self.conf.ip}", 1)
            
            return True
        except Exception as e:
            self.printmsg(f"ERROR => Connection to {self.conf.server}:{self.conf.port} failed: {e}", 0)
            return False
    
    def send_command(self, command=''):
        """Send SMTP command and get response"""
        try:
            if command:
                self.printmsg(f"INFO => Sending: {command}", 1)
                self.conf.socket.sendall((command + CRLF).encode())
            
            response = self._read_response()
            self.conf.smtp_response = response
            
            # Evaluate response
            match = re.match(r'^([23]\d\d)', response)
            if match:
                self.conf.error = f"SUCCESS => Received: {response}"
                self.printmsg(self.conf.error, 1)
                return 0
            
            match = re.match(r'^([45]\d\d)', response)
            if match:
                self.conf.error = f"ERROR => Received: {response}"
                self.printmsg(self.conf.error, 0)
                return int(match.group(1))
            
            self.conf.error = f"ERROR => Invalid response: {response}"
            return 1
        
        except socket.timeout:
            self.conf.error = f"ERROR => Timeout while reading from {self.conf.server}:{self.conf.port}"
            self.printmsg(self.conf.error, 0)
            return 1
        except Exception as e:
            self.conf.error = f"ERROR => {e}"
            self.printmsg(self.conf.error, 0)
            return 1
    
    def _read_response(self):
        """Read SMTP response from server"""
        response = b''
        try:
            while True:
                data = self.conf.socket.recv(1024)
                if not data:
                    break
                response += data
                if response.endswith(b'\r\n'):
                    break
            return response.decode().strip()
        except:
            return ''
    
    def start_tls(self):
        """Start TLS connection"""
        try:
            if self.send_command('STARTTLS'):
                return False
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            self.conf.socket = context.wrap_socket(
                self.conf.socket,
                server_hostname=self.conf.server
            )
            
            self.printmsg("DEBUG => TLS session initialized :)", 1)
            return True
        except Exception as e:
            self.printmsg(f"ERROR => TLS setup failed: {e}", 0)
            return False
    
    def smtp_auth_login(self):
        """SMTP authentication using LOGIN method"""
        try:
            if self.send_command('AUTH LOGIN'):
                return False
            
            username_b64 = base64.b64encode(self.conf.username.encode()).decode()
            if self.send_command(username_b64):
                return False
            
            password_b64 = base64.b64encode(self.conf.password.encode()).decode()
            if self.send_command(password_b64):
                return False
            
            self.printmsg("DEBUG => User authentication was successful (Method: LOGIN)", 1)
            return True
        except:
            return False
    
    def smtp_auth_plain(self):
        """SMTP authentication using PLAIN method"""
        try:
            auth_string = f"{self.conf.username}\0{self.conf.username}\0{self.conf.password}"
            auth_b64 = base64.b64encode(auth_string.encode()).decode()
            
            if self.send_command(f'AUTH PLAIN {auth_b64}'):
                return False
            
            self.printmsg("DEBUG => User authentication was successful (Method: PLAIN)", 1)
            return True
        except:
            return False
    
    def send_email(self):
        """Main email sending function"""
        # Validate inputs
        if not self.sender:
            self.quit("ERROR => You must specify a 'from' field!", 1)
        
        if not (self.to_addresses or self.cc_addresses or self.bcc_addresses):
            self.quit("ERROR => You must specify at least one recipient!", 1)
        
        if not self.message:
            self.quit("ERROR => You must specify a message body!", 1)
        
        # Validate all addresses
        all_addrs = [self.sender] + self.to_addresses + self.cc_addresses + self.bcc_addresses
        if self.reply_to:
            all_addrs.append(self.reply_to)
        
        if not self.validate_addresses(all_addrs):
            self.quit("ERROR => Invalid email address detected!", 1)
        
        # Validate attachment files
        if not self.validate_files(self.attachments):
            self.quit("ERROR => Invalid attachment file!", 1)
        
        # Connect to server
        if not self.connect_to_server():
            self.quit("ERROR => Failed to connect to SMTP server!", 1)
        
        # Read initial greeting
        response = self._read_response()
        self.conf.smtp_response = response
        self.printmsg(f"INFO => {response}", 1)
        
        # EHLO
        if self.send_command(f'EHLO {self.conf.fqdn}'):
            self.printmsg("NOTICE => EHLO failed, trying HELO", 0)
            if self.send_command(f'HELO {self.conf.fqdn}'):
                self.quit("ERROR => HELO failed!", 1)
        else:
            # Check for TLS support
            if 'STARTTLS' in self.conf.smtp_response:
                self.conf.tls_server = True
                self.printmsg("DEBUG => Server supports TLS", 2)
                
                # Start TLS if enabled
                if self.conf.tls in ['auto', 'yes'] and self.conf.tls_client:
                    if self.start_tls():
                        # Re-EHLO after TLS
                        if self.send_command(f'EHLO {self.conf.fqdn}'):
                            self.quit("ERROR => EHLO failed after TLS!", 1)
                    else:
                        if self.conf.tls == 'yes':
                            self.quit("ERROR => TLS required but startup failed!", 1)
            else:
                self.conf.tls_server = False
                self.printmsg("DEBUG => Server does NOT support TLS", 2)
            
            # SMTP Authentication
            if self.conf.username and self.conf.password:
                if 'AUTH' not in self.conf.smtp_response:
                    self.printmsg("NOTICE => Authentication not supported by server", 0)
                else:
                    auth_success = False
                    if 'LOGIN' in self.conf.smtp_response and not auth_success:
                        auth_success = self.smtp_auth_login()
                    
                    if 'PLAIN' in self.conf.smtp_response and not auth_success:
                        auth_success = self.smtp_auth_plain()
                    
                    if not auth_success:
                        self.quit("ERROR => Authentication failed!", 1)
        
        # MAIL FROM
        from_addr = self.parse_address(self.sender)[1]
        dsn_opts = ''
        if self.conf.dsnopts:
            dsn_opts = f' RET=HDRS ENVID={self.conf.dsnid}' if self.conf.dsnid else ' RET=HDRS'
        
        if self.send_command(f'MAIL FROM:<{from_addr}>{dsn_opts}'):
            self.quit("ERROR => MAIL FROM failed!", 1)
        
        # RCPT TO
        rcpt_accepted = 0
        for rcpt in self.to_addresses + self.cc_addresses + self.bcc_addresses:
            rcpt_addr = self.parse_address(rcpt)[1]
            rcpt_dsn = f' {self.conf.dsnopts}' if self.conf.dsnopts else ''
            
            if self.send_command(f'RCPT TO:<{rcpt_addr}>{rcpt_dsn}'):
                self.printmsg(f"WARNING => Recipient {rcpt_addr} was rejected", 0)
            else:
                rcpt_accepted += 1
        
        if rcpt_accepted == 0:
            self.quit("ERROR => No recipients were accepted!", 1)
        
        # DATA
        if self.send_command('DATA'):
            self.quit("ERROR => DATA command failed!", 1)
        
        # Send message
        self._send_message()
        
        # End data
        self.conf.socket.sendall(f"{CRLF}.{CRLF}".encode())
        if self.send_command():
            self.quit("ERROR => Failed to send message!", 1)
        
        # QUIT
        self.conf.socket.sendall(f"QUIT{CRLF}".encode())
        self.conf.socket.close()
        
        self.quit("Email was sent successfully!", 0)
    
    def _send_message(self):
        """Build and send message body"""
        if self.message_format == 'raw':
            self.conf.socket.sendall(self.message.encode())
        else:
            # Build headers
            headers = ''
            
            if 'Message-ID:' not in self.message_header:
                headers += f'Message-ID: <{self.conf.message_id}@{self.conf.hostname}>{CRLF}'
            
            name, addr = self.parse_address(self.sender)
            if self.sender and 'From:' not in self.message_header:
                headers += f'From: "{name}" <{addr}>{CRLF}'
            
            if self.reply_to and 'Reply-To:' not in self.message_header:
                name, addr = self.parse_address(self.reply_to)
                headers += f'Reply-To: "{name}" <{addr}>{CRLF}'
            
            if 'To:' not in self.message_header and self.to_addresses:
                headers += 'To:'
                for i, to_addr in enumerate(self.to_addresses):
                    name, addr = self.parse_address(to_addr)
                    comma = ',' if i < len(self.to_addresses) - 1 else ''
                    headers += f' "{name}" <{addr}>{comma}{CRLF}'
            elif not self.to_addresses:
                headers += f'To: "Undisclosed Recipients" <>{CRLF}'
            
            if self.cc_addresses and 'Cc:' not in self.message_header:
                headers += 'Cc:'
                for i, cc_addr in enumerate(self.cc_addresses):
                    name, addr = self.parse_address(cc_addr)
                    comma = ',' if i < len(self.cc_addresses) - 1 else ''
                    headers += f' "{name}" <{addr}>{comma}{CRLF}'
            
            if 'Subject:' not in self.message_header:
                headers += f'Subject: {self.subject}{CRLF}'
            
            if 'Date:' not in self.message_header:
                now = datetime.now()
                date_str = now.strftime("%a, %d %b %Y %H:%M:%S") + f' {self.conf.timezone}'
                headers += f'Date: {date_str}{CRLF}'
            
            if 'X-Mailer:' not in self.message_header:
                headers += f'X-Mailer: sendEmail-{VERSION}{CRLF}'
            
            headers += f'MIME-Version: 1.0{CRLF}'
            content_type = 'multipart/mixed' if self.attachments else 'multipart/related'
            headers += f'Content-Type: {content_type}; boundary="{self.conf.delimiter}"{CRLF}'
            
            if self.message_header:
                headers += self.message_header
            
            # Send headers
            self.conf.socket.sendall(headers.encode())
            self.conf.socket.sendall(f'{CRLF}{CRLF}'.encode())
            
            # Send body
            msg_body = f'This is a multi-part message in MIME format.{CRLF}{CRLF}'
            msg_body += f'--{self.conf.delimiter}{CRLF}'
            
            if self.message_content_type == 'html' or (self.message_content_type == 'auto' and self.message.lstrip().startswith('<')):
                msg_body += f'Content-Type: text/html;{CRLF}'
            else:
                msg_body += f'Content-Type: text/plain;{CRLF}'
            
            msg_body += f'        charset="{self.message_charset}"{CRLF}'
            msg_body += f'Content-Transfer-Encoding: 7bit{CRLF}{CRLF}'
            msg_body += self.message
            
            self.conf.socket.sendall(msg_body.encode())
            
            # Send attachments
            if self.attachments:
                for attachment in self.attachments:
                    self._send_attachment(attachment)
            
            # End message
            self.conf.socket.sendall(f'{CRLF}--{self.conf.delimiter}--{CRLF}'.encode())
    
    def _send_attachment(self, filepath):
        """Send file attachment"""
        try:
            filename = os.path.basename(filepath)
            mime_type = self.get_mime_type(filename)
            
            attachment_header = f'{CRLF}--{self.conf.delimiter}{CRLF}'
            attachment_header += f'Content-Type: {mime_type};{CRLF}'
            attachment_header += f'        name="{filename}"{CRLF}'
            attachment_header += f'Content-Transfer-Encoding: base64{CRLF}'
            attachment_header += f'Content-Disposition: attachment; filename="{filename}"{CRLF}{CRLF}'
            
            self.conf.socket.sendall(attachment_header.encode())
            
            # Read and encode file
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            encoded_data = base64.b64encode(file_data).decode()
            
            # Send in chunks of 76 characters
            for i in range(0, len(encoded_data), 76):
                self.conf.socket.sendall((encoded_data[i:i+76] + CRLF).encode())
        
        except Exception as e:
            self.printmsg(f"ERROR => Failed to attach file {filepath}: {e}", 0)

def show_help():
    """Display main help message with colors"""
    print(f"\n{Colors.BOLD}{PROGRAM_NAME}-{VERSION} by {AUTHOR_NAME} <{AUTHOR_EMAIL}>{Colors.NO_BOLD}\n")
    print(f"Synopsis:  {PROGRAM_NAME} -f ADDRESS [options]\n")
    
    print(f"  {Colors.RED}Required:{Colors.NORMAL}")
    print(f"    -f ADDRESS                from (sender) email address")
    print(f"    * At least one recipient required via -t, -cc, or -bcc")
    print(f"    * Message body required via -m, STDIN, or -o message-file=FILE\n")
    
    print(f"  {Colors.GREEN}Common:{Colors.NORMAL}")
    print(f"    -t ADDRESS [ADDR ...]     to email address(es)")
    print(f"    -u SUBJECT                message subject")
    print(f"    -m MESSAGE                message body")
    print(f"    -s SERVER[:PORT]          smtp mail relay, default is localhost:25\n")
    
    print(f"  {Colors.GREEN}Optional:{Colors.NORMAL}")
    print(f"    -a   FILE [FILE ...]      file attachment(s)")
    print(f"    -cc  ADDRESS [ADDR ...]   cc  email address(es)")
    print(f"    -bcc ADDRESS [ADDR ...]   bcc email address(es)")
    print(f"    -xu  USERNAME             username for SMTP authentication")
    print(f"    -xp  PASSWORD             password for SMTP authentication\n")
    
    print(f"  {Colors.GREEN}Paranormal:{Colors.NORMAL}")
    print(f"    -b BINDADDR[:PORT]        local host bind address")
    print(f"    -l LOGFILE                log to the specified file")
    print(f"    -v                        verbosity, use multiple times for greater effect")
    print(f"    -q                        be quiet (i.e. no STDOUT output)")
    print(f"    -o NAME=VALUE             advanced options, for details try: --help misc")
    print(f"        -o message-content-type=<auto|text|html>")
    print(f"        -o message-file=FILE         -o message-format=raw")
    print(f"        -o message-header=HEADER     -o message-charset=CHARSET")
    print(f"        -o reply-to=ADDRESS          -o timeout=SECONDS")
    print(f"        -o username=USERNAME         -o password=PASSWORD")
    print(f"        -o tls=<auto|yes|no>         -o fqdn=FQDN\n")
    
    print(f"  {Colors.GREEN}Extra:{Colors.NORMAL}")
    print(f"    -dsn [OPTIONS]            enable Delivery Status Notification (DSN)")
    print(f"                              DSN options: (S)uccess, (F)ailure, (D)elay")
    print(f"                              default value for OPTIONS is 'sfd'")
    print(f"    -dsnid [ID]               envelope ID for DSN requests, default is random\n")
    
    print(f"  {Colors.GREEN}Help:{Colors.NORMAL}")
    print(f"    --help                    the helpful overview you're reading now")
    print(f"    --help addressing         explain addressing and related options")
    print(f"    --help message            explain message body input and related options")
    print(f"    --help networking         explain -s, -b, etc")
    print(f"    --help output             explain logging and other output options")
    print(f"    --help misc               explain -o options, TLS, SMTP auth, and more\n")
    sys.exit(0)

def show_help_topic(topic):
    """Display help for a specific topic with colors"""
    if topic == 'addressing':
        print(f"\n{Colors.BOLD}ADDRESSING DOCUMENTATION{Colors.NORMAL}\n")
        
        print(f"{Colors.GREEN}Addressing Options{Colors.NORMAL}")
        print(f"Options related to addressing:")
        print(f"    -f   ADDRESS")
        print(f"    -t   ADDRESS [ADDRESS ...]")
        print(f"    -cc  ADDRESS [ADDRESS ...]")
        print(f"    -bcc ADDRESS [ADDRESS ...]")
        print(f"    -o   reply-to=ADDRESS\n")
        
        print(f"-f ADDRESS")
        print(f"    This required option specifies who the email is from, I.E. the sender's")
        print(f"    email address.\n")
        
        print(f"-t ADDRESS [ADDRESS ...]")
        print(f"    This option specifies the primary recipient(s).  At least one recipient")
        print(f"    address must be specified via the -t, -cc. or -bcc options.\n")
        
        print(f"-cc ADDRESS [ADDRESS ...]")
        print(f"    This option specifies the \"carbon copy\" recipient(s).  At least one")
        print(f"    recipient address must be specified via the -t, -cc. or -bcc options.\n")
        
        print(f"-bcc ADDRESS [ADDRESS ...]")
        print(f"    This option specifies the \"blind carbon copy\" recipient(s).  At least")
        print(f"    one recipient address must be specified via the -t, -cc. or -bcc options.\n")
        
        print(f"-o reply-to=ADDRESS")
        print(f"    This option specifies that an optional \"Reply-To\" address should be")
        print(f"    written in the email's headers.\n")
        
        print(f"{Colors.GREEN}Email Address Syntax{Colors.NORMAL}")
        print(f"Email addresses may be specified in one of two ways:")
        print(f"    Full Name:     \"John Doe <john.doe@gmail.com>\"")
        print(f"    Just Address:  \"john.doe@gmail.com\"\n")
        
        print(f"The \"Full Name\" method is useful if you want a name, rather than a plain")
        print(f"email address, to be displayed in the recipient's From, To, or Cc fields")
        print(f"when they view the message.\n")
        
        print(f"{Colors.GREEN}Multiple Recipients{Colors.NORMAL}")
        print(f"The -t, -cc, and -bcc options each accept multiple addresses.  They may be")
        print(f"specified by separating them by either a white space, comma, or semi-colon")
        print(f"separated list.  You may also specify the -t, -cc, and -bcc options multiple")
        print(f"times, each occurance will append the new recipients to the respective list.\n")
        
        print(f"Examples:")
        print(f"  * Space separated list:")
        print(f"    -t jane.doe@yahoo.com \"John Doe <john.doe@gmail.com>\"\n")
        print(f"  * Semi-colon separated list:")
        print(f"    -t \"jane.doe@yahoo.com; John Doe <john.doe@gmail.com>\"\n")
        print(f"  * Comma separated list:")
        print(f"    -t \"jane.doe@yahoo.com, John Doe <john.doe@gmail.com>\"\n")
        print(f"  * Multiple -t, -cc, or -bcc options:")
        print(f"    -t \"jane.doe@yahoo.com\" -t \"John Doe <john.doe@gmail.com>\"\n")
    
    elif topic == 'message':
        print(f"\n{Colors.BOLD}MESSAGE DOCUMENTATION{Colors.NORMAL}\n")
        
        print(f"{Colors.GREEN}Message Options{Colors.NORMAL}")
        print(f"Options related to the email message body:")
        print(f"    -u  SUBJECT")
        print(f"    -m  MESSAGE")
        print(f"    -o  message-file=FILE")
        print(f"    -o  message-content-type=<auto|text|html>")
        print(f"    -o  message-header=EMAIL HEADER")
        print(f"    -o  message-charset=CHARSET")
        print(f"    -o  message-format=raw\n")
        
        print(f"-u SUBJECT")
        print(f"    This option allows you to specify the subject for your email message.")
        print(f"    It is not required that the subject be quoted, although it is recommended.")
        print(f"    The subject will be read until an argument starting with a hyphen (-) is found.\n")
        
        print(f"-m MESSAGE")
        print(f"    This option is one of three methods that allow you to specify the message")
        print(f"    body for your email.  The message may be specified on the command line")
        print(f"    with this -m option, read from a file with the -o message-file=FILE")
        print(f"    option, or read from STDIN if neither of these options are present.\n")
        
        print(f"-o message-file=FILE")
        print(f"    This option is one of three methods that allow you to specify the message")
        print(f"    body for your email.  To use this option simply specify a text file")
        print(f"    containing the body of your email message.\n")
        
        print(f"-o message-content-type=<auto|text|html>")
        print(f"    This option allows you to specify the content-type of the email. If your")
        print(f"    email message is an html message but is being displayed as a text message")
        print(f"    just add \"-o message-content-type=html\" to the command line to force it")
        print(f"    to display as an html message.\n")
        
        print(f"-o message-header=EMAIL HEADER")
        print(f"    This option allows you to specify additional email headers to be included.")
        print(f"    To add more than one message header simply use this option on the command")
        print(f"    line more than once.  If you specify a message header that sendEmail would")
        print(f"    normally generate the one you specified will be used in its place.\n")
        
        print(f"-o message-charset=CHARSET")
        print(f"    This option allows you to specify the character-set for the message body.")
        print(f"    The default is iso-8859-1.\n")
        
        print(f"-o message-format=raw")
        print(f"    This option instructs sendEmail to assume the message (specified with -m,")
        print(f"    read from STDIN, or read from the file specified in -o message-file=FILE)")
        print(f"    is already a *complete* email message.  SendEmail will not generate any")
        print(f"    headers and will transmit the message as-is to the remote SMTP server.\n")
    
    elif topic == 'networking':
        print(f"\n{Colors.BOLD}NETWORKING DOCUMENTATION{Colors.NORMAL}\n")
        
        print(f"{Colors.GREEN}Networking Options{Colors.NORMAL}")
        print(f"Options related to networking:")
        print(f"    -s   SERVER[:PORT]")
        print(f"    -b   BINDADDR[:PORT]")
        print(f"    -o   tls=<auto|yes|no>")
        print(f"    -o   timeout=SECONDS\n")
        
        print(f"-s SERVER[:PORT]")
        print(f"    This option allows you to specify the SMTP server sendEmail should")
        print(f"    connect to to deliver your email message to.  If this option is not")
        print(f"    specified sendEmail will try to connect to localhost:25 to deliver")
        print(f"    the message.  THIS IS MOST LIKELY NOT WHAT YOU WANT, AND WILL LIKELY")
        print(f"    FAIL unless you have a email server running on your computer!\n")
        
        print(f"    Typically you will need to specify your company or ISP's email server.")
        print(f"    For example, if you use CableOne you will need to specify:")
        print(f"       -s mail.cableone.net\n")
        
        print(f"    If you have your own email server running on port 300 you would")
        print(f"    probably use an option like this:")
        print(f"       -s myserver.mydomain.com:300\n")
        
        print(f"-b BINDADDR[:PORT]")
        print(f"    This option allows you to specify the local IP address (and optional")
        print(f"    tcp port number) for sendEmail to bind to when connecting to the remote")
        print(f"    SMTP server.  This useful for people who need to send an email from a")
        print(f"    specific network interface or source address.\n")
        
        print(f"-o tls=<auto|yes|no>")
        print(f"    This option allows you to specify if TLS should be enabled or disabled.")
        print(f"    The default, auto, will use TLS automatically if your Python installation")
        print(f"    has SSL support and the remote SMTP server supports TLS.\n")
        
        print(f"-o timeout=SECONDS")
        print(f"    This option sets the timeout value in seconds used for all network reads,")
        print(f"    writes, and a few other things.\n")
    
    elif topic == 'output':
        print(f"\n{Colors.BOLD}OUTPUT DOCUMENTATION{Colors.NORMAL}\n")
        
        print(f"{Colors.GREEN}Output Options{Colors.NORMAL}")
        print(f"Options related to output:")
        print(f"    -l LOGFILE")
        print(f"    -v")
        print(f"    -q\n")
        
        print(f"-l LOGFILE")
        print(f"    This option allows you to specify a log file to append to.  Every message")
        print(f"    that is displayed to STDOUT is also written to the log file.  This may be")
        print(f"    used in conjunction with -q and -v.\n")
        
        print(f"-q")
        print(f"    This option tells sendEmail to disable printing to STDOUT.  In other")
        print(f"    words nothing will be printed to the console.  This does not affect the")
        print(f"    behavior of the -l or -v options.\n")
        
        print(f"-v")
        print(f"    This option allows you to increase the debug level of sendEmail.  You may")
        print(f"    either use this option more than once, or specify more than one v at a")
        print(f"    time to obtain a debug level higher than one.\n")
        
        print(f"    Examples:")
        print(f"        Specifies a debug level of 1:  -v")
        print(f"        Specifies a debug level of 2:  -vv")
        print(f"        Specifies a debug level of 2:  -v -v\n")
        
        print(f"    A debug level of one is recommended when doing any sort of debugging.")
        print(f"    At that level you will see the entire SMTP transaction (except the body")
        print(f"    of the email message), and hints will be displayed for most warnings and")
        print(f"    errors.  The highest debug level is three.\n")
    
    elif topic == 'misc':
        print(f"\n{Colors.BOLD}MISC DOCUMENTATION{Colors.NORMAL}\n")
        
        print(f"{Colors.GREEN}Misc Options{Colors.NORMAL}")
        print(f"Options that don't fit anywhere else:")
        print(f"    -a   ATTACHMENT [ATTACHMENT ...]")
        print(f"    -xu  USERNAME")
        print(f"    -xp  PASSWORD")
        print(f"    -o   username=USERNAME")
        print(f"    -o   password=PASSWORD")
        print(f"    -o   tls=<auto|yes|no>")
        print(f"    -o   timeout=SECONDS")
        print(f"    -o   fqdn=FQDN\n")
        
        print(f"-a   ATTACHMENT [ATTACHMENT ...]")
        print(f"    This option allows you to attach any number of files to your email message.")
        print(f"    To specify more than one attachment, simply separate each filename with a")
        print(f"    space.\n")
        
        print(f"-xu  USERNAME")
        print(f"    Alias for -o username=USERNAME\n")
        
        print(f"-xp  PASSWORD")
        print(f"    Alias for -o password=PASSWORD\n")
        
        print(f"-o   username=USERNAME (synonym for -xu)")
        print(f"    These options allow specification of a username to be used with SMTP")
        print(f"    servers that require authentication.  If a username is specified but a")
        print(f"    password is not, you will be prompted to enter one at runtime.\n")
        
        print(f"-o   password=PASSWORD (synonym for -xp)")
        print(f"    These options allow specification of a password to be used with SMTP")
        print(f"    servers that require authentication.  If a username is specified but a")
        print(f"    password is not, you will be prompted to enter one at runtime.\n")
        
        print(f"-o   tls=<auto|yes|no>")
        print(f"    This option allows you to specify if TLS should be enabled or disabled.")
        print(f"    The default, auto, will use TLS automatically if your Python installation")
        print(f"    has SSL support and the remote SMTP server supports TLS.  To require TLS")
        print(f"    for message delivery set this to yes.  To disable TLS support set this to no.\n")
        
        print(f"-o   timeout=SECONDS")
        print(f"    This option sets the timeout value in seconds used for all network reads,")
        print(f"    writes, and a few other things.\n")
        
        print(f"-o   fqdn=FQDN")
        print(f"    This option sets the Fully Qualified Domain Name used during the initial")
        print(f"    SMTP greeting.  Normally this is automatically detected, but in case you")
        print(f"    need to manually set it for some reason, you can use this to override the default.\n")
    
    else:
        print(f"\n{Colors.RED}ERROR => The help topic '{topic}' is not valid!{Colors.NORMAL}\n")
        print(f"Valid topics are: addressing, message, networking, output, misc\n")
        sys.exit(1)
    
    sys.exit(0)

def main():
    # Check for help options before argparse
    if '--help' in sys.argv or '-h' in sys.argv:
        if len(sys.argv) > 2 and sys.argv[1] in ['--help', '-h']:
            topic = sys.argv[2]
            show_help_topic(topic)
        else:
            show_help()
    
    # Show help if no arguments provided
    if len(sys.argv) < 2:
        show_help()
    
    parser = argparse.ArgumentParser(
        description=f'{PROGRAM_NAME}-{VERSION} by {AUTHOR_NAME} <{AUTHOR_EMAIL}>',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog="""
Examples:
  sendEmail.py -f sender@example.com -t recipient@example.com -s mail.example.com -u "Subject" -m "Message body"
  sendEmail.py -f sender@example.com -t recipient@example.com -s mail.example.com:587 -xu username -xp password -u "Subject" -m "Message"
        """
    )
    
    # Required arguments
    parser.add_argument('-f', '--from', dest='sender', default='', help='From email address')
    
    # Recipients
    parser.add_argument('-t', '--to', dest='to', action='append', default=[], help='To email address(es)')
    parser.add_argument('-cc', dest='cc', action='append', default=[], help='Cc email address(es)')
    parser.add_argument('-bcc', dest='bcc', action='append', default=[], help='Bcc email address(es)')
    
    # Message
    parser.add_argument('-u', '--subject', dest='subject', default='', help='Email subject')
    parser.add_argument('-m', '--message', dest='message', default='', help='Message body')
    parser.add_argument('-o', '--option', dest='options', action='append', default=[], help='Advanced options')
    
    # Server
    parser.add_argument('-s', '--server', dest='server', default='localhost:25', help='SMTP server:port')
    parser.add_argument('-b', '--bind', dest='bindaddr', default='', help='Bind address')
    
    # Attachments
    parser.add_argument('-a', '--attachment', dest='attachments', action='append', default=[], help='Attachment file(s)')
    
    # Authentication
    parser.add_argument('-xu', '--username', dest='username', default='', help='SMTP username')
    parser.add_argument('-xp', '--password', dest='password', default='', help='SMTP password')
    
    # Logging and verbosity
    parser.add_argument('-l', '--logfile', dest='logfile', default='', help='Log file')
    parser.add_argument('-v', '--verbose', dest='verbose', action='count', default=0, help='Verbose output')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true', help='Quiet mode')
    
    # DSN
    parser.add_argument('-dsn', dest='dsn', default='', help='DSN options')
    parser.add_argument('-dsnid', dest='dsnid', default='', help='DSN ID')
    
    args = parser.parse_args()
    
    # Create config and sender
    config = Config()
    sender = EmailSender(config)
    
    # Parse server
    if ':' in args.server:
        server, port = args.server.split(':')
        config.server = server
        config.port = int(port)
    else:
        config.server = args.server
    
    # Set configuration
    config.debug = args.verbose
    config.stdout = not args.quiet
    config.timeout = 60
    config.username = args.username or config.username
    config.password = args.password or config.password
    config.bindaddr = args.bindaddr
    config.logfile = args.logfile
    config.logging = bool(args.logfile)
    
    if args.dsnid:
        config.dsnid = args.dsnid
    
    # DSN options
    if args.dsn:
        dsn_opts = []
        if 's' in args.dsn.lower():
            dsn_opts.append('SUCCESS')
        if 'f' in args.dsn.lower():
            dsn_opts.append('FAILURE')
        if 'd' in args.dsn.lower():
            dsn_opts.append('DELAY')
        
        if dsn_opts:
            config.dsnopts = 'NOTIFY=' + ','.join(dsn_opts)
        else:
            config.dsnopts = 'NOTIFY=SUCCESS,FAILURE,DELAY'
    
    # Set sender data
    if not args.sender:
        print(f"{Colors.RED}ERROR => You must specify a 'from' field! Try --help.{Colors.NORMAL}")
        sys.exit(1)
    
    sender.sender = args.sender
    sender.to_addresses = []
    for to in args.to:
        if ';' in to or ',' in to:
            sender.to_addresses.extend(re.split('[,;]', to))
        else:
            sender.to_addresses.append(to)
    
    for cc in args.cc:
        if ';' in cc or ',' in cc:
            sender.cc_addresses.extend(re.split('[,;]', cc))
        else:
            sender.cc_addresses.append(cc)
    
    for bcc in args.bcc:
        if ';' in bcc or ',' in bcc:
            sender.bcc_addresses.extend(re.split('[,;]', bcc))
        else:
            sender.bcc_addresses.append(bcc)
    
    sender.subject = args.subject
    sender.message = args.message.replace('\\n', '\n') if args.message else ''
    sender.attachments = args.attachments
    
    # Process advanced options
    for opt in args.options:
        if '=' in opt:
            key, value = opt.split('=', 1)
            if key == 'message-file':
                if os.path.isfile(value):
                    with open(value, 'r') as f:
                        sender.message = f.read()
            elif key == 'message-charset':
                sender.message_charset = value
            elif key == 'message-content-type':
                sender.message_content_type = value
            elif key == 'message-format':
                sender.message_format = value
            elif key == 'message-header':
                sender.message_header += value + CRLF
            elif key == 'reply-to':
                sender.reply_to = value
            elif key == 'timeout':
                config.timeout = int(value)
            elif key == 'tls':
                config.tls = value.lower()
            elif key == 'fqdn':
                config.fqdn = value
                config.hostname = value.split('.')[0]
            elif key == 'username':
                config.username = value
            elif key == 'password':
                config.password = value
    
    # Prompt for password if username set but password not
    if config.username and not config.password:
        config.password = getpass.getpass("Password: ")
    
    # Read message from stdin if not provided
    if not sender.message:
        sender.printmsg("Reading message body from STDIN (end with Ctrl-D):", 0)
        try:
            sender.message = sys.stdin.read()
        except KeyboardInterrupt:
            sender.quit("Interrupted!", 1)
    
    # Send email
    sender.send_email()

if __name__ == '__main__':
    main()
