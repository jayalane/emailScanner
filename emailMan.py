#!/usr/bin/env python3
"""
IMAP Email Manager

This script connects to an IMAP server, displays email details (from, to, subject, date, 
and preview), and asks if you want to delete each message. It maintains a SQLite database 
of previously seen messages to avoid showing them again in future runs.

Usage:
    python email_manager.py

You will be prompted for your IMAP server details and credentials on startup.
"""

IMAP_SERVER = "mail.disputingtaste.com"


import imaplib
import email
import email.utils
import getpass
import sqlite3
import os
import re
import datetime
import textwrap
from email.header import decode_header

def read_config():
    """Read IMAP server and account information from config.txt file."""
    config_file = "config.txt"
    config = {
        "imap_server": None,
        "account": None,
        "port": "993"  # Default port
    }
    
    try:
        if os.path.exists(config_file):
            print(f"Reading configuration from {config_file}")
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            key, value = [part.strip() for part in line.split('=', 1)]
                            if key in config:
                                config[key] = value
                        except ValueError:
                            print(f"Warning: Ignoring invalid config line: {line}")
                            
            print(f"Using server: {config['imap_server']}")
            print(f"Using account: {config['account']}")
            return config
        else:
            print(f"Config file {config_file} not found, using interactive mode")
            return None
    except Exception as e:
        print(f"Error reading config file: {str(e)}")
        return None


class EmailManager:
    def __init__(self):
        self.mail = None
        self.db_conn = None
        self.setup_database()

    def setup_database(self):
        """Set up the SQLite database to track seen emails."""
        db_path = os.path.expanduser("~/.email_manager.db")
        self.db_conn = sqlite3.connect(db_path)
        cursor = self.db_conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS seen_emails (
            message_id TEXT PRIMARY KEY,
            subject TEXT,
            sender TEXT,
            date TEXT,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        self.db_conn.commit()

    def connect_to_server(self):
        """Connect to the IMAP server using user credentials."""
        print("\n=== IMAP Email Manager ===")
        print("Enter your email server information:")
        
        # Try to read from config first
        config = read_config()
        
        if config and config["imap_server"] and config["account"]:
            server = config["imap_server"]
            port = config["port"]
            username = config["account"]
        else:
            # Fall back to interactive mode
            print("Enter your email server information:")
            server = input("IMAP Server (e.g., imap.gmail.com): ")
            port = input("Port (usually 993 for SSL, default: 993): ") or "993"
            username = input("Email address: ")
        
        password = getpass.getpass("Password: ")
        
        try:
            # Connect to the server
            self.mail = imaplib.IMAP4_SSL(server, int(port))
            print(f"Connecting to {server}...")
            self.mail.login(username, password)
            print("Successfully logged in!")
            return True
        except Exception as e:
            print(f"Connection failed: {str(e)}")
            return False

    def list_mailboxes(self):
        """List available mailboxes/folders on the server."""
        status, mailboxes = self.mail.list()
        print("\nAvailable mailboxes:")
        
        # Parse and show mailbox list in a cleaner format
        for i, mailbox in enumerate(mailboxes, 1):
            decoded = mailbox.decode('utf-8')
            # Extract mailbox name using regex
            match = re.search(r' "([A-Za-z\ ]*)"', decoded)
            if match:
                name = match.group(1)
            else:
                name = decoded.split(' ')[-1]
            print(f"{i}. {name}")
        
        choice = input("\nEnter mailbox name or number: ")
        
        # If the user entered a number, convert it to the corresponding mailbox name
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(mailboxes):
                decoded = mailboxes[idx].decode('utf-8')
                match = re.search(r'"/" "(.*)', decoded)
                if match:
                    mailbox_name = match.group(1)
                else:
                    mailbox_name = decoded.split(' ')[-1]
                return mailbox_name
        except ValueError:
            pass
        
        return choice

    def is_message_seen(self, message_id):
        """Check if a message has been seen and kept before."""
        cursor = self.db_conn.cursor()
        cursor.execute("SELECT action FROM seen_emails WHERE message_id = ?", (message_id,))
        result = cursor.fetchone()
        
        if result and result[0] == 'kept':
            return True
        return False

    def mark_message_seen(self, message_id, subject, sender, date, action):
        """Mark a message as seen in the database."""
        cursor = self.db_conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO seen_emails (message_id, subject, sender, date, action) VALUES (?, ?, ?, ?, ?)",
            (message_id, subject, sender, date, action)
        )
        self.db_conn.commit()

    def decode_mime_words(self, text):
        """Decode MIME encoded words in a header."""
        if text is None:
            return ""
        
        result = ""
        for decoded_bytes, charset in decode_header(text):
            if isinstance(decoded_bytes, bytes):
                try:
                    if charset:
                        result += decoded_bytes.decode(charset)
                    else:
                        result += decoded_bytes.decode('utf-8', errors='replace')
                except (UnicodeDecodeError, LookupError):
                    result += decoded_bytes.decode('utf-8', errors='replace')
            else:
                result += decoded_bytes
                
        return result

    def get_email_body(self, msg):
        """Extract the email body text."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                # Look for text content
                if content_type == "text/plain":
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='replace')
                        return body
                    except:
                        pass
                elif content_type == "text/html":
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='replace')
                        # Very basic HTML to text conversion
                        body = re.sub(r'<[^>]+>', '', body)
                        return body
                    except:
                        pass
        else:
            # Not multipart - get the content directly
            try:
                body = msg.get_payload(decode=True).decode('utf-8', errors='replace')
                content_type = msg.get_content_type()
                if content_type == "text/html":
                    body = re.sub(r'<[^>]+>', '', body)
                return body
            except:
                return "[Could not decode message body]"
        
        return "[No readable text content]"

    def process_emails(self, mailbox):
        """Process emails in the selected mailbox."""
        try:
            status, select_data = self.mail.select(mailbox, readonly=False)
            if status != 'OK':
                print(f"Could not open mailbox: {mailbox}")
                return
            
            # Get total message count
            message_count = int(select_data[0])
            print(f"\nFound {message_count} messages in {mailbox}")
            
            # Search for all mail
            status, message_ids = self.mail.search(None, 'ALL')
            if status != 'OK':
                print("No messages found.")
                return
            
            message_id_list = message_ids[0].split()
            print(f"Processing {len(message_id_list)} messages...\n")
            
            # Process in reverse order (newest first)
            for i, message_num in enumerate(reversed(message_id_list), 1):
                # Fetch the message
                status, msg_data = self.mail.fetch(message_num, '(RFC822)')
                if status != 'OK':
                    print(f"Error fetching message {message_num}")
                    continue
                
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)
                
                # Get message ID for tracking
                message_id = msg.get('Message-ID', f"NO-ID-{message_num.decode('utf-8')}")
                
                # Skip if we've seen and kept this message before
                if self.is_message_seen(message_id):
                    continue
                
                # Extract and decode headers
                subject = self.decode_mime_words(msg.get('Subject', '[No Subject]'))
                from_header = self.decode_mime_words(msg.get('From', '[Unknown Sender]'))
                to_header = self.decode_mime_words(msg.get('To', '[Unknown Recipient]'))
                
                # Parse the date
                date_header = msg.get('Date', '')
                try:
                    parsed_date = email.utils.parsedate_to_datetime(date_header)
                    date_str = parsed_date.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    date_str = date_header
                
                # Get email body preview
                body = self.get_email_body(msg)
                preview = textwrap.shorten(body, width=200, placeholder="...") if body else "[No body]"
                
                # Display email information
                print(f"Email {i}/{len(message_id_list)}")
                print(f"From: {from_header}")
                print(f"To: {to_header}")
                print(f"Date: {date_str}")
                print(f"Subject: {subject}")
                print(f"Preview: {preview}")
                
                # Ask for user action
                while True:
                    breakNow = False
                    for banned in ['dccc.org', 'info@', 'ncdp.org','team@e.summerforpa.com', 'defeatextremists.org','brady@bradyunited.org', 'notifications@mastodon.online', 'GabNews@mailer.gab.com','no-reply@givebloodtoday', 'macys.com', 'points-mail.com', 'zennioptical','substack.com', 'opencve.io', 'southwest.com','singaporeair.com','noreply@discord.com','choicehotels.com','expedia.com','carvana.com','duke.edu','linkedin.com', 'kamalaharris.com', 'hello@','jetblue.com','nipponkodo@nipponkodostore.com']: 
                        if banned in from_header:
                            print("Deleting banned", banned)
                            breakNow = True
                            action = 'y'
                            break
                    for banned in ['chris@austin-lane.net']:
                        if banned in to_header:
                            print("Deleting banned", banned)
                            breakNow = True
                            action = 'y'
                            break
                    for banned in ['actblue']:
                        if banned in preview:
                            print("Deleting banned", banned)
                            breakNow = True
                            action = 'y'
                            break
                    if breakNow:
                        break
                    action = input("\nDelete this message? (y/n/q to quit): ").lower()
                    if action in ('y', 'n', 'q', ''):
                        break
                    print("Invalid input. Please enter 'y', 'n', or 'q'.")
                
                if action == 'q':
                    print("Quitting...")
                    break
                
                if action == 'y' or action == '':
                    # Mark as deleted on the server
                    self.mail.store(message_num, '+FLAGS', '\\Deleted')
                    print("Marked for deletion.")
                    self.mark_message_seen(message_id, subject, from_header, date_str, 'deleted')
                else:
                    print("Keeping this message.")
                    self.mark_message_seen(message_id, subject, from_header, date_str, 'kept')
                
                print('-' * 60)
            
            # Expunge to actually delete messages
            self.mail.expunge()
            
        except Exception as e:
            print(f"Error processing emails: {str(e)}")
        finally:
            try:
                self.mail.close()
            except:
                pass

    def run(self):
        """Main method to run the email manager."""
        try:
            if not self.connect_to_server():
                return
            
            mailbox = self.list_mailboxes()
            self.process_emails(mailbox)
            
        except Exception as e:
            print(f"An error occurred: {str(e)}")
        finally:
            if self.mail:
                try:
                    self.mail.logout()
                except:
                    pass
            
            if self.db_conn:
                self.db_conn.close()

if __name__ == "__main__":
    manager = EmailManager()
    manager.run()
