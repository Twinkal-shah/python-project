import smtplib
import dns.resolver
import random
from threading import Thread
from queue import Queue
import string
import itertools
from typing import List, Optional, Set, Union, Dict
import unicodedata
from unidecode import unidecode
import re
import time

class Scout:
    def __init__(self, 
            check_variants: bool = True, 
            check_prefixes: bool = True, 
            check_catchall: bool = True,
            normalize: bool = True,
            num_threads: int = 5,
            num_bulk_threads: int = 1,
            smtp_timeout: int = 2) -> None:
        self.check_variants = check_variants
        self.check_prefixes = check_prefixes
        self.check_catchall = check_catchall
        self.normalize = normalize
        self.num_threads = num_threads
        self.num_bulk_threads = num_bulk_threads
        self.smtp_timeout = smtp_timeout

    def check_smtp(self, email: str, port: int = 25) -> Dict[str, Union[str, int, float]]:
        domain = email.split('@')[1]
        ver_ops = 0
        connections = 0
        start_time = time.time()
        mx_record = ""

        try:
            records = dns.resolver.resolve(domain, 'MX')
            mx_record = str(records[0].exchange).rstrip('.')
            connections += 1

            with smtplib.SMTP(mx_record, port, timeout=self.smtp_timeout) as server:
                server.set_debuglevel(0)
                server.ehlo("blu-harvest.com")
                server.mail('noreply@blu-harvest.com')
                ver_ops += 1
                code, message = server.rcpt(email)
                ver_ops += 1

            time_exec = round(time.time() - start_time, 3)
            return {
                "email": email,
                "status": "found" if code == 250 else "not_found",
                "message": f"{code} {message.decode()}",
                "user_name": email.split('@')[0].replace('.', ' ').title(),
                "domain": domain,
                "mx": mx_record,
                "connections": connections,
                "ver_ops": ver_ops,
                "time_exec": time_exec
            }

        except Exception as e:
            time_exec = round(time.time() - start_time, 3)
            return {
                "email": "",
                "status": "not_found",
                "message": f"Rejected: {str(e)}",
                "user_name": email.split('@')[0].replace('.', ' ').title(),
                "domain": domain,
                "mx": mx_record,
                "connections": connections,
                "ver_ops": ver_ops,
                "time_exec": time_exec
            }

    def find_valid_emails(self, domain: str, names: Optional[Union[str, List[str], List[List[str]]]] = None) -> List[Dict[str, Union[str, int, float]]]:
        email_results = []
        email_variants = []
        generated_mails = []

        if self.check_variants and names:
            if isinstance(names, str):
                names = names.split(" ")
            if isinstance(names, list) and names and isinstance(names[0], list):
                for name_list in names:
                    assert isinstance(name_list, list)
                    name_list = self.split_list_data(name_list)
                    email_variants.extend(self.generate_email_variants(name_list, domain, normalize=self.normalize))
            else:
                names = self.split_list_data(names)
                email_variants = self.generate_email_variants(names, domain, normalize=self.normalize)

        if self.check_prefixes and not names:
            generated_mails = self.generate_prefixes(domain)

        all_emails = email_variants + generated_mails

        for email in all_emails:
            result = self.check_smtp(email)
            email_results.append(result)
            break  # Only 1 request now
            # time.sleep(random.uniform(1.0, 2.0))  # Optional delay

        if not email_results:
            email_results.append({
                "email": "",
                "status": "not_found",
                "message": "Rejected",
                "user_name": "",
                "domain": domain,
                "mx": "",
                "connections": 0,
                "ver_ops": 0,
                "time_exec": 0.0
            })

        return email_results

    def find_valid_emails_bulk(self, email_data: List[Dict[str, Union[str, List[str]]]]) -> List[Dict[str, Union[str, List[str], List[Dict[str, Union[str, int, float]]]]]]:
        all_valid_emails = []
        for data in email_data:
            domain = data.get("domain")
            names = data.get("names", [])
            valid_emails = self.find_valid_emails(domain, names)
            all_valid_emails.append({"domain": domain, "names": names, "valid_emails": valid_emails})
        return all_valid_emails

    def split_list_data(self, target):
        new_target = []
        for i in target:
            new_target.extend(i.split(" "))
        return new_target
