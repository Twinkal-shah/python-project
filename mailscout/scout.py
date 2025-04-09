# import smtplib
# import dns.resolver
# import random
# from threading import Thread
# from queue import Queue
# import string
# import itertools
# from typing import List, Optional, Set, Union, Dict
# import unicodedata
# from unidecode import unidecode
# import re

# class Scout:
#     def __init__(self, 
#             check_variants: bool = True, 
#             check_prefixes: bool = True, 
#             check_catchall: bool = True,
#             normalize: bool = True,
#             num_threads: int = 5,
#             num_bulk_threads: int = 1,
#             smtp_timeout: int = 2) -> None:
#         """
#         Initialize the Scout object with default settings.

#         Args:
#             check_variants (bool): Flag to check variants. Defaults to True.
#             check_prefixes (bool): Flag to check prefixes. Defaults to True.
#             check_catchall (bool): Flag to check catchall. Defaults to True.
#             normalize (bool): Flag to normalize data. Defaults to True.
#             num_threads (int): Number of email finder threads for concurrency. Defaults to 5.
#             num_bulk_threads (int): Number of bulk email finder threads for concurrency. Defaults to 1.
#             smtp_timeout (int): Timeout for the SMTP connection. Defaults to 2. (in seconds)
#         """
        
#         self.check_variants = check_variants
#         self.check_prefixes = check_prefixes
#         self.check_catchall = check_catchall
#         self.normalize = normalize
#         self.num_threads = num_threads
#         self.num_bulk_threads = num_bulk_threads
#         self.smtp_timeout = smtp_timeout


#     # SMTP Mail Checker Function
#     def check_smtp(self, email: str, port: int = 25) -> bool:
#         """
#         Check if an email is deliverable using SMTP.

#         Args:
#         email (str): The email address to check.
#         port (int, optional): The port to use for the SMTP connection. Defaults to 25.

#         Returns:
#         bool: True if the email is deliverable, False otherwise.
#         """
#         domain = email.split('@')[1]
#         try:
#             records = dns.resolver.resolve(domain, 'MX')
#             mx_record = str(records[0].exchange)
#             with smtplib.SMTP(mx_record, port, timeout=self.smtp_timeout) as server:
#                 server.set_debuglevel(0)
#                 server.ehlo("example.com")
#                 server.mail('test@example.com')
#                 code, message = server.rcpt(email)

#             return code == 250
#         except Exception as e:
#             print(f"Error checking {email}: {e}")
#             return False


#     # Catch-all checker function, checks whether the domain accepts all addresses
#     def check_email_catchall(self, domain: str) -> bool:
#         """
#         Check if a domain is a catch-all for email addresses.

#         A catch-all domain will accept emails sent to any address under that domain,
#         even if the specific address does not exist.

#         Args:
#         domain (str): The domain to check.

#         Returns:
#         bool: True if the domain is a catch-all, False otherwise.
#         """
#         random_prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + "falan"
#         random_email = f"{random_prefix}@{domain}"
#         return self.check_smtp(random_email)

#     def normalize_name(self, name: str) -> str:
#         """
#         Convert a non-email compliant name to a normalized email-friendly format.

#         Args:
#         name (str): The name to be normalized.

#         Returns:
#         str: A normalized, email-friendly version of the name.
#         """
#         # This function is a little bit overkill 
#         # I will strip it over time with proper testing
        
#         # Basic normalization
#         name = name.upper().lower()

#         # Normalize using unidecode for proper transliteration
#         name = unidecode(name)

#         # Normalize to NFKD form which separates characters and their diacritics
#         normalized = unicodedata.normalize('NFKD', name)

#         # Encode to ASCII bytes, then decode back to string ignoring non-ASCII characters
#         ascii_encoded = normalized.encode('ascii', 'ignore').decode('ascii')

#         # Replace any remaining non-alphanumeric characters with an empty string
#         email_compliant = re.sub(r'[^a-zA-Z0-9]', '', ascii_encoded)

#         return email_compliant


#     def generate_prefixes(self, domain: str, custom_prefixes: Optional[List[str]] = None) -> List[str]:
#         """
#         Generate a list of email addresses with common or custom prefixes for a given domain.

#         Args:
#         domain (str): The domain for which to generate email addresses.
#         custom_prefixes (List[str], optional): A list of custom prefixes. If provided, these
#                                             prefixes are used instead of the common ones.

#         Returns:
#         List[str]: A list of email addresses with the specified prefixes.
#         """
#         common_prefixes = [
#             # Business Prefixes
#             "info", "contact", "sales", "support", "admin",
#             "service", "team", "hello", "marketing", "hr",
#             "office", "accounts", "billing", "careers", "jobs",
#             "press", "help", "enquiries", "management", "staff",
#             "webmaster", "administrator", "customer", "tech",
#             "finance", "legal", "compliance", "operations", "it",
#             "network", "development", "research", "design", "engineering",
#             "production", "purchasing", "logistics", "training",
#             "ceo", "director", "manager",
#             "executive", "agent", "representative", "partner",
#             # Website Management Prefixes
#             "blog", "forum", "news", "updates", "events",
#             "community", "shop", "store", "feedback",
#             "media", "resource", "resources",
#             "api", "dev", "developer", "status", "security"
#         ]

#         prefixes = custom_prefixes if custom_prefixes is not None else common_prefixes
#         return [f"{prefix}@{domain}" for prefix in prefixes]

#     def generate_email_variants(self, names: List[str], domain: str, normalize: bool = True) -> List[str]:
#         """
#         Generate a set of email address variants based on a list of names for a given domain.

#         This function creates combinations of the provided names, both with and without dots
#         between them, and also includes individual names and their first initials.

#         Args:
#         names (List[str]): A list of names to combine into email address variants.
#         domain (str): The domain to be appended to each email variant.
#         normalize (bool, optional): If True, normalize the prefixes to email-friendly format.

#         Returns:
#         List[str]: A list of unique email address variants.
#         """
#         variants: Set[str] = set()

#         assert False not in [isinstance(i, str) for i in names]

#         if normalize:
#             normalized_names = [self.normalize_name(name) for name in names]
#             names = normalized_names

#         # Generate combinations of different lengths
#         for r in range(1, len(names) + 1):
#             for name_combination in itertools.permutations(names, r):
#                 # Join the names in the combination with and without a dot
#                 variants.add(''.join(name_combination))
#                 variants.add('.'.join(name_combination))

#         # Add individual names (and their first initials) as variants
#         for name in names:
#             variants.add(name)
#             variants.add(name[0])

#         return [f"{variant}@{domain}" for variant in variants]


#     def find_valid_emails(self,
#                         domain: str, 
#                         names: Optional[Union[str, List[str], List[List[str]]]] = None, 
#                         )-> List[str]:
#         """
#         Find valid email addresses for a given domain based on various checks.

#         Args:
#         domain (str): The domain to check email addresses against.
#         names (Union[str, List[str], List[List[str]]], optional): Names to generate email variants. 
#             Can be a single string, a list of strings, or a list of lists of strings.

#         Returns:
#         List[str]: A list of valid email addresses found.
#         """
#         # Pre-flight checks
#         if self.check_catchall:
#             if self.check_email_catchall(domain):
#                 return []

#         # Valid e-mail finder function
#         def worker():
#             while True:
#                 email = q.get()
#                 if email is None:  # None is the signal to stop
#                     break
#                 try:
#                     if self.check_smtp(email):
#                         valid_emails.append(email)
#                 except Exception as e:
#                     print(f"Error processing {domain}: {e}")
#                 finally:
#                     q.task_done()

#         valid_emails = []
#         email_variants = []
#         generated_mails = []

#         # Generate email variants based on the type of 'names'
#         if self.check_variants and names:
#             if isinstance(names, str):
#                 names = names.split(" ")
#             if isinstance(names, list) and names and isinstance(names[0], list):
#                 for name_list in names:
#                     assert isinstance(name_list, list)
#                     name_list = self.split_list_data(name_list)
#                     email_variants.extend(self.generate_email_variants(name_list, domain, normalize = self.normalize))
#             else:
#                 names = self.split_list_data(names)
#                 email_variants = self.generate_email_variants(names, domain, normalize = self.normalize)

#         if self.check_prefixes and not names:
#             generated_mails = self.generate_prefixes(domain)

#         all_emails = email_variants + generated_mails

#         q = Queue()
#         threads = []
#         num_worker_threads = self.num_threads  # Number of worker threads, as passed via the argument

#         # Start worker threads
#         for i in range(num_worker_threads):
#             t = Thread(target=worker)
#             t.start()
#             threads.append(t)

#         # Enqueue emails
#         for email in all_emails:
#             q.put(email)

#         # Wait for all tasks to be processed
#         q.join()

#         # Stop workers
#         for i in range(num_worker_threads):
#             q.put(None)
#         for t in threads:
#             t.join()

#         return valid_emails



#     def find_valid_emails_bulk(self,
#         email_data: List[Dict[str, Union[str, List[str]]]], 
#         ) -> List[Dict[str, Union[str, List[str], List[Dict[str, str]]]]]:
#         """
#         Find valid email addresses in bulk for multiple domains and names.

#         Args:
#         email_data (List[Dict[str, Union[str, List[str]]]]): A list of dictionaries, 
#             each containing domain and optional names to check.

#         Returns:
#         List[Dict[str, Union[str, List[str], List[Dict[str, str]]]]]: A list of dictionaries, 
#             each containing the domain, names, and a list of valid emails found.
#         """
#         # Remove duplicates
#         email_data_clean = [i for n, i in enumerate(email_data) if i not in email_data[n + 1:]]

#         # Worker function for threading
#         def worker():
#             while True:
#                 data = q.get()
#                 if data is None:  # None is the signal to stop
#                     break
#                 try:
#                     domain = data.get("domain")
#                     names = data.get("names", [])
#                     check_prefixes_value = False if names else self.check_prefixes

#                     valid_emails = self.find_valid_emails(
#                         domain, names
#                     )
#                     all_valid_emails.append({"domain": domain, "names": names, "valid_emails": valid_emails})
#                 except Exception as e:
#                     print(f"Error processing {domain}: {e}")
#                 finally:
#                     q.task_done()

#         all_valid_emails = []
#         q = Queue()
#         threads = []
#         num_worker_threads = self.num_bulk_threads

#         # Start worker threads
#         for i in range(num_worker_threads):
#             t = Thread(target=worker)
#             t.start()
#             threads.append(t)

#         # Enqueue email data
#         for data in email_data_clean:
#             q.put(data)

#         # Wait for all tasks to be processed
#         q.join()

#         # Stop workers
#         for i in range(num_worker_threads):
#             q.put(None)
#         for t in threads:
#             t.join()

#         return all_valid_emails
    
#     def split_list_data(self, target):
#         new_target = []
#         for i in target:
#             new_target.extend(i.split(" "))
#         return new_target


# import smtplib
# import dns.resolver
# import random
# from threading import Thread
# from queue import Queue
# import string
# import itertools
# from typing import List, Optional, Union, Dict
# import re

# class Scout:
#     def __init__(self, 
#             check_variants: bool = True, 
#             check_prefixes: bool = True, 
#             check_catchall: bool = True,
#             normalize: bool = True,
#             num_threads: int = 5,
#             num_bulk_threads: int = 1,
#             smtp_timeout: int = 2) -> None:
#         self.check_variants = check_variants
#         self.check_prefixes = check_prefixes
#         self.check_catchall = check_catchall
#         self.normalize = normalize
#         self.num_threads = num_threads
#         self.num_bulk_threads = num_bulk_threads
#         self.smtp_timeout = smtp_timeout
#         self.mx_cache = {}

#     def get_mx_record(self, domain: str) -> str:
#         """Fetch and cache MX records for a domain."""
#         if domain in self.mx_cache:
#             return self.mx_cache[domain]
        
#         try:
#             records = dns.resolver.resolve(domain, 'MX')
#             mx_record = str(records[0].exchange)
#             self.mx_cache[domain] = mx_record
#             return mx_record
#         except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
#             return ""

#     def check_smtp(self, email: str, port: int = 25) -> Dict[str, Union[str, int]]:
#         """Verify if an email exists via SMTP handshake."""
#         domain = email.split('@')[-1]
#         mx_record = self.get_mx_record(domain)

#         if not mx_record:
#             return {
#                 "email": email, "status": "not_found", "message": "No MX record",
#                 "user_name": email.split('@')[0], "domain": domain, "mx": "",
#                 "connections": 0, "ver_ops": 0, "time_exec": 0.0
#             }

#         try:
#             with smtplib.SMTP(mx_record, port, timeout=self.smtp_timeout) as server:
#                 server.ehlo("example.com")
#                 server.mail("test@example.com")  # Fake sender
#                 code, _ = server.rcpt(email)

#             return {
#                 "email": email, "status": "found" if code == 250 else "not_found", "message": "Accepted" if code == 250 else "Rejected",
#                 "user_name": email.split('@')[0], "domain": domain, "mx": mx_record,
#                 "connections": 1, "ver_ops": 1, "time_exec": 1.2
#             }
#         except Exception:
#             return {
#                 "email": email, "status": "not_found", "message": "SMTP error",
#                 "user_name": email.split('@')[0], "domain": domain, "mx": "",
#                 "connections": 0, "ver_ops": 0, "time_exec": 0.0
#             }

#     def generate_email_variations(self, names: List[str], domain: str) -> List[str]:
#         """Generate common email patterns."""
#         first, last = (names + [""])[:2]
#         patterns = [
#             f"{first}.{last}@{domain}", f"{first}{last}@{domain}", f"{first}@{domain}",
#             f"{first}{last[0]}@{domain}", f"{first[0]}{last}@{domain}"
#         ]
#         return [email.lower() for email in patterns if first]

#     def find_valid_emails(self, domain: str, names: Optional[Union[str, List[str], List[List[str]]]] = None) -> Dict:
#         """Find valid emails for a domain based on name patterns."""
#         email_results = []
#         email_variants = []
#         generated_mails = []

#         if self.check_variants and names:
#             if isinstance(names, str):
#                 names = names.split(" ")
#             if isinstance(names, list) and names and isinstance(names[0], list):
#                 for name_list in names:
#                     email_variants.extend(self.generate_email_variations(self.split_list_data(name_list), domain))
#             else:
#                 email_variants = self.generate_email_variations(self.split_list_data(names), domain)

#         if self.check_prefixes and not names:
#             generated_mails = self.generate_prefixes(domain)

#         all_emails = email_variants + generated_mails

#         for email in all_emails:
#             result = self.check_smtp(email)
#             if result["status"] == "found":
#                 email_results.append(result)
#                 break  # Stop checking once a valid email is found

#         if not email_results:
#             email_results.append({
#                 "email": "", "status": "not_found", "message": "Rejected",
#                 "user_name": "N/A", "domain": domain, "mx": self.get_mx_record(domain),
#                 "connections": 0, "ver_ops": 0, "time_exec": 0.0
#             })
        
#         return {"domain": domain, "valid_emails": email_results}

#     def find_valid_emails_bulk(self, email_data: List[Dict[str, Union[str, List[str]]]]) -> List[Dict[str, Union[str, List[str], List[Dict[str, str]]]]]:
#         """Find valid emails in bulk."""
#         all_valid_emails = []

#         for data in email_data:
#             domain = data.get("domain")
#             names = data.get("names", [])
#             valid_emails = self.find_valid_emails(domain, names)
#             all_valid_emails.append(valid_emails)

#         return all_valid_emails

#     def split_list_data(self, target: List[str]) -> List[str]:
#         """Split names into individual words."""
#         return [word for i in target for word in i.split(" ")]

# # Example Usage
# if __name__ == "__main__":
#     finder = Scout()
#     email_data = [
#         {"domain": "example.com", "names": ["John Doe"]},
#         {"domain": "test.com", "names": ["Jane Smith"]}
#     ]
    
#     result = finder.find_valid_emails_bulk(email_data)
#     print(result)





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
                "status": "valid" if code == 250 else "invalid",
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
                "status": "invalid",
                "message": f"Rejected: {str(e)}",
                "user_name": email.split('@')[0].replace('.', ' ').title() if email else "",
                "domain": domain,
                "mx": mx_record if 'mx_record' in locals() else "",
                "connections": connections,
                "ver_ops": ver_ops,
                "time_exec": time_exec
            }

    def find_valid_emails(self, domain: str, names: Optional[Union[str, List[str], List[List[str]]]] = None) -> Dict[str, Union[str, int, float, None]]:
        email_variants = []
        generated_mails = []

        if self.check_variants and names:
            if isinstance(names, str):
                names = names.split(" ")
            if isinstance(names, list) and names and isinstance(names[0], list):
                for name_list in names:
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
            time.sleep(random.uniform(1.0, 2.0))  # Delay between SMTP checks
            if result["status"] == "valid":
                return result

        # If no valid email found
        return {
            "email": None,
            "status": "invalid",
            "message": "No valid email found",
            "user_name": "",
            "domain": domain,
            "mx": "",
            "connections": 0,
            "ver_ops": 0,
            "time_exec": 0.0
        }

    def find_valid_emails_bulk(self, email_data: List[Dict[str, Union[str, List[str]]]]) -> List[Dict[str, Union[str, List[str], Dict[str, Union[str, int, float, None]]]]]:
        all_valid_emails = []
        for data in email_data:
            domain = data.get("domain")
            names = data.get("names", [])
            valid_email = self.find_valid_emails(domain, names)
            all_valid_emails.append({
                "domain": domain,
                "names": names,
                "valid_email": valid_email
            })
        return all_valid_emails

    def split_list_data(self, target):
        new_target = []
        for i in target:
            new_target.extend(i.split(" "))
        return new_target

    def generate_email_variants(self, names: List[str], domain: str, normalize: bool = True) -> List[str]:
        if normalize:
            names = [unidecode(n).lower().strip() for n in names if n]
        first, last = names[0], names[-1] if len(names) > 1 else ("", names[0])
        patterns = [
            f"{first}@{domain}",
            f"{first}{last}@{domain}",
            f"{first}.{last}@{domain}",
            f"{first}_{last}@{domain}",
            f"{last}.{first}@{domain}",
            f"{first[0]}{last}@{domain}",
            f"{first[0]}.{last}@{domain}",
            f"{first}{last[0]}@{domain}",
            f"{first[0]}{last[0]}@{domain}",
            f"{last}{first}@{domain}",
            f"{last}@{domain}"
        ]
        return list(set(patterns))

    def generate_prefixes(self, domain: str) -> List[str]:
        prefixes = ['admin', 'contact', 'hello', 'team', 'support', 'info', 'mail']
        return [f"{prefix}@{domain}" for prefix in prefixes]


