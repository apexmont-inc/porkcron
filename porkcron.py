#!/usr/bin/env python3

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from urllib import request

# https://porkbun.com/api/json/v3/documentation
DEFAULT_API_URL = "https://api.porkbun.com/api/json/v3"
DEFAULT_CERTIFICATE_PATH = "/etc/porkcron/{domain}/certificate.pem"
DEFAULT_PRIVATE_KEY_PATH = "/etc/porkcron/{domain}/private_key.pem"
DEFAULT_BACKUP_PATH = None

DOMAIN_PLACEHOLDER = "{domain}"


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    logging.info("running SSL certificate renewal script")

    domains = getenv_or_exit("DOMAIN").split(",")
    api_key = getenv_or_exit("API_KEY")
    secret_key = getenv_or_exit("SECRET_KEY")

    certificate_path_template = os.getenv("CERTIFICATE_PATH", DEFAULT_CERTIFICATE_PATH)
    if len(domains) > 1 and DOMAIN_PLACEHOLDER not in certificate_path_template:
        exit(f"CERTIFICATE_PATH must contain the {DOMAIN_PLACEHOLDER} placeholder")

    private_key_path_template = os.getenv("PRIVATE_KEY_PATH", DEFAULT_PRIVATE_KEY_PATH)
    if len(domains) > 1 and DOMAIN_PLACEHOLDER not in private_key_path_template:
        exit(f"PRIVATE_KEY_PATH must contain the {DOMAIN_PLACEHOLDER} placeholder")

    backup_path_template = os.getenv("BACKUP_PATH", DEFAULT_BACKUP_PATH)
    if backup_path_template is not None:
        if len(domains) > 1 and DOMAIN_PLACEHOLDER not in backup_path_template:
            exit(f"BACKUP_PATH must contain the {DOMAIN_PLACEHOLDER} placeholder when backup is specified.")

    folder_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    for domain in domains:
        url = os.getenv("API_URL", DEFAULT_API_URL) + "/ssl/retrieve/" + domain
        body = json.dumps({"apikey": api_key, "secretapikey": secret_key}).encode()
        headers = {"Content-Type": "application/json"}

        logging.info(f"downloading SSL bundle for {domain}")
        req = request.Request(url, data=body, headers=headers, method="POST")
        with request.urlopen(req) as resp:
            data = json.load(resp)

        if data["status"] == "ERROR":
            exit(data["message"])

        backup_path = None
        if backup_path_template:
            backup_path = Path(backup_path_template.replace(DOMAIN_PLACEHOLDER, domain))

        certificate_path = Path(certificate_path_template.replace(DOMAIN_PLACEHOLDER, domain))
        certificate_chain = data["certificatechain"]
        certificate_matches = False
        if certificate_path.is_file():
            logging.info(f"checking certificate {certificate_path} for differences...")
            certificate_matches = compare_file(certificate_path, certificate_chain)
            if certificate_matches:
                logging.info(f"skipping matching certificate {certificate_path}")
            else:
                if backup_path is not None:
                    file_name = certificate_path.name
                    backup_file_path=Path(backup_path, folder_timestamp, file_name)
                    logging.info(f"backing up certificate to {backup_file_path}")
                    backup_file_path.parent.mkdir(parents=True, exist_ok=True)
                    certificate_path.copy(backup_file_path, preserve_metadata=True)

        if not certificate_matches:
            logging.info(f"saving certificate to {certificate_path}")
            certificate_path.parent.mkdir(parents=True, exist_ok=True)
            certificate_path.write_text(certificate_chain)

        private_key_path = Path(private_key_path_template.replace(DOMAIN_PLACEHOLDER, domain))
        private_key = data["privatekey"]
        private_key_matches = False
        if private_key_path.is_file():
            logging.info(f"checking private key {private_key_path} for differences...")
            private_key_matches = compare_file(private_key_path, private_key)
            if private_key_matches:
                logging.info(f"skipping matching private key {private_key_path}")
            else:
                if backup_path is not None:
                    file_name = private_key_path.name
                    backup_file_path=Path(backup_path, folder_timestamp, file_name)
                    logging.info(f"backing up certificate to {backup_file_path}")
                    backup_file_path.parent.mkdir(parents=True, exist_ok=True)
                    private_key_path.copy(backup_file_path, preserve_metadata=True)

        if not private_key_matches:
            logging.info(f"saving private key to {private_key_path}")
            private_key_path.parent.mkdir(parents=True, exist_ok=True)
            private_key_path.write_text(private_key)

        if not certificate_matches or private_key_matches:
            logging.info(f"SSL certificate for {domain} has been renewed")
        else:
            logging.info(f"No SSL certificate updates for {domain} have been detected")


def exit(msg: str) -> None:
    logging.error(msg)
    sys.exit(1)


def getenv_or_exit(key: str) -> str:
    value = os.getenv(key)
    if value is not None:
        return value

    logging.error(f"{key} is required but not set")
    sys.exit(1)

def compare_file(file: Path, contents: str) -> bool:
    file_contents = file.read_text(encoding="utf-8").strip()
    return file_contents == contents.strip()


if __name__ == "__main__":
    main()
