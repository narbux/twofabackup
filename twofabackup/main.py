#!/usr/bin/env python3

"""Copyright (C) 2024  Marnix Enthoven

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>."""

import argparse
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel
from rich.console import Console, ConsoleOptions, RenderResult
from rich.panel import Panel
from rich.prompt import Prompt

__version__ = "1.0.0"

DB_URI = Path.home() / ".config/2FA_codes.db"

console = Console(color_system="truecolor")
error_console = Console(stderr=True, style="bold red")


class ServiceCodesBase(BaseModel):
    service_name: str
    description: Optional[str]
    encrypted_backup_codes: Optional[bytes] = None
    decrypted_backup_codes: Optional[str] = ""


class ServiceCodes(ServiceCodesBase):
    id: int
    date_added: datetime

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:
        panel = Panel(
            str(self.decrypted_backup_codes),
            title=self.service_name,
            subtitle=f"Added on: {self.date_added.strftime('%d/%m/%Y')}",
        )
        yield panel


def servicecodes_factory(cursor, row):
    fields = [column[0] for column in cursor.description]
    return ServiceCodes(**{k: v for k, v in zip(fields, row)})


def create_db() -> None:
    create_tables_sql = """\
        CREATE TABLE IF NOT EXISTS servicecodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT NOT NULL UNIQUE,
            description TEXT,
            encrypted_backup_codes BLOB,
            date_added TEXT
    )"""
    with sqlite3.connect(DB_URI) as db:
        db.execute(create_tables_sql)


def count_entries_db() -> int:
    count_sql = """\
        SELECT COUNT() FROM servicecodes
    """
    with sqlite3.connect(DB_URI) as db:
        cur = db.cursor()
        count: list[int] = cur.execute(count_sql).fetchone()
    return count[0]


def generate_new_key() -> bytes:
    return Fernet.generate_key()


def ask_key_from_user() -> bytes:
    key = Prompt.ask("Provide your encryption key", password=True)
    return key.encode()


def get_key() -> Fernet:
    if count_entries_db() == 0:
        key = generate_new_key()
        console.print(
            f"Your key is [blue bold] {key.decode()} [/] \nSave this code carefully!"
        )
    else:
        key = ask_key_from_user()
    try:
        fernet = Fernet(key)
    except ValueError:
        error_console.print("Invalid key! #001")
        raise SystemExit(1)
    return fernet


def encrypt_codes(clear_codes: str, fernet: Fernet) -> bytes:
    return fernet.encrypt(clear_codes.encode())


def input_in_db(args: argparse.Namespace) -> None:
    key = get_key()
    input_sql = """\
        INSERT INTO servicecodes (service_name, description, encrypted_backup_codes, date_added) 
        VALUES (?,?,?,?)
    """
    input = Path(args.file.name).read_text().strip()
    encrypted_codes = encrypt_codes(input, key)
    timestamp = datetime.now()
    with sqlite3.connect(DB_URI) as db:
        db.execute(
            input_sql,
            (args.name, args.description, encrypted_codes, timestamp),
        )
    console.print(f"[green bold]\t>> Added {args.name} to database")


def decrypt_item(data: bytes, fernet: Fernet) -> str:
    try:
        decrypted_data = fernet.decrypt(data).decode()
    except InvalidToken:
        error_console.print("Invalid key! #002")
        raise SystemExit(1)
    return decrypted_data


def decrypt_all(args: argparse.Namespace) -> None:
    key = get_key()
    select_all_sql = """\
        SELECT 
            id, service_name, description, encrypted_backup_codes, date_added
        FROM servicecodes
    """
    DB_URI.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB_URI) as db:
        cur = db.cursor()
        cur.row_factory = servicecodes_factory
        res: list[ServiceCodes] = cur.execute(select_all_sql).fetchall()
    for x in res:
        if not x.encrypted_backup_codes:
            raise ValueError
        x.decrypted_backup_codes = decrypt_item(x.encrypted_backup_codes, key)
        console.print(x)
        console.print("")


def options() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="twofabackup",
        description="Encrypted 2FA backup codes storage",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.set_defaults(func=decrypt_all)

    subparser = parser.add_subparsers(
        help="Add new backupcodes from a text file or stdin"
    )

    add_option = subparser.add_parser("add")
    add_option.add_argument(
        "-f",
        "--file",
        type=argparse.FileType("r"),
        help="Text file with backupcodes",
    )
    add_option.add_argument(
        "-n", "--name", action="store", required=True, help="Name of the service"
    )
    add_option.add_argument(
        "-d",
        "--description",
        action="store",
        required=False,
        help="Optional description of service",
    )
    add_option.set_defaults(func=input_in_db)

    return parser.parse_args()


def main() -> None:
    args = options()
    create_db()
    args.func(args)


if __name__ == "__main__":
    main()
