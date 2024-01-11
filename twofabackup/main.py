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
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Self

from cryptography.fernet import Fernet, InvalidToken
from rich.console import Console, ConsoleOptions, RenderResult
from rich.panel import Panel
from rich.prompt import Prompt

__version__ = "1.1.0"

DB_URI = Path.home() / ".config/2FA_codes.db"

console = Console(color_system="truecolor")
error_console = Console(stderr=True, style="bold red")


@dataclass
class ServiceCodes:
    id: int
    service_name: str
    date_added: str
    description: Optional[str]
    encrypted_backup_codes: Optional[bytes] = None
    decrypted_backup_codes: Optional[str] = ""

    def __rich_console__(
        self, console: Console, options: ConsoleOptions
    ) -> RenderResult:
        today = datetime.fromisoformat(self.date_added)
        contents = ""
        if self.description:
            contents += f"[bold]{self.description}[/]\n\n"
        contents += str(self.decrypted_backup_codes)
        panel = Panel(
            contents,
            title=self.service_name,
            subtitle=f"Added on: {today.strftime('%d/%m/%Y')}",
        )
        yield panel

    @classmethod
    def servicecodes_factory(cls, cursor, row) -> Self:
        fields = [column[0] for column in cursor.description]
        return cls(**{k: v for k, v in zip(fields, row)})


class KeyHolder:
    def __init__(self):
        self.engine = self.fernet_factory()

    def fernet_factory(self) -> Fernet:
        if count_entries_db() == 0:
            key = self.generate_new_key()
            console.print(
                f"Your key is [blue bold] {key.decode()} [/] \nSave this code carefully!"
            )
        else:
            key = self.ask_key_from_user()

        try:
            fernet = Fernet(key)
        except ValueError:
            error_console.print("Invalid key! #001")
            raise SystemExit(1)
        return fernet

    @staticmethod
    def generate_new_key() -> bytes:
        return Fernet.generate_key()

    @staticmethod
    def ask_key_from_user() -> bytes:
        key = Prompt.ask("Provide your encryption key", password=True)
        return key.encode()

    def encrypt_codes(self, clear_codes: str) -> bytes:
        return self.engine.encrypt(clear_codes.encode())

    def decrypt_item(self, data: bytes) -> str:
        try:
            decrypted_data = self.engine.decrypt(data).decode()
        except InvalidToken:
            error_console.print("Invalid key! #002")
            raise SystemExit(1)
        return decrypted_data


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


def input_in_db(args: argparse.Namespace) -> None:
    input_sql = """\
        INSERT INTO servicecodes (
            service_name, 
            description, 
            encrypted_backup_codes, 
            date_added ) 
        VALUES (?,?,?,?)
    """
    key = KeyHolder()
    input = Path(args.file.name).read_text().strip()
    encrypted_codes = key.encrypt_codes(input)
    timestamp = datetime.now()
    with sqlite3.connect(DB_URI) as db:
        db.execute(
            input_sql,
            (args.name, args.description, encrypted_codes, timestamp),
        )
    console.print(f"[green bold]\t>> Added {args.name} to database")


def decrypt_all(args: argparse.Namespace) -> None:
    if count_entries_db() < 1:
        error_console.print("Add new entries to db first.")
        error_console.print("See `twofabackup add -h` for details")
        raise SystemExit(1)
    key = KeyHolder()
    select_all_sql = """\
        SELECT 
            id, service_name, description, encrypted_backup_codes, date_added
        FROM servicecodes
    """
    DB_URI.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB_URI) as db:
        cur = db.cursor()
        cur.row_factory = ServiceCodes.servicecodes_factory
        db_response: list[ServiceCodes] = cur.execute(select_all_sql).fetchall()
    for row in db_response:
        if not row.encrypted_backup_codes:
            raise ValueError(
                "Something went wrong in retrieving encrypted data from database"
            )
        row.decrypted_backup_codes = key.decrypt_item(row.encrypted_backup_codes)
        console.print(row, new_line_start=True)


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
