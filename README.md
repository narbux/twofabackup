# TwoFaBackup

Application to safely and locally store backup codes for two factor authenticated
services. It is good pracice to store these codes in an other location than in
e.g. the password manager that stores the first factor or in the authenticator app
that generates the one time passwords.

The backup is locally stored in a sqlite database with symmetric Fermet encryption.
The sqlite database stores a `id`, `service name`, `description [optional]`,
`the backupcodes [encrypted]`, `date added`. A new encryption key will be generated
when first codes are saved in the db.
The location of the database is `$HOME/.config/2FA_codes.db`.

!! Do not lose the generated key, or your codes will be lost !!

### Main help

```python
$ twofabackup ---help
usage: twofabackup [-h] [-v] {add} ...

Encrypted 2FA backup codes storage

positional arguments:
  {add}          Add new backupcodes from a text file or stdin

options:
  -h, --help     show this help message and exit
  -v, --version  show program's version number and exit
```

### Add codes help

```python
$ twofabackup add --help
usage: twofabackup add [-h] [-f FILE] -n NAME [-d DESCRIPTION]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Text file with backupcodes
  -n NAME, --name NAME  Name of the service
  -d DESCRIPTION, --description DESCRIPTION
                        Optional description of service
```
