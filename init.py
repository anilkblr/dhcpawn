#!/usr/bin/env python3
import os
import glob
import yaml
from datetime import datetime
import requests
import json
import subprocess
from time import sleep

def insert_missing_import():
    """
    adding missing import sqlalchemy_utils
    to the new version file"""

    to_add = "import sqlalchemy_utils\n"
    os.chdir("migrations/versions")
    new_fh = open("edited_init_db.py", "w")

    for f in glob.glob("*_init_db.py"):

        with open(f, "r") as fh:
            for line in fh:
                new_fh.write(line)
                if line.startswith("import"):
                    new_fh.write(to_add)
        new_fh.close()
        os.remove(f)
        os.rename("edited_init_db.py", f)
        break
    os.chdir("../../")

def prepare_db():
    pw = os.environ.get('PASS1')
    if pw is None:
        raise ValueError(f"Missing PASS1 env variable.")

    commands = [
        ("dropdb", ["dropdb", "dhcpawn"]),
        ("createdb", ["createdb", "dhcpawn"]),
        ("delmigrations", ["rm", "-rf", "migrations"]),
        ("migrateinit", ["cob", "migrate", "init"]),
        ("migraterev", ["cob", "migrate", "revision", "-m", "\"init db\""]),
        ("insert_missing_import", ""),
        ("migrateup", ["cob", "migrate", "up"]),
        ("get_skeleton", ["p", "dhcpldap", "-u", "admin", "-p", pw, "get_skeleton", "--lab", "Infi1"]),
        ("runtestserver", ["cob", "testserver", "-p", "5454"]),
        ("wait 5 seconds", ["sleep", "5"]),
        ("populate_skeleton", ["p", "dhcpawn", "populate", "--filename", "skeleton.yml", "--port", "5454"]),
        ]
    for cmd, r_gs in commands:

        print(f"running {cmd}")
        if cmd == "insert_missing_import":
            insert_missing_import()
            continue
        if cmd == "runtestserver":
            subprocess.Popen(r_gs, shell=False)
        else:
            r = subprocess.run(r_gs, shell=False)
            if r.returncode:
                raise RuntimeError(f"Failed prepare db step. {cmd}:{r.stderr}")



if __name__ == "__main__":


    prepare_db()
    # datafile = "data.yml"
    # with open(datafile, 'r') as stream:
    #     try:
        #     data = yaml.load(stream)

        # except yaml.YAMLError as exc:
        #     print(exc)
        # else:
        #     users_list = data['users']
