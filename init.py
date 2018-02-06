#!/usr/bin/env python3
import os
import glob
import subprocess

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
def prepare_env():

    pass1 = os.getenv("PASS1")
    export_vars = [("_DHCPAWN_PRODUCTION_LDAP_DN", "cn=DHCP Config,dc=infinidat,dc=com"),
                   ("_DHCPAWN_PRODUCTION_LDAP", "True"),
                   ("_DHCPAWN_PRODUCTION_LDAP_URI","ldap://dhcp-prod01:389"),
                   ("_DHCPAWN_PRODUCTION_BIND_CN","cn=admin,dc=infinidat,dc=com"),
                   ("_DHCPAWN_PRODUCTION_PW",pass1)]
    for envvar, val in export_vars:
        os.environ[envvar] = val


def prepare_db():
    pw = os.environ.get('PASS1')
    if pw is None:
        raise ValueError(f"Missing PASS1 env variable.")




    commands = [
        ("dropdb", ["dropdb", "dhcpawn"]),
        ("createdb", ["createdb", "dhcpawn"]),
        ("delmigrations", ["rm", "-rf", "migrations"]),
        ("setenv", ""),
        ("migrateinit", ["cob", "migrate", "init"]),
        ("migraterev", ["cob", "migrate", "revision", "-m", "\"init db\""]),
        ("insert_missing_import", ""),
        ("migrateup", ["cob", "migrate", "up"]),
        # ("get_skeleton", ["p", "dhcpldap", "-u", "admin", "-p", pw, "get_skeleton", "--lab", "Infi1", "--deployed"]),
        # ("runtestserver", ["cob", "testserver", "-p", "5454"]),
        # ("wait 5 seconds", ["sleep", "5"]),
        # ("populate_skeleton", ["p", "dhcpawn", "populate", "--filename", "skeleton.yml", "--port", "5454"]),
        ]
    for cmd, r_gs in commands:

        print(f"running {cmd}")
        if cmd == "get_skeleton" or cmd == "populate_skeleton" :
            continue
        if cmd == "insert_missing_import":
            insert_missing_import()
            continue
        if cmd == "setenv":
            prepare_env()
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
