#!python
import argparse
from glpi import GLPI
from pprint import pprint

def setupArgumentsParsing():
    parser = argparse.ArgumentParser(
        prog="GLPI REST API client",
        description="This program can be used to retriview informations from a GLPI server.",
    )

    parser.add_argument("-url", "--url")
    parser.add_argument("-u", "--username")
    parser.add_argument("-p", "--password")
    parser.add_argument("-ut", "--userToken")
    parser.add_argument("-at", "--applicationToken")
    parser.add_argument("-ap", "--APIPath", default="/apirest.php")

    return parser.parse_args()


if __name__ == "__main__":
    args = setupArgumentsParsing()

    server = GLPI(args.url)

    if args.applicationToken:
        server.setApplicationToken(args.applicationToken)

    if args.username and args.password:
        server.authUsingCredentials(args.username, args.password)

    if args.userToken:
        server.authUsingToken(args.userToken)
