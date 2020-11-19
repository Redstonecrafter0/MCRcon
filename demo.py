import argparse
from mcrcon import McRcon
from getpass import getpass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", type=str)
    parser.add_argument("port", type=int)
    parser.add_argument("password", type=str, required=False)
    args = parser.parse_args()
    password = args.password

    rcon = McRcon(args.host, args.port)

    try:
        if not password:
            password = getpass('Password: ')
        result = rcon.login(password)
        if not result:
            print("Incorrect password")
            return

        while True:
            request = input('>')
            if request in ('quit', 'exit'):
                rcon.close()
                print('Bye')
                break
            response = rcon.command(request)
            print(response)
    finally:
        rcon.close()

if __name__ == '__main__':
    main()
