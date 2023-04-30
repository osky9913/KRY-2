# author: xosval03
import sys
from client import start_client
from server import start_server

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 main.py TYPE PORT")
        sys.exit(1)
    type = sys.argv[1]
    port = int(sys.argv[2])

    if type == 's':
        start_server(port)
    elif type == 'c':
        start_client(port)
    else:
        print(f"Invalid TYPE '{type}'")
        sys.exit(1)