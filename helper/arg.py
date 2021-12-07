import argparse
parser = argparse.ArgumentParser(
    description="process helper",
)
parser.add_argument('-i','--ida',  action="store_true", help="ida mode")
parser.add_argument('-d','--debug',  action="store_true", help="debug mode")
parser.add_argument('-p','--port',type=int, help="specify port")
parser.add_argument('-P','--patch',type=float, help="patch AIO version")
args = parser.parse_args()
