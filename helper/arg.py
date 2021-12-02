import argparse
parser = argparse.ArgumentParser(
    description="process helper",
)
parser.add_argument('-i','--ida',  action="store_true", help="ida mode")
parser.add_argument('-p','--port',type=int, help="specify port")
args = parser.parse_args()
