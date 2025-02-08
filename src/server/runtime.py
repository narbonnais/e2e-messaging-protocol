import argparse
import logging
import sys

from .lib import run_server

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('server.log', mode='a')
        ]
    )

def main():
    parser = argparse.ArgumentParser(description="Raw TCP server runtime")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", default=50000, type=int, help="Port to bind")
    args = parser.parse_args()

    setup_logging()
    run_server(args.host, args.port)

if __name__ == "__main__":
    main()
