import argparse
import json
from pathlib import Path
from .core import ParseError, read_capture
from .analysis import analyze


def main():
    parser = argparse.ArgumentParser(
        description="Inspect a bounded offline classic-PCAP file"
    )
    parser.add_argument("capture", type=Path)
    parser.add_argument(
        "--output", type=Path, help="Exclusive-create JSON output; default is stdout"
    )
    args = parser.parse_args()
    try:
        capture = read_capture(args.capture)
        value = {"capture": capture.as_dict(), "analysis": analyze(capture)}
        text = json.dumps(value, indent=2, allow_nan=False) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
        else:
            print(text, end="")
    except (ParseError, OSError, ValueError) as error:
        parser.exit(2, f"{error}\n")


if __name__ == "__main__":
    main()
