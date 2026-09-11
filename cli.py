"""
cli.py — command-line entry point for the PhishIt pipeline.

Usage:
    python cli.py path/to/email.eml
    python cli.py path/to/email.eml --quiet   # suppress module stdout noise, print only the JSON result
"""

import argparse
import json
import sys

from pipeline import process_email, PipelineInputError


def main():
    parser = argparse.ArgumentParser(description="Run the PhishIt analysis pipeline on one .eml file")
    parser.add_argument("eml_path", help="Path to the .eml file to analyze")
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress the modules' own stdout logging and print only the final JSON result",
    )
    args = parser.parse_args()

    if args.quiet:
        import io
        import contextlib
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                result = process_email(args.eml_path)
        except PipelineInputError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        try:
            result = process_email(args.eml_path)
        except PipelineInputError as e:
            print(f"Error: {e}")
            sys.exit(1)

    print(json.dumps(result, indent=2, default=str))
    print(f"\nWritten to: {result['_output_path']}", file=sys.stderr)


if __name__ == "__main__":
    main()
