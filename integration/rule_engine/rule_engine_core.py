#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Rule-based engine for filtering false positives in Chain-Fox analysis results.

The AI-driven filtering is under development and will be integrated in future versions.
"""

import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Pattern, Any


def load_filter_patterns(file_path: str = "filter_out.txt") -> List[Pattern]:
    """
    Load filtering rules from a text file and compile them into regex patterns.
    
    :param file_path: Path to the filter configuration file.
    :return: List of compiled regex patterns.
    """
    regex_filters = []

    with open(file_path, "r", encoding="utf-8") as infile:
        for line in infile:
            path = line.strip()
            if not path:
                continue
            if "/" in path:
                crate_with_version, subpath = path.split("/", 1)
                crate_name = crate_with_version.split("-")[0]
                regex = rf"{re.escape(crate_name)}-[^/]+/{re.escape(subpath)}"
            else:
                regex = rf"{re.escape(path)}"
            regex_filters.append(re.compile(regex))

    # Additional hardcoded rules
    regex_filters.append(re.compile(r"\[lockbud\] Not supported to display yet\."))
    regex_filters.append(re.compile(r"rustlib/src/rust/library"))

    return regex_filters


def load_analysis_result(file_path: str) -> Dict[str, Any]:
    """
    Load the raw JSON analysis result.

    :param file_path: Path to the JSON result file.
    :return: Parsed JSON as a Python dictionary.
    """
    with open(file_path, "r", encoding="utf-8") as infile:
        return json.load(infile)


def apply_filter(data: Dict[str, Any], filters: List[Pattern]) -> None:
    """
    Filter out false positives in-place based on file path regex rules.

    :param data: Parsed JSON data.
    :param filters: List of compiled regex patterns.
    """
    if "data" not in data:
        return

    for package in data.get("data", []):
        raw_reports = package.get("raw_reports", [])
        filtered = [
            report for report in raw_reports
            if not any(regex.search(report.get("file", "")) for regex in filters)
        ]
        package["raw_reports"] = filtered
        package["count"] = len(filtered)


def write_filtered_result(data: Dict[str, Any], output_path: str = "filtered_output.json") -> None:
    """
    Write the filtered analysis result to a JSON file.

    :param data: Filtered JSON data.
    :param output_path: Path to the output file.
    """
    with open(output_path, "w", encoding="utf-8") as outfile:
        json.dump(data, outfile, ensure_ascii=False, indent=2)


def main() -> None:
    """
    Entry point of the script.
    """
    # Optionally allow input path override from command line
    result_path = sys.argv[1] if len(sys.argv) > 1 else "paritytech/polkadot-sdk/All-Targets.json"
    filters = load_filter_patterns()

    print("Loaded regex filters:")
    for pattern in filters:
        print(f"  - {pattern.pattern}")

    result = load_analysis_result(result_path)
    apply_filter(result, filters)
    write_filtered_result(result)


if __name__ == "__main__":
    main()

