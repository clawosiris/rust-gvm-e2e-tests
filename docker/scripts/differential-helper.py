#!/usr/bin/env python3
"""Run a single GMP command through python-gvm and emit normalized JSON."""

import argparse
import json
import os
import sys

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

SOCKET_PATH = os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock")
USERNAME = os.environ.get("GVM_ADMIN_USER", "admin")
PASSWORD = os.environ.get("GVM_ADMIN_PASS", "admin")


def _text(parent, tag):
    child = parent.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def _id_name_list(response, element_tag):
    items = []
    for element in response.findall(element_tag):
        items.append({
            "id": element.get("id", ""),
            "name": _text(element, "name"),
        })
    return items


def _report_formats(response):
    items = []
    for element in response.findall("report_format"):
        items.append({
            "id": element.get("id", ""),
            "name": _text(element, "name"),
            "extension": _text(element, "extension"),
            "content_type": _text(element, "content_type"),
        })
    return items


def _feeds(response):
    items = []
    for element in response.findall("feed"):
        syncing = element.find("currently_syncing") is not None
        syncing_text = _text(element, "currently_syncing").lower()
        if syncing_text in {"1", "true", "yes"}:
            syncing = True
        items.append({
            "type": _text(element, "type"),
            "name": _text(element, "name"),
            "status": _text(element, "status"),
            "currently_syncing": syncing,
        })
    return items


def run_command(args):
    connection = UnixSocketConnection(path=SOCKET_PATH)
    transform = EtreeCheckCommandTransform()

    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)

        if args.command == "get_version":
            response = gmp.get_version()
            return {"version": _text(response, "version")}
        if args.command == "get_scan_configs":
            return {"scan_configs": _id_name_list(gmp.get_scan_configs(), "config")}
        if args.command == "get_scanners":
            return {"scanners": _id_name_list(gmp.get_scanners(), "scanner")}
        if args.command == "get_port_lists":
            return {"port_lists": _id_name_list(gmp.get_port_lists(), "port_list")}
        if args.command == "get_feeds":
            return {"feeds": _feeds(gmp.get_feeds())}
        if args.command == "get_report_formats":
            return {"report_formats": _report_formats(gmp.get_report_formats())}
        if args.command == "get_targets":
            return {"targets": _id_name_list(gmp.get_targets(), "target")}
        if args.command == "create_target":
            if not args.name or not args.hosts or not args.port_list_id:
                raise ValueError("create_target requires --name, --hosts, and --port-list-id")
            response = gmp.create_target(
                name=args.name,
                hosts=[host.strip() for host in args.hosts.split(",") if host.strip()],
                port_list_id=args.port_list_id,
            )
            target_id = response.get("id", "") if hasattr(response, "get") else ""
            return {"id": target_id, "name": args.name}
        if args.command == "delete_target":
            if not args.target_id:
                raise ValueError("delete_target requires --target-id")
            response = gmp.delete_target(args.target_id, ultimate=True)
            status = response.get("status", "") if hasattr(response, "get") else ""
            return {"status": status, "id": args.target_id}

    raise ValueError(f"unsupported command: {args.command}")


def parse_args():
    parser = argparse.ArgumentParser(description="Cross-client differential helper")
    parser.add_argument(
        "command",
        choices=[
            "get_version",
            "get_scan_configs",
            "get_scanners",
            "get_port_lists",
            "get_feeds",
            "get_report_formats",
            "get_targets",
            "create_target",
            "delete_target",
        ],
    )
    parser.add_argument("--name")
    parser.add_argument("--hosts")
    parser.add_argument("--port-list-id")
    parser.add_argument("--target-id")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        data = run_command(args)
        payload = {"status": "ok", "command": args.command, "data": data}
        print(json.dumps(payload))
        return 0
    except Exception as exc:
        payload = {
            "status": "error",
            "command": args.command,
            "error": str(exc),
        }
        print(json.dumps(payload))
        return 1


if __name__ == "__main__":
    sys.exit(main())
