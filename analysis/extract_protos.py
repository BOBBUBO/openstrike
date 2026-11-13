#!/usr/bin/env python3
"""Extract the embedded protobuf FileDescriptorProtos from libGame.so.

The Android build stores serialized FileDescriptorProto records in the
protodesc_cold ELF section.  This script locates them by their source-file
name and prints reconstructed .proto text without requiring protoc.
"""
from __future__ import annotations

import pathlib
import sys

WIRE = {0: "varint", 1: "64-bit", 2: "length-delimited", 5: "32-bit"}
LABEL = {1: "optional", 2: "required", 3: "repeated"}
TYPE = {
    1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
    6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 10: "group",
    11: "message", 12: "bytes", 13: "uint32", 14: "enum", 15: "sfixed32",
    16: "sfixed64", 17: "sint32", 18: "sint64",
}


def varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 70:
            raise ValueError("oversized varint")


def fields(data: bytes):
    pos = 0
    while pos < len(data):
        start = pos
        key, pos = varint(data, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = varint(data, pos)
        elif wire == 1:
            value = data[pos:pos + 8]
            pos += 8
        elif wire == 2:
            length, pos = varint(data, pos)
            value = data[pos:pos + length]
            if len(value) != length:
                raise ValueError("truncated length-delimited field")
            pos += length
        elif wire == 5:
            value = data[pos:pos + 4]
            pos += 4
        else:
            raise ValueError(f"unsupported wire type {wire} at {start}")
        yield number, wire, value


def one(data: bytes, number: int, default=None):
    for num, _wire, value in fields(data):
        if num == number:
            return value
    return default


def all_values(data: bytes, number: int):
    return [value for num, _wire, value in fields(data) if num == number]


def text(value) -> str:
    return value.decode("utf-8", "replace")


def parse_file(data: bytes):
    result = {
        "name": "", "package": "", "dependencies": [], "messages": [],
        "enums": [], "services": [], "syntax": "proto2",
    }
    for number, wire, value in fields(data):
        if number == 1:
            result["name"] = text(value)
        elif number == 2:
            result["package"] = text(value)
        elif number == 3:
            result["dependencies"].append(text(value))
        elif number == 4:
            result["messages"].append(parse_message(value))
        elif number == 5:
            result["enums"].append(parse_enum(value))
        elif number == 6:
            result["services"].append(parse_service(value))
        elif number == 12 and wire == 2:
            result["syntax"] = text(value)
    return result


def parse_message(data: bytes):
    result = {"name": "", "fields": [], "messages": [], "enums": [], "oneofs": []}
    for number, _wire, value in fields(data):
        if number == 1:
            result["name"] = text(value)
        elif number == 2:
            result["fields"].append(parse_field(value))
        elif number == 3:
            result["messages"].append(parse_message(value))
        elif number == 4:
            result["enums"].append(parse_enum(value))
        elif number == 8:
            result["oneofs"].append(text(one(value, 1, b"")))
    return result


def parse_field(data: bytes):
    result = {
        "name": text(one(data, 1, b"")), "number": one(data, 3, 0),
        "label": LABEL.get(one(data, 4, 1), "optional"),
        "type": TYPE.get(one(data, 5, 0), "unknown"),
        "type_name": text(one(data, 6, b"")), "json_name": text(one(data, 10, b"")),
    }
    return result


def parse_enum(data: bytes):
    result = {"name": text(one(data, 1, b"")), "values": []}
    for number, _wire, value in fields(data):
        if number == 2:
            result["values"].append((text(one(value, 1, b"")), one(value, 2, 0)))
    return result


def parse_service(data: bytes):
    result = {"name": text(one(data, 1, b"")), "methods": []}
    for number, _wire, value in fields(data):
        if number == 2:
            result["methods"].append({
                "name": text(one(value, 1, b"")),
                "input": text(one(value, 2, b"")),
                "output": text(one(value, 3, b"")),
            })
    return result


def qualified(prefix: str, name: str) -> str:
    return f"{prefix}.{name}" if prefix else name


def emit_message(out, message, prefix="", indent=0):
    name = qualified(prefix, message["name"])
    pad = "  " * indent
    out.append(f"{pad}message {message['name']} {{")
    for oneof in message["oneofs"]:
        out.append(f"{pad}  // oneof {oneof}")
    for field in message["fields"]:
        type_name = field["type_name"]
        if type_name.startswith("."):
            type_name = type_name[1:]
        elif type_name and field["type"] in ("message", "enum"):
            type_name = qualified(prefix, type_name)
        out.append(
            f"{pad}  {field['label']} {type_name or field['type']} "
            f"{field['name']} = {field['number']};"
        )
    for enum in message["enums"]:
        emit_enum(out, enum, indent + 1)
    for nested in message["messages"]:
        emit_message(out, nested, name, indent + 1)
    out.append(f"{pad}}}")


def emit_enum(out, enum, indent=0):
    pad = "  " * indent
    out.append(f"{pad}enum {enum['name']} {{")
    for value, number in enum["values"]:
        out.append(f"{pad}  {value} = {number};")
    out.append(f"{pad}}}")


def emit_file(out, proto):
    out.append(f"// Extracted from {proto['name']} in libGame.so")
    out.append(f'syntax = "{proto["syntax"]}";')
    out.append(f'package {proto["package"]};')
    out.append("")
    for dependency in proto["dependencies"]:
        out.append(f'import "{dependency}";')
    if proto["dependencies"]:
        out.append("")
    for enum in proto["enums"]:
        emit_enum(out, enum)
        out.append("")
    for message in proto["messages"]:
        emit_message(out, message)
        out.append("")
    for service in proto["services"]:
        out.append(f"service {service['name']} {{")
        for method in service["methods"]:
            inp = method["input"].lstrip(".")
            outp = method["output"].lstrip(".")
            out.append(f"  rpc {method['name']} ({inp}) returns ({outp});")
        out.append("}")
        out.append("")


def extract(data: bytes, source_name: str):
    needle = source_name.encode()
    # The descriptor starts with FileDescriptorProto.name (field 1, wire 2).
    marker = b"\x0a" + bytes([len(needle)]) + needle
    pos = data.find(marker)
    if pos < 0:
        raise ValueError(f"descriptor not found: {source_name}")

    # These descriptors do not carry an explicit syntax field.  The generated
    # descriptor table follows the raw bytes with its own offset metadata, so
    # walk only the actual FileDescriptorProto fields and stop at that table.
    valid_fields = {1, 2, 3, 4, 5, 6, 7, 8, 9, 12}
    cursor = pos
    while cursor < len(data):
        key_start = cursor
        key, cursor2 = varint(data, cursor)
        number, wire = key >> 3, key & 7
        if number not in valid_fields:
            cursor = key_start
            break
        if wire == 0:
            _value, cursor2 = varint(data, cursor2)
        elif wire == 1:
            cursor2 += 8
        elif wire == 2:
            length, cursor2 = varint(data, cursor2)
            if cursor2 + length > len(data):
                cursor = key_start
                break
            cursor2 += length
        elif wire == 5:
            cursor2 += 4
        else:
            cursor = key_start
            break
        cursor = cursor2
        if number == 12 and wire == 2:
            break
    return data[pos:cursor], pos, cursor


def main():
    so = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else
                      "decompiled/native/lib/arm64-v8a/libGame.so")
    out_dir = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "analysis/protos")
    out_dir.mkdir(parents=True, exist_ok=True)
    data = so.read_bytes()
    names = ["client_gate.proto", "common.proto", "gate_game.proto", "server_common.proto"]
    for name in names:
        raw, start, end = extract(data, name)
        proto = parse_file(raw)
        lines = []
        emit_file(lines, proto)
        destination = out_dir / name
        destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"{name}: offset={start:#x}..{end:#x}, {len(raw)} bytes, "
              f"{len(proto['messages'])} messages, {len(proto['services'])} services")
        print(destination)


if __name__ == "__main__":
    main()
