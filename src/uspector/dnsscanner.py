# Uspector – Copyright (c) 2026 Menahem Levinski

"""
Standard-library-only DNS diagnostics for Uspector.

Supports DNS record lookups over UDP with TCP fallback, reverse lookups,
basic SPF/DMARC/DKIM checks, and DNSSEC-related record inspection.

DNSSEC records are inspected, not cryptographically validated.
"""

from __future__ import annotations

import base64
import ipaddress
import math
import os
import secrets
import socket
import struct
import time
from typing import Any, Iterable


class DNSScanner:
    TYPE_CODES = {
        "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
        "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "NAPTR": 35,
        "CAA": 257, "DS": 43, "RRSIG": 46, "DNSKEY": 48, "NSEC": 47,
        "NSEC3": 50, "TLSA": 52, "HTTPS": 65, "SVCB": 64,
    }

    RCODE_NAMES = {
        0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
        4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
        8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
    }

    def __init__(
        self,
        nameservers: Iterable[str] | None = None,
        timeout: float = 2.0,
        retries: int = 2,
        port: int = 53,
    ) -> None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError("timeout must be a positive number")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite positive number")
        if isinstance(retries, bool) or not isinstance(retries, int):
            raise TypeError("retries must be a positive integer")
        if retries < 1:
            raise ValueError("retries must be a positive integer")
        if isinstance(port, bool) or not isinstance(port, int):
            raise TypeError("port must be an integer between 1 and 65535")
        if not (1 <= port <= 65535):
            raise ValueError("port must be between 1 and 65535")

        self.timeout = float(timeout)
        self.retries = retries
        self.port = port

        if nameservers is None:
            self.nameservers = self._discover_nameservers() or ["1.1.1.1"]
        else:
            self.nameservers = list(nameservers)

        self.nameservers = list(dict.fromkeys(self.nameservers))

    @staticmethod
    def _discover_nameservers() -> list[str]:
        """Discover configured DNS resolvers without external dependencies."""
        active_found: list[str] = []
        found: list[str] = []

        if os.name == "nt":
            try:
                import winreg

                key_path = (
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                    r"\Interfaces"
                )

                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, key_path
                ) as root:
                    index = 0

                    while True:
                        try:
                            interface_name = winreg.EnumKey(root, index)
                        except OSError:
                            break

                        index += 1

                        try:
                            with winreg.OpenKey(
                                root, interface_name
                            ) as interface:
                                interface_dns: list[str] = []
                                for value_name in (
                                    "NameServer", "DhcpNameServer"
                                ):
                                    try:
                                        value, _ = winreg.QueryValueEx(
                                            interface, value_name
                                        )
                                    except OSError:
                                        continue

                                    if isinstance(value, str):
                                        interface_dns.extend(
                                            value.replace(",", " ")
                                            .replace(";", " ")
                                            .split()
                                        )

                                if not interface_dns:
                                    continue

                                found.extend(interface_dns)

                                is_active = False
                                for ip_value_name in (
                                    "IPAddress", "DhcpIPAddress"
                                ):
                                    try:
                                        ip_val, _ = winreg.QueryValueEx(
                                            interface, ip_value_name
                                        )
                                    except OSError:
                                        continue

                                    ips = (
                                        ip_val
                                        if isinstance(ip_val, list)
                                        else [ip_val]
                                        if isinstance(ip_val, str)
                                        else []
                                    )
                                    if any(
                                        item and item != "0.0.0.0"
                                        for item in ips
                                    ):
                                        is_active = True
                                        break

                                if is_active:
                                    active_found.extend(interface_dns)
                        except OSError:
                            continue

            except (ImportError, OSError):
                pass

        else:
            try:
                with open(
                    "/etc/resolv.conf",
                    encoding="utf-8",
                    errors="replace",
                ) as file:
                    for line in file:
                        fields = line.split("#", 1)[0].split()

                        if (
                            len(fields) >= 2
                            and fields[0] == "nameserver"
                        ):
                            found.append(fields[1])

            except OSError:
                pass

        def _validate_candidates(candidates: list[str]) -> list[str]:
            valid: list[str] = []

            for candidate in candidates:
                candidate = candidate.strip().strip("[]")
                ip_part, sep, zone = candidate.partition("%")

                try:
                    ip = ipaddress.ip_address(ip_part)
                except ValueError:
                    continue

                if sep and isinstance(ip, ipaddress.IPv6Address) and zone:
                    valid.append(f"{ip}%{zone}")
                else:
                    valid.append(str(ip))

            return list(dict.fromkeys(valid))

        preferred = _validate_candidates(active_found)
        return preferred if preferred else _validate_candidates(found)

    @staticmethod
    def _normalize_name(name: str) -> str:
        name = name.strip()

        if not name:
            raise ValueError("DNS name cannot be empty.")

        if name == ".":
            return "."

        return name.rstrip(".") + "."

    @classmethod
    def _encode_name(cls, name: str) -> bytes:
        normalized = cls._normalize_name(name)

        if normalized == ".":
            return b"\x00"

        output = bytearray()

        for label in normalized[:-1].split("."):
            try:
                raw = label.encode("idna")
            except UnicodeError as exc:
                raise ValueError(
                    f"Invalid DNS label: {label!r}"
                ) from exc

            if not raw or len(raw) > 63:
                raise ValueError(
                    f"DNS label must be 1-63 bytes: {label!r}"
                )

            output.append(len(raw))
            output.extend(raw)

        output.append(0)

        if len(output) > 255:
            raise ValueError(
                "DNS name exceeds the 255-byte wire-format limit."
            )

        return bytes(output)

    @staticmethod
    def _strip_trailing_dot(name: str) -> str:
        return "." if name == "." else name.rstrip(".")

    @staticmethod
    def _decode_name(
        packet: bytes,
        offset: int,
        max_wire_end: int | None = None,
    ) -> tuple[str, int]:
        """Decode a possibly compressed DNS name."""
        labels: list[str] = []
        cursor = offset
        next_offset: int | None = None
        jumps = 0
        visited: set[int] = set()
        packet_end = len(packet)

        while True:
            limit = (
                max_wire_end
                if next_offset is None and max_wire_end is not None
                else packet_end
            )

            if cursor >= limit:
                raise ValueError("DNS name extends beyond packet.")

            length = packet[cursor]

            if length & 0xC0 == 0xC0:
                if cursor + 1 >= limit:
                    raise ValueError(
                        "Incomplete DNS compression pointer."
                    )

                pointer = (
                    (length & 0x3F) << 8
                ) | packet[cursor + 1]

                if pointer >= packet_end or pointer in visited:
                    raise ValueError(
                        "Invalid or cyclic DNS compression pointer."
                    )

                visited.add(pointer)

                if next_offset is None:
                    next_offset = cursor + 2

                cursor = pointer
                jumps += 1

                if jumps > 128:
                    raise ValueError(
                        "Too many DNS compression pointers."
                    )

                continue

            if length & 0xC0:
                raise ValueError(
                    "Unsupported DNS label encoding."
                )

            cursor += 1

            if length == 0:
                if next_offset is None:
                    next_offset = cursor
                break

            if length > 63 or cursor + length > limit:
                raise ValueError("Invalid DNS label length.")

            raw = packet[cursor:cursor + length]

            try:
                labels.append(raw.decode("ascii"))
            except UnicodeDecodeError:
                labels.append(
                    raw.decode("utf-8", errors="replace")
                )

            cursor += length

            if len(labels) > 127:
                raise ValueError("Too many DNS labels.")

        return (
            ".".join(labels) if labels else ".",
            next_offset,
        )

    @staticmethod
    def _read_u16(
        packet: bytes,
        offset: int,
    ) -> tuple[int, int]:
        if offset + 2 > len(packet):
            raise ValueError("Unexpected end of DNS packet.")

        return struct.unpack_from("!H", packet, offset)[0], offset + 2

    @staticmethod
    def _read_u32(
        packet: bytes,
        offset: int,
    ) -> tuple[int, int]:
        if offset + 4 > len(packet):
            raise ValueError("Unexpected end of DNS packet.")

        return struct.unpack_from("!I", packet, offset)[0], offset + 4

    @staticmethod
    def _build_query(
        name: str,
        qtype: int,
        transaction_id: int,
        dnssec: bool = True,
    ) -> bytes:
        question = (
            DNSScanner._encode_name(name)
            + struct.pack("!HH", qtype, 1)
        )

        header = struct.pack(
            "!HHHHHH",
            transaction_id,
            0x0100,
            1,
            0,
            0,
            1 if dnssec else 0,
        )

        if not dnssec:
            return header + question

        # EDNS(0), 1232-byte advertised UDP payload, DNSSEC OK bit.
        opt = b"\x00" + struct.pack(
            "!HHIH", 41, 1232, 0x00008000, 0
        )

        return header + question + opt

    def _resolve_nameserver_target(
        self,
        nameserver: str,
        socktype: int,
    ) -> tuple[int, tuple[Any, ...], str]:
        family = (
            socket.AF_INET6
            if ":" in nameserver
            else socket.AF_INET
        )

        if "%" in nameserver:
            infos = socket.getaddrinfo(
                nameserver,
                self.port,
                family,
                socktype,
            )
            chosen_family, _, _, _, sockaddr = infos[0]
            return chosen_family, sockaddr, sockaddr[0]

        return family, (nameserver, self.port), nameserver

    @staticmethod
    def _addresses_match(source_ip: str, expected_ip: str) -> bool:
        if source_ip == expected_ip:
            return True

        try:
            return (
                ipaddress.ip_address(source_ip.split("%", 1)[0])
                == ipaddress.ip_address(expected_ip.split("%", 1)[0])
            )
        except ValueError:
            return False

    def _exchange(
        self,
        nameserver: str,
        query: bytes,
        transaction_id: int,
    ) -> tuple[bytes, float]:
        family, sockaddr, expected_ip = self._resolve_nameserver_target(
            nameserver, socket.SOCK_DGRAM
        )

        start = time.perf_counter()
        deadline = start + self.timeout

        with socket.socket(
            family, socket.SOCK_DGRAM
        ) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(query, sockaddr)

            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    raise TimeoutError("Timed out waiting for DNS response.")

                sock.settimeout(remaining)
                packet, source = sock.recvfrom(65535)

                if (
                    source[1] != self.port
                    or not self._addresses_match(source[0], expected_ip)
                ):
                    continue

                if len(packet) < 12:
                    continue

                response_id = struct.unpack_from("!H", packet, 0)[0]
                if response_id != transaction_id:
                    continue

                flags = struct.unpack_from("!H", packet, 2)[0]
                if not flags & 0x8000:
                    continue

                break

        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        if flags & 0x0200:
            packet = self._exchange_tcp(
                nameserver, query, transaction_id
            )

            elapsed_ms = (
                time.perf_counter() - start
            ) * 1000

        return packet, elapsed_ms

    def _exchange_tcp(
        self,
        nameserver: str,
        query: bytes,
        transaction_id: int,
    ) -> bytes:
        family, sockaddr, _ = self._resolve_nameserver_target(
            nameserver, socket.SOCK_STREAM
        )

        with socket.socket(
            family, socket.SOCK_STREAM
        ) as sock:
            sock.settimeout(self.timeout)
            sock.connect(sockaddr)
            sock.sendall(
                struct.pack("!H", len(query)) + query
            )

            size_bytes = self._recv_exact(sock, 2)
            size = struct.unpack("!H", size_bytes)[0]

            if size < 12:
                raise ValueError(
                    "DNS TCP response length is invalid."
                )

            packet = self._recv_exact(sock, size)

        if struct.unpack_from("!H", packet, 0)[0] != transaction_id:
            raise ValueError(
                "DNS TCP transaction ID mismatch."
            )

        flags = struct.unpack_from(
            "!H", packet, 2
        )[0]

        if not flags & 0x8000:
            raise ValueError(
                "TCP packet is not a DNS response."
            )

        return packet

    @staticmethod
    def _recv_exact(
        sock: socket.socket,
        count: int,
    ) -> bytes:
        chunks = bytearray()

        while len(chunks) < count:
            part = sock.recv(count - len(chunks))

            if not part:
                raise OSError(
                    "Connection closed during DNS TCP response."
                )

            chunks.extend(part)

        return bytes(chunks)

    @classmethod
    def _parse_rr(
        cls,
        packet: bytes,
        offset: int,
    ) -> tuple[dict[str, Any], int]:
        name, offset = cls._decode_name(packet, offset)
        rtype, offset = cls._read_u16(packet, offset)
        rclass, offset = cls._read_u16(packet, offset)
        ttl, offset = cls._read_u32(packet, offset)
        rdlength, offset = cls._read_u16(packet, offset)

        rstart = offset
        rend = rstart + rdlength

        if rend > len(packet):
            raise ValueError(
                "DNS record data extends beyond packet."
            )

        data = packet[rstart:rend]

        kind = next(
            (
                key for key, value in cls.TYPE_CODES.items()
                if value == rtype
            ),
            f"TYPE{rtype}",
        )

        record: dict[str, Any] = {
            "name": cls._strip_trailing_dot(name),
            "type": kind,
            "class": "IN" if rclass == 1 else rclass,
            "ttl": ttl,
        }

        if rtype == 1 and rdlength == 4:
            record["value"] = str(
                ipaddress.IPv4Address(data)
            )

        elif rtype == 28 and rdlength == 16:
            record["value"] = str(
                ipaddress.IPv6Address(data)
            )

        elif rtype in (2, 5, 12):
            value, pos = cls._decode_name(
                packet, rstart, max_wire_end=rend
            )
            if pos != rend:
                raise ValueError("Malformed DNS domain-name record.")
            record["value"] = cls._strip_trailing_dot(value)

        elif rtype == 15 and rdlength >= 3:
            preference = struct.unpack_from(
                "!H", packet, rstart
            )[0]

            exchange, pos = cls._decode_name(
                packet, rstart + 2, max_wire_end=rend
            )
            if pos != rend:
                raise ValueError("Malformed MX record.")

            clean_exchange = cls._strip_trailing_dot(exchange)
            record.update({
                "preference": preference,
                "exchange": clean_exchange,
                "value": f"{preference} {clean_exchange}",
            })

        elif rtype == 6:
            mname, pos = cls._decode_name(
                packet, rstart, max_wire_end=rend
            )
            rname, pos = cls._decode_name(
                packet, pos, max_wire_end=rend
            )
            serial, pos = cls._read_u32(packet, pos)
            refresh, pos = cls._read_u32(packet, pos)
            retry, pos = cls._read_u32(packet, pos)
            expire, pos = cls._read_u32(packet, pos)
            minimum, pos = cls._read_u32(packet, pos)

            if pos != rend:
                raise ValueError("Malformed SOA record.")

            record.update({
                "mname": cls._strip_trailing_dot(mname),
                "rname": cls._strip_trailing_dot(rname),
                "serial": serial,
                "refresh": refresh,
                "retry": retry,
                "expire": expire,
                "minimum": minimum,
                "value": (
                    f"{mname} {rname} {serial} {refresh} "
                    f"{retry} {expire} {minimum}"
                ),
            })

        elif rtype == 16:
            chunks: list[str] = []
            pos = rstart

            while pos < rend:
                size = packet[pos]
                pos += 1

                if pos + size > rend:
                    raise ValueError(
                        "Malformed TXT character-string."
                    )

                chunks.append(
                    packet[pos:pos + size].decode(
                        "utf-8", errors="replace"
                    )
                )

                pos += size

            record["chunks"] = chunks
            record["value"] = "".join(chunks)

        elif rtype == 257 and rdlength >= 2:
            flags = data[0]
            tag_len = data[1]

            if 2 + tag_len > len(data):
                raise ValueError("Malformed CAA record.")

            tag = data[2:2 + tag_len].decode(
                "ascii", errors="replace"
            )

            value = data[2 + tag_len:].decode(
                "utf-8", errors="replace"
            )

            record.update({
                "flags": flags,
                "tag": tag,
                "value": value,
            })

        elif rtype == 43 and rdlength >= 4:
            key_tag, algorithm, digest_type = struct.unpack_from(
                "!HBB", data, 0
            )

            record.update({
                "key_tag": key_tag,
                "algorithm": algorithm,
                "digest_type": digest_type,
                "digest": data[4:].hex(),
            })

        elif rtype == 48 and rdlength >= 4:
            flags, protocol, algorithm = struct.unpack_from(
                "!HBB", data, 0
            )

            record.update({
                "flags": flags,
                "protocol": protocol,
                "algorithm": algorithm,
                "public_key": data[4:].hex(),
            })

        elif rtype == 46 and rdlength >= 18:
            covered, algorithm, labels, original_ttl = (
                struct.unpack_from("!HBBI", data, 0)
            )

            expiration, inception, key_tag = (
                struct.unpack_from("!IIH", data, 8)
            )

            signer, pos = cls._decode_name(
                packet, rstart + 18, max_wire_end=rend
            )
            if pos > rend:
                raise ValueError("Malformed RRSIG record.")

            record.update({
                "type_covered": covered,
                "algorithm": algorithm,
                "labels": labels,
                "original_ttl": original_ttl,
                "expiration": expiration,
                "inception": inception,
                "key_tag": key_tag,
                "signer": cls._strip_trailing_dot(signer),
                "signature": packet[pos:rend].hex(),
            })

        elif rtype == 33 and rdlength >= 7:
            priority, weight, port = struct.unpack_from(
                "!HHH", data, 0
            )

            target, pos = cls._decode_name(
                packet, rstart + 6, max_wire_end=rend
            )
            if pos != rend:
                raise ValueError("Malformed SRV record.")

            clean_target = cls._strip_trailing_dot(target)
            record.update({
                "priority": priority,
                "weight": weight,
                "port": port,
                "target": clean_target,
                "value": f"{priority} {weight} {port} {clean_target}",
            })

        elif rtype == 52 and rdlength >= 4:
            usage, selector, matching_type = struct.unpack_from(
                "!BBB", data, 0
            )
            cert_data = data[3:].hex()
            record.update({
                "usage": usage,
                "selector": selector,
                "matching_type": matching_type,
                "certificate_data": cert_data,
                "value": f"{usage} {selector} {matching_type} {cert_data}",
            })

        elif rtype in (64, 65) and rdlength >= 3:
            priority = struct.unpack_from("!H", data, 0)[0]
            target, pos = cls._decode_name(
                packet, rstart + 2, max_wire_end=rend
            )
            if pos > rend:
                raise ValueError("Malformed SVCB/HTTPS record.")

            clean_target = cls._strip_trailing_dot(target)
            svc_params: dict[int, str] = {}
            while pos + 4 <= rend:
                param_key, param_len = struct.unpack_from("!HH", packet, pos)
                pos += 4
                if pos + param_len > rend:
                    raise ValueError("Malformed SVCB/HTTPS parameter.")
                svc_params[param_key] = packet[pos:pos + param_len].hex()
                pos += param_len

            record.update({
                "priority": priority,
                "target": clean_target,
                "params": svc_params,
                "value": f"{priority} {clean_target}",
            })

        else:
            record["rdata_hex"] = data.hex()

        return record, rend

    def query(
        self,
        name: str,
        record_type: str = "A",
        dnssec: bool = True,
    ) -> dict[str, Any]:
        """Query one record type and return structured results."""
        try:
            qname = self._normalize_name(name)
            record_type = record_type.upper()
            qtype = self.TYPE_CODES.get(record_type)

            if qtype is None:
                raise ValueError(
                    f"Unsupported DNS record type: {record_type}"
                )

            self._encode_name(qname)

        except (ValueError, UnicodeError) as exc:
            return {
                "name": name,
                "type": record_type.upper(),
                "status": "INVALID_QUERY",
                "error": str(exc),
                "records": [],
            }

        errors: list[str] = []

        for nameserver in self.nameservers:
            for _ in range(self.retries):
                txid = secrets.randbits(16)

                packet = self._build_query(
                    qname, qtype, txid, dnssec=dnssec
                )

                try:
                    response, latency_ms = self._exchange(
                        nameserver, packet, txid
                    )

                    return self._parse_response(
                        response,
                        qname,
                        record_type,
                        nameserver,
                        latency_ms,
                    )

                except (OSError, ValueError, struct.error) as exc:
                    errors.append(f"{nameserver}: {exc}")

        return {
            "name": qname.rstrip("."),
            "type": record_type,
            "status": "DNS_ERROR",
            "error": (
                "; ".join(errors[-6:])
                or "No DNS resolver available."
            ),
            "records": [],
        }

    @classmethod
    def _parse_response(
        cls,
        packet: bytes,
        qname: str,
        qtype_name: str,
        nameserver: str,
        latency_ms: float,
    ) -> dict[str, Any]:
        if len(packet) < 12:
            raise ValueError(
                "DNS response header is too short."
            )

        (
            txid, flags, qdcount,
            ancount, nscount, arcount,
        ) = struct.unpack_from("!HHHHHH", packet, 0)

        if not flags & 0x8000:
            raise ValueError(
                "Packet is not a DNS response."
            )

        offset = 12

        for _ in range(qdcount):
            _, offset = cls._decode_name(packet, offset)
            _, offset = cls._read_u16(packet, offset)
            _, offset = cls._read_u16(packet, offset)

        answers: list[dict[str, Any]] = []
        authority: list[dict[str, Any]] = []
        additional: list[dict[str, Any]] = []

        for target, count in zip(
            (answers, authority, additional),
            (ancount, nscount, arcount),
        ):
            for _ in range(count):
                record, offset = cls._parse_rr(
                    packet, offset
                )
                target.append(record)

        rcode = flags & 0x000F
        status = cls.RCODE_NAMES.get(
            rcode, f"RCODE_{rcode}"
        )

        if rcode == 0 and not answers:
            status = "NO_RECORDS"

        return {
            "name": qname.rstrip("."),
            "type": qtype_name,
            "status": status,
            "rcode": rcode,
            "resolver": nameserver,
            "latency_ms": round(latency_ms, 2),
            "truncated": bool(flags & 0x0200),
            "recursion_available": bool(flags & 0x0080),
            "authenticated_data": bool(flags & 0x0020),
            "dnssec_advisory": (
                "AD is the resolver's assertion; this client "
                "does not validate DNSSEC signatures."
            ),
            "records": answers,
            "authority": authority,
            "additional": additional,
        }

    @staticmethod
    def _reverse_name(address: str) -> str:
        ip = ipaddress.ip_address(address)

        if isinstance(ip, ipaddress.IPv4Address):
            return (
                ".".join(reversed(str(ip).split("."))
                ) + ".in-addr.arpa."
            )

        nibbles = ip.exploded.replace(":", "")
        return ".".join(reversed(nibbles)) + ".ip6.arpa."

    def reverse_lookup(
        self,
        address: str,
    ) -> dict[str, Any]:
        """Look up the PTR record for an IP address."""
        try:
            reverse_name = self._reverse_name(address)

        except ValueError as exc:
            return {
                "address": address,
                "status": "INVALID_ADDRESS",
                "error": str(exc),
                "records": [],
            }

        result = self.query(reverse_name, "PTR")
        result["address"] = address
        return result

    @staticmethod
    def format_scan(result: dict[str, Any]) -> str:
        """Format DNS results into a concise vertical report."""
        lines = [
            f"Uspector DNS Scan: {result.get('target', 'Unknown')}",
            "=" * 48,
        ]

        if result.get("error"):
            lines.append(f"Error: {result['error']}")
            return "\n".join(lines)

        records = result.get("records", {})

        def show(record_type: str, label: str) -> None:
            data = records.get(record_type, {})
            entries = data.get("records", [])
            status = data.get("status", "UNKNOWN")

            lines.append(f"\n{label}:")

            if not entries:
                if status in {"NOERROR", "NO_RECORDS"}:
                    lines.append("  None found")
                else:
                    lines.append(f"  {status}")
                return

            for record in entries:
                entry_type = record.get("type", record_type)
                if entry_type == "CNAME" and record_type != "CNAME":
                    continue

                if record_type == "MX":
                    value = (
                        f"{record.get('exchange', '')} "
                        f"(priority {record.get('preference', '?')})"
                    )
                elif record_type == "SOA":
                    value = (
                        f"Primary: {record.get('mname', '?')}\n"
                        f"    Responsible: {record.get('rname', '?')}\n"
                        f"    Serial: {record.get('serial', '?')}"
                    )
                elif record_type == "CAA":
                    value = (
                        f"{record.get('tag', '?')}: "
                        f"{record.get('value', '')}"
                    )
                elif record_type == "TXT":
                    value = record.get("value", "")
                    # Show only relevant TXT records.
                    if not value.lower().startswith((
                        "v=spf1",
                        "v=dmarc1",
                        "v=dkim1",
                        "google-site-verification=",
                        "apple-domain-verification=",
                    )):
                        continue
                else:
                    value = record.get("value", "")

                if value:
                    lines.append(f"  - {value}")

        for record_type, label in (
            ("A", "IPv4"),
            ("AAAA", "IPv6"),
            ("CNAME", "CNAME"),
            ("MX", "Mail Servers"),
            ("NS", "Name Servers"),
            ("TXT", "Important TXT Records"),
            ("CAA", "CAA"),
            ("SOA", "SOA"),
        ):
            show(record_type, label)

        email = result.get("email_security", {})

        lines.append("\nEmail Security:")

        for key, label in (("spf", "SPF"), ("dmarc", "DMARC")):
            item = email.get(key) or {}
            lines.append(
                f"  {label}: {item.get('status', 'UNKNOWN')}"
            )

            if key == "dmarc" and item.get("policy"):
                lines.append(f"    Policy: {item['policy']}")

        dkim = email.get("dkim")
        if dkim is not None:
            lines.append(f"  DKIM: {dkim.get('status', 'UNKNOWN')}")

        dnssec = result.get("dnssec")
        if dnssec:
            lines.append("\nDNSSEC (inspection only):")
            for key, label in (
                ("ds_records_found", "DS"),
                ("dnskey_records_found", "DNSKEY"),
                ("rrsig_records_found", "RRSIG"),
            ):
                lines.append(
                    f"  {label}: "
                    f"{'Found' if dnssec.get(key) else 'Not found'}"
                )

        findings = result.get("findings", [])
        if findings:
            lines.append("\nFindings:")
            for finding in findings:
                lines.append(f"  - {finding}")

        return "\n".join(lines)

    @staticmethod
    def _read_asn1_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
        if offset >= len(data):
            raise ValueError("Truncated ASN.1 data.")
        tag = data[offset]
        offset += 1
        if offset >= len(data):
            raise ValueError("Truncated ASN.1 length.")
        length = data[offset]
        offset += 1
        if length & 0x80:
            num_bytes = length & 0x7F
            if num_bytes == 0 or offset + num_bytes > len(data):
                raise ValueError("Invalid ASN.1 length.")
            length = int.from_bytes(data[offset:offset + num_bytes], "big")
            offset += num_bytes
        if offset + length > len(data):
            raise ValueError("ASN.1 value extends past buffer.")
        return tag, data[offset:offset + length], offset + length

    @classmethod
    def _rsa_bits_from_spki(cls, b64_key: str) -> int | None:
        try:
            der = base64.b64decode("".join(b64_key.split()), validate=True)
            tag, spki, _ = cls._read_asn1_tlv(der, 0)
            if tag != 0x30:
                return None
            alg_tag, alg_seq, pos = cls._read_asn1_tlv(spki, 0)
            if alg_tag != 0x30:
                return None
            oid_tag, oid_bytes, _ = cls._read_asn1_tlv(alg_seq, 0)
            # RSA encryption OID 1.2.840.113549.1.1.1
            if oid_tag != 0x06 or oid_bytes != b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01":
                return None
            bit_tag, bit_str, _ = cls._read_asn1_tlv(spki, pos)
            if bit_tag != 0x03 or len(bit_str) < 2 or bit_str[0] != 0:
                return None
            rsa_tag, rsa_seq, _ = cls._read_asn1_tlv(bit_str[1:], 0)
            if rsa_tag != 0x30:
                return None
            mod_tag, modulus, _ = cls._read_asn1_tlv(rsa_seq, 0)
            if mod_tag != 0x02:
                return None
            modulus_int = int.from_bytes(modulus, "big")
            return modulus_int.bit_length() or None
        except Exception:
            return None

    @staticmethod
    def _evaluate_spf(spf_records: list[str]) -> tuple[int | None, list[str]]:
        if len(spf_records) != 1:
            return None, []

        findings: list[str] = []
        terms = spf_records[0].lower().split()
        mechanisms = terms[1:]
        lookup_count = 0
        has_redirect = False
        has_all = False

        for term in mechanisms:
            if term.startswith("redirect="):
                has_redirect = True
                lookup_count += 1
                continue

            bare = term.lstrip("+-~?")
            if bare == "all":
                has_all = True
                if term == "+all":
                    findings.append("SPF record uses permissive '+all' policy")
                elif term == "?all":
                    findings.append("SPF record uses neutral '?all' policy")
                continue

            if bare == "ptr" or bare.startswith("ptr:"):
                findings.append("SPF record uses deprecated 'ptr' mechanism")
                lookup_count += 1
            elif (
                bare.startswith(("include:", "exists:"))
                or bare in ("a", "mx")
                or bare.startswith(("a:", "a/", "mx:", "mx/"))
            ):
                lookup_count += 1

        if not has_all and not has_redirect:
            findings.append(
                "SPF record does not end with an 'all' or 'redirect' mechanism"
            )

        if lookup_count > 10:
            findings.append(
                f"SPF record exceeds the 10-DNS-lookup limit ({lookup_count})"
            )
        elif lookup_count >= 8:
            findings.append(
                f"SPF record approaches the 10-DNS-lookup limit ({lookup_count}/10)"
            )

        return lookup_count, findings

    @staticmethod
    def _evaluate_dmarc(
        dmarc_records: list[str],
        dmarc_tags: dict[str, str],
    ) -> list[str]:
        if len(dmarc_records) != 1:
            return []

        findings: list[str] = []
        sp = (dmarc_tags.get("sp") or "").lower()
        if sp == "none":
            findings.append("DMARC subdomain policy (sp) is set to none")

        pct_raw = dmarc_tags.get("pct")
        if pct_raw is not None:
            try:
                pct_val = int(pct_raw)
                if 0 <= pct_val < 100:
                    findings.append(
                        f"DMARC enforcement percentage (pct={pct_val}) is below 100%"
                    )
            except ValueError:
                pass

        if not dmarc_tags.get("rua") and not dmarc_tags.get("ruf"):
            findings.append(
                "DMARC record has no aggregate/forensic reporting URI (rua/ruf)"
            )

        return findings

    @classmethod
    def _evaluate_dkim(cls, dkim_records: list[str]) -> tuple[dict[str, Any], list[str]]:
        if not dkim_records:
            return {}, []

        findings: list[str] = []
        tags: dict[str, str] = {}
        for item in dkim_records[0].split(";"):
            if "=" in item:
                k, v = item.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        details: dict[str, Any] = {}
        pub_key = tags.get("p", "")
        if pub_key == "":
            findings.append("DKIM key is revoked (empty p= tag)")
            details["revoked"] = True
        else:
            bits = cls._rsa_bits_from_spki(pub_key)
            if bits is not None:
                details["rsa_bits"] = bits
                if bits < 1024:
                    findings.append(f"Weak DKIM RSA key: {bits} bits (< 1024)")
                elif bits < 2048:
                    findings.append(f"DKIM RSA key is below 2048 bits ({bits} bits)")

        if "y" in (tags.get("t") or "").lower().split(":"):
            findings.append("DKIM record is in test mode (t=y)")
            details["test_mode"] = True

        return details, findings

    @staticmethod
    def _evaluate_zone_records(
        records: dict[str, Any],
        include_dnssec: bool,
    ) -> list[str]:
        findings: list[str] = []

        # CAA tags.
        caa_records = [
            record for record in records.get("CAA", {}).get("records", [])
            if record.get("type", "CAA") == "CAA"
        ]
        if caa_records:
            caa_tags = {
                str(record.get("tag", "")).lower()
                for record in caa_records
            }
            if "issue" not in caa_tags and "issuewild" not in caa_tags:
                findings.append("CAA records do not specify 'issue' or 'issuewild'")
            if "iodef" not in caa_tags:
                findings.append("CAA records do not specify an 'iodef' reporting contact")

        # NS redundancy.
        ns_data = records.get("NS", {})
        ns_records = [
            record for record in ns_data.get("records", [])
            if record.get("type", "NS") == "NS"
        ]
        if (
            ns_data.get("status") in {"NOERROR", "NO_RECORDS"}
            and len(ns_records) == 1
        ):
            findings.append("Single NS record found; redundant nameservers recommended")

        # MX target hygiene.
        for mx in records.get("MX", {}).get("records", []):
            if mx.get("type", "MX") != "MX":
                continue
            exchange = mx.get("exchange", "")
            if exchange and exchange != ".":
                try:
                    ipaddress.ip_address(exchange)
                    findings.append(
                        f"MX target {exchange} appears to be an IP address"
                    )
                except ValueError:
                    pass

        # SOA timer sanity.
        for soa in records.get("SOA", {}).get("records", []):
            if soa.get("type", "SOA") != "SOA":
                continue
            refresh = soa.get("refresh")
            retry = soa.get("retry")
            expire = soa.get("expire")
            if isinstance(refresh, int) and isinstance(retry, int) and retry >= refresh:
                findings.append(
                    "SOA retry timer is greater than or equal to refresh"
                )
            if isinstance(expire, int) and expire < 604800:
                findings.append("SOA expire timer is below 7 days")

        # DNSSEC algorithm & signature expiration.
        if include_dnssec:
            deprecated_algs = {1, 3, 5, 6, 7}
            for dnskey in records.get("DNSKEY", {}).get("records", []):
                alg = dnskey.get("algorithm")
                if alg in deprecated_algs:
                    findings.append(
                        f"Deprecated DNSSEC DNSKEY algorithm detected ({alg})"
                    )
                    break

            now_ts = int(time.time())
            for rrsig in records.get("RRSIG", {}).get("records", []):
                exp = rrsig.get("expiration")
                if isinstance(exp, int):
                    if exp < now_ts:
                        findings.append("Expired DNSSEC RRSIG signature detected")
                        break
                    if exp - now_ts < 86400:
                        findings.append(
                            "DNSSEC RRSIG signature expires within 24 hours"
                        )
                        break

        return findings

    def _run_extended_checks(
        self,
        domain: str,
        records: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        extra: dict[str, Any] = {}
        findings: list[str] = []

        # Optional email transport & brand indicators.
        mta_sts = self.query(f"_mta-sts.{domain}", "TXT")
        mta_sts_found = any(
            isinstance(r.get("value"), str) and r["value"].startswith("v=STSv1")
            for r in mta_sts.get("records", [])
        )
        tls_rpt = self.query(f"_smtp._tls.{domain}", "TXT")
        tls_rpt_found = any(
            isinstance(r.get("value"), str) and r["value"].startswith("v=TLSRPTv1")
            for r in tls_rpt.get("records", [])
        )
        bimi = self.query(f"default._bimi.{domain}", "TXT")
        bimi_found = any(
            isinstance(r.get("value"), str) and r["value"].startswith("v=BIMI1")
            for r in bimi.get("records", [])
        )
        extra["email_transport"] = {
            "mta_sts_found": mta_sts_found,
            "tls_rpt_found": tls_rpt_found,
            "bimi_found": bimi_found,
        }

        # Optional service/DANE/NSEC records (no failure findings if unsupported).
        for label, qname, qtype in (
            ("TLSA", f"_443._tcp.{domain}", "TLSA"),
            ("HTTPS", domain, "HTTPS"),
            ("SVCB", domain, "SVCB"),
            ("NSEC", domain, "NSEC"),
            ("NSEC3", domain, "NSEC3"),
        ):
            extra[label] = self.query(qname, qtype)

        if extra["NSEC"].get("records"):
            findings.append("DNSSEC NSEC record present (zone enumeration possible)")

        # Dangling CNAME check.
        for cname in records.get("CNAME", {}).get("records", []):
            target = cname.get("value")
            if isinstance(target, str) and target and target != ".":
                a_res = self.query(target, "A")
                aaaa_res = self.query(target, "AAAA")
                if a_res.get("status") == "NXDOMAIN" and aaaa_res.get("status") == "NXDOMAIN":
                    findings.append(
                        f"Dangling CNAME target {target} resolves to NXDOMAIN"
                    )

        # FCrDNS check on first resolved A/AAAA IP.
        fcrdns: list[dict[str, Any]] = []
        for rtype in ("A", "AAAA"):
            for rec in records.get(rtype, {}).get("records", [])[:1]:
                ip_val = rec.get("value")
                if isinstance(ip_val, str):
                    ptr_res = self.reverse_lookup(ip_val)
                    ptrs = [
                        p.get("value")
                        for p in ptr_res.get("records", [])
                        if p.get("type") == "PTR" and p.get("value")
                    ]
                    fcrdns.append({"ip": ip_val, "ptrs": ptrs})
        extra["fcrdns"] = fcrdns

        return extra, findings

    def scan(
        self,
        target: str,
        dkim_selector: str | None = None,
        include_dnssec: bool = True,
        check_extended: bool = False,
    ) -> dict[str, Any]:
        """Scan DNS configuration and return structured results."""
        result: dict[str, Any] = {
            "target": target,
            "resolver": self.nameservers,
            "records": {},
            "email_security": {
                "spf": None,
                "dmarc": None,
                "dkim": None,
            },
            "dnssec": None,
            "findings": [],
            "error": None,
        }

        try:
            if not isinstance(target, str):
                raise TypeError("Domain must be a string.")

            domain = target.strip().rstrip(".")

            if not domain:
                raise ValueError("Domain cannot be empty.")

            self._encode_name(domain)
            result["target"] = domain

            record_types = [
                "A", "AAAA", "CNAME", "MX",
                "NS", "SOA", "TXT", "CAA",
            ]

            if include_dnssec:
                record_types.extend(["DS", "DNSKEY", "RRSIG"])

            records = {
                record_type: self.query(domain, record_type)
                for record_type in record_types
            }

            # Some DNS resolvers include CNAME records in A/AAAA answers.
            # Use those records as a fallback if the direct CNAME query
            # did not return an alias.
            cname_records = list(records["CNAME"].get("records", []))

            if not cname_records:
                seen_cnames: set[tuple[str | None, str | None]] = set()
                for record_type in ("A", "AAAA"):
                    for record in records[record_type].get("records", []):
                        if record.get("type") == "CNAME":
                            key = (record.get("name"), record.get("value"))
                            if key not in seen_cnames:
                                seen_cnames.add(key)
                                cname_records.append(record)

            if cname_records:
                records["CNAME"]["records"] = cname_records
                records["CNAME"]["status"] = "NOERROR"

            result["records"] = records

            # Record lookup failures without confusing them with
            # successfully queried but absent records.
            failed_statuses = {
                "DNS_ERROR", "INVALID_QUERY", "SERVFAIL",
                "REFUSED", "FORMERR", "NOTIMP", "NOTAUTH",
                "NOTZONE",
            }

            for record_type, record_result in records.items():
                if record_result.get("status") in failed_statuses:
                    result["findings"].append(
                        f"{record_type} query failed: "
                        f"{record_result.get('status')}"
                    )

            txt_records = [
                record.get("value", "")
                for record in records["TXT"].get("records", [])
                if (
                    record.get("type", "TXT") == "TXT"
                    and isinstance(record.get("value"), str)
                )
            ]

            # SPF.
            spf_records = [
                value for value in txt_records
                if (
                    value.lower() == "v=spf1"
                    or value.lower().startswith("v=spf1 ")
                )
            ]

            spf_terms = (
                spf_records[0].lower().split()
                if len(spf_records) == 1
                else []
            )

            spf_lookup_count, spf_extra_findings = self._evaluate_spf(spf_records)

            spf = {
                "status": "FOUND" if spf_records else "MISSING",
                "records": spf_records,
                "multiple_records": len(spf_records) > 1,
                "ends_with_all": bool(
                    spf_terms and spf_terms[-1] in {
                        "+all", "-all", "~all", "?all",
                    }
                ),
                "lookup_count": spf_lookup_count,
                "note": (
                    "Passive SPF policy inspection; external include targets "
                    "are not recursively resolved."
                ),
            }

            result["email_security"]["spf"] = spf

            if (
                not spf_records
                and records["TXT"].get("status")
                in {"NOERROR", "NO_RECORDS"}
            ):
                result["findings"].append("Missing SPF record")

            elif len(spf_records) > 1:
                result["findings"].append(
                    "Multiple SPF records detected"
                )

            result["findings"].extend(spf_extra_findings)

            # DMARC.
            dmarc_result = self.query(
                f"_dmarc.{domain}", "TXT"
            )

            if dmarc_result.get("status") in failed_statuses:
                result["findings"].append(
                    f"DMARC query failed: {dmarc_result.get('status')}"
                )

            dmarc_records = [
                record.get("value", "")
                for record in dmarc_result.get("records", [])
                if (
                    record.get("type", "TXT") == "TXT"
                    and isinstance(record.get("value"), str)
                    and (
                        record.get("value", "").strip().lower() == "v=dmarc1"
                        or record.get("value", "").strip().lower().startswith(
                            ("v=dmarc1;", "v=dmarc1 ")
                        )
                    )
                )
            ]

            dmarc_tags: dict[str, str] = {}

            if len(dmarc_records) == 1:
                for item in dmarc_records[0].split(";"):
                    if "=" in item:
                        key, value = item.split("=", 1)
                        dmarc_tags[key.strip().lower()] = (
                            value.strip()
                        )

            dmarc = {
                "status": "FOUND" if dmarc_records else "MISSING",
                "records": dmarc_records,
                "multiple_records": len(dmarc_records) > 1,
                "policy": dmarc_tags.get("p"),
                "tags": dmarc_tags,
                "query_status": dmarc_result.get("status"),
                "note": (
                    "Basic DMARC record discovery only; policy "
                    "semantics are not fully validated."
                ),
            }

            result["email_security"]["dmarc"] = dmarc

            if (
                not dmarc_records
                and dmarc_result.get("status")
                in {"NOERROR", "NO_RECORDS", "NXDOMAIN"}
            ):
                result["findings"].append("Missing DMARC record")

            elif len(dmarc_records) > 1:
                result["findings"].append(
                    "Multiple DMARC records detected"
                )

            if (
                len(dmarc_records) == 1
                and (dmarc_tags.get("p") or "").lower() == "none"
            ):
                result["findings"].append(
                    "DMARC policy is set to none"
                )

            result["findings"].extend(
                self._evaluate_dmarc(dmarc_records, dmarc_tags)
            )

            # Optional DKIM selector.
            if dkim_selector is not None:
                selector = dkim_selector.strip().rstrip(".")

                try:
                    if not selector or "." in selector:
                        raise ValueError(
                            "Supply a single DKIM selector label."
                        )

                    self._encode_name(selector)

                except ValueError as exc:
                    result["email_security"]["dkim"] = {
                        "status": "INVALID_SELECTOR",
                        "error": str(exc),
                    }

                else:
                    dkim_result = self.query(
                        f"{selector}._domainkey.{domain}",
                        "TXT",
                    )

                    if dkim_result.get("status") in failed_statuses:
                        result["findings"].append(
                            f"DKIM query failed: {dkim_result.get('status')}"
                        )

                    dkim_records = [
                        record.get("value", "")
                        for record in dkim_result.get("records", [])
                        if (
                            record.get("type", "TXT") == "TXT"
                            and isinstance(record.get("value"), str)
                            and "p=" in record.get("value", "").lower()
                        )
                    ]

                    dkim_details, dkim_extra_findings = self._evaluate_dkim(
                        dkim_records
                    )

                    result["email_security"]["dkim"] = {
                        "status": (
                            "FOUND" if dkim_records else "NOT_FOUND"
                        ),
                        "records": dkim_records,
                        "query": dkim_result,
                        **dkim_details,
                    }

                    if (
                        not dkim_records
                        and dkim_result.get("status")
                        in {"NOERROR", "NO_RECORDS", "NXDOMAIN"}
                    ):
                        result["findings"].append(
                            "DKIM record not found for supplied selector"
                        )

                    result["findings"].extend(dkim_extra_findings)

            # DNSSEC inspection, not cryptographic validation.
            if include_dnssec:
                result["dnssec"] = {
                    "ds_records_found": bool(
                        records["DS"].get("records")
                    ),
                    "dnskey_records_found": bool(
                        records["DNSKEY"].get("records")
                    ),
                    "rrsig_records_found": bool(
                        records["RRSIG"].get("records")
                    ),
                    "validation": "NOT_PERFORMED",
                    "note": (
                        "Record presence is not a DNSSEC validation "
                        "result. DS records are normally queried "
                        "from the parent zone."
                    ),
                }

            # Only report absence when the DNS query succeeded.
            mx_records = [
                record
                for record in records["MX"].get("records", [])
                if record.get("type", "MX") == "MX"
            ]
            if (
                not mx_records
                and records["MX"].get("status")
                in {"NOERROR", "NO_RECORDS"}
            ):
                result["findings"].append("No MX records found")

            caa_records = [
                record
                for record in records["CAA"].get("records", [])
                if record.get("type", "CAA") == "CAA"
            ]
            if (
                not caa_records
                and records["CAA"].get("status")
                in {"NOERROR", "NO_RECORDS"}
            ):
                result["findings"].append("No CAA records found")

            is_null_mx = (
                len(mx_records) == 1
                and mx_records[0].get("preference") == 0
                and mx_records[0].get("exchange") == "."
            )
            if is_null_mx:
                result["email_security"]["null_mx"] = True

            result["findings"].extend(
                self._evaluate_zone_records(records, include_dnssec)
            )

            if check_extended:
                extended_data, extended_findings = self._run_extended_checks(
                    domain,
                    records,
                )
                result["extended"] = extended_data
                result["findings"].extend(extended_findings)

        except (ValueError, OSError, TypeError) as exc:
            result["error"] = str(exc)

        return result
