# Uspector – Copyright (c) 2026 Menahem Levinski

"""
Standard-library-only DNS diagnostics for Uspector.

Supports DNS record lookups over UDP with TCP fallback, reverse lookups,
basic SPF/DMARC/DKIM checks, and DNSSEC-related record inspection.

DNSSEC records are inspected, not cryptographically validated.
"""

from __future__ import annotations

import ipaddress
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
        self.timeout = max(0.1, float(timeout))
        self.retries = max(1, int(retries))
        self.port = int(port)
        self.nameservers = list(nameservers or self._discover_nameservers())

        if not self.nameservers:
            self.nameservers = ["1.1.1.1"]

        self.nameservers = list(dict.fromkeys(self.nameservers))

    @staticmethod
    def _discover_nameservers() -> list[str]:
        """Discover configured DNS resolvers without external dependencies."""
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
                                        found.extend(
                                            value.replace(",", " ")
                                            .replace(";", " ")
                                            .split()
                                        )
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

        valid: list[str] = []

        for candidate in found:
            candidate = candidate.strip().strip("[]")

            try:
                valid.append(
                    str(
                        ipaddress.ip_address(
                            candidate.split("%", 1)[0]
                        )
                    )
                )
            except ValueError:
                continue

        return list(dict.fromkeys(valid))

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
    def _decode_name(
        packet: bytes,
        offset: int,
    ) -> tuple[str, int]:
        """Decode a possibly compressed DNS name."""
        labels: list[str] = []
        cursor = offset
        next_offset: int | None = None
        jumps = 0
        visited: set[int] = set()

        while True:
            if cursor >= len(packet):
                raise ValueError("DNS name extends beyond packet.")

            length = packet[cursor]

            if length & 0xC0 == 0xC0:
                if cursor + 1 >= len(packet):
                    raise ValueError(
                        "Incomplete DNS compression pointer."
                    )

                pointer = (
                    (length & 0x3F) << 8
                ) | packet[cursor + 1]

                if pointer >= len(packet) or pointer in visited:
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

            if length > 63 or cursor + length > len(packet):
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

    def _exchange(
        self,
        nameserver: str,
        query: bytes,
        transaction_id: int,
    ) -> tuple[bytes, float]:
        family = (
            socket.AF_INET6
            if ":" in nameserver
            else socket.AF_INET
        )

        start = time.perf_counter()

        with socket.socket(
            family, socket.SOCK_DGRAM
        ) as sock:
            sock.settimeout(self.timeout)
            sock.sendto(query, (nameserver, self.port))
            packet, source = sock.recvfrom(65535)

            if source[1] != self.port:
                raise OSError(
                    "DNS response came from an unexpected source port."
                )

        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        if len(packet) < 12:
            raise ValueError(
                "DNS response header is too short."
            )

        response_id = struct.unpack_from(
            "!H", packet, 0
        )[0]

        if response_id != transaction_id:
            raise ValueError(
                "DNS transaction ID mismatch."
            )

        flags = struct.unpack_from(
            "!H", packet, 2
        )[0]

        if not flags & 0x8000:
            raise ValueError(
                "Packet is not a DNS response."
            )

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
        family = (
            socket.AF_INET6
            if ":" in nameserver
            else socket.AF_INET
        )

        with socket.socket(
            family, socket.SOCK_STREAM
        ) as sock:
            sock.settimeout(self.timeout)
            sock.connect((nameserver, self.port))
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
            "name": name.rstrip("."),
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
            value, _ = cls._decode_name(packet, rstart)
            record["value"] = (
                value.rstrip(".") if value != "." else "."
            )

        elif rtype == 15 and rdlength >= 3:
            preference = struct.unpack_from(
                "!H", packet, rstart
            )[0]

            exchange, _ = cls._decode_name(
                packet, rstart + 2
            )

            record.update({
                "preference": preference,
                "exchange": exchange.rstrip("."),
                "value": f"{preference} {exchange.rstrip('.')}",
            })

        elif rtype == 6:
            mname, pos = cls._decode_name(packet, rstart)
            rname, pos = cls._decode_name(packet, pos)
            serial, pos = cls._read_u32(packet, pos)
            refresh, pos = cls._read_u32(packet, pos)
            retry, pos = cls._read_u32(packet, pos)
            expire, pos = cls._read_u32(packet, pos)
            minimum, pos = cls._read_u32(packet, pos)

            if pos != rend:
                raise ValueError("Malformed SOA record.")

            record.update({
                "mname": mname.rstrip("."),
                "rname": rname.rstrip("."),
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
                packet, rstart + 18
            )

            record.update({
                "type_covered": covered,
                "algorithm": algorithm,
                "labels": labels,
                "original_ttl": original_ttl,
                "expiration": expiration,
                "inception": inception,
                "key_tag": key_tag,
                "signer": signer.rstrip("."),
                "signature": packet[pos:rend].hex(),
            })

        elif rtype == 33 and rdlength >= 7:
            priority, weight, port = struct.unpack_from(
                "!HHH", data, 0
            )

            target, _ = cls._decode_name(
                packet, rstart + 6
            )

            record.update({
                "priority": priority,
                "weight": weight,
                "port": port,
                "target": target.rstrip("."),
                "value": f"{priority} {weight} {port} {target}",
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

    def scan(
        self,
        target: str,
        dkim_selector: str | None = None,
        include_dnssec: bool = True,
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
            cname_records = records["CNAME"].get("records", [])

            if not cname_records:
                for record_type in ("A", "AAAA"):
                    for record in records[record_type].get("records", []):
                        if record.get("type") == "CNAME":
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
                if isinstance(record.get("value"), str)
            ]

            # SPF.
            spf_records = [
                value for value in txt_records
                if value.lower().startswith("v=spf1")
            ]

            spf_terms = (
                spf_records[0].lower().split()
                if len(spf_records) == 1
                else []
            )

            spf = {
                "status": "FOUND" if spf_records else "MISSING",
                "records": spf_records,
                "multiple_records": len(spf_records) > 1,
                "ends_with_all": bool(
                    spf_terms and spf_terms[-1] in {
                        "+all", "-all", "~all", "?all",
                    }
                ),
                "note": (
                    "Basic SPF record discovery only; full SPF syntax "
                    "and policy evaluation are not performed."
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

            # DMARC.
            dmarc_result = self.query(
                f"_dmarc.{domain}", "TXT"
            )

            dmarc_records = [
                record.get("value", "")
                for record in dmarc_result.get("records", [])
                if (
                    isinstance(record.get("value"), str)
                    and record.get("value", "")
                    .lower().startswith("v=dmarc1")
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
                and dmarc_tags.get("p") == "none"
            ):
                result["findings"].append(
                    "DMARC policy is set to none"
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

                    dkim_records = [
                        record.get("value", "")
                        for record in dkim_result.get("records", [])
                        if (
                            isinstance(record.get("value"), str)
                            and "p=" in record.get("value", "").lower()
                        )
                    ]

                    result["email_security"]["dkim"] = {
                        "status": (
                            "FOUND" if dkim_records else "NOT_FOUND"
                        ),
                        "records": dkim_records,
                        "query": dkim_result,
                    }

                    if (
                        not dkim_records
                        and dkim_result.get("status")
                        in {"NOERROR", "NO_RECORDS", "NXDOMAIN"}
                    ):
                        result["findings"].append(
                            "DKIM record not found for supplied selector"
                        )

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
            if (
                not records["MX"].get("records")
                and records["MX"].get("status")
                in {"NOERROR", "NO_RECORDS"}
            ):
                result["findings"].append("No MX records found")

            if (
                not records["CAA"].get("records")
                and records["CAA"].get("status")
                in {"NOERROR", "NO_RECORDS"}
            ):
                result["findings"].append("No CAA records found")

        except (ValueError, OSError, TypeError) as exc:
            result["error"] = str(exc)

        return result
