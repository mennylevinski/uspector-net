# Uspector – Copyright (c) 2026 Menahem Levinski

import ipaddress
import math
import socket
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter


def validate_timeout(timeout):
    """Validate that timeout is a finite positive number and return float."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a positive number")

    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a finite positive number")

    return float(timeout)


def validate_public_http_url(url, error_prefix="Target", resolver=None):
    """Validate an HTTP(S) URL and verify all resolved IPs are globally routable."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname

    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported {error_prefix} protocol.")

    if not hostname:
        raise ValueError(f"Invalid {error_prefix} hostname.")

    if parsed.username or parsed.password:
        raise ValueError(f"{error_prefix} credentials are not allowed.")

    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError(f"Invalid {error_prefix} port.")

    if hostname.lower() == "localhost":
        raise ValueError(f"{error_prefix} targets localhost.")

    port = parsed.port or (443 if scheme == "https" else 80)
    getaddrinfo = resolver or socket.getaddrinfo

    try:
        addresses = getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve {error_prefix} hostname.") from exc

    if not addresses:
        raise ValueError(f"{error_prefix} hostname did not resolve.")

    validated_ips = []
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])

        if not ip.is_global:
            raise ValueError(
                f"{error_prefix} resolves to a private or restricted IP address."
            )

        validated_ips.append(ip.compressed)

    return hostname.lower(), port, validated_ips[0]


class PinnedIPAdapter(HTTPAdapter):
    """HTTPAdapter that pins validated DNS resolutions to prevent rebinding."""

    def __init__(self, pinned_ips, *args, **kwargs):
        self._pinned_ips = pinned_ips
        super().__init__(*args, **kwargs)

    def send(
        self,
        request,
        stream=False,
        timeout=None,
        verify=True,
        cert=None,
        proxies=None,
    ):
        parsed = urlparse(request.url)
        hostname = parsed.hostname
        if hostname:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            pinned = self._pinned_ips.get((hostname.lower(), port))
            if pinned and hostname.lower() != pinned.lower():
                request.headers.setdefault("Host", parsed.netloc)

        return super().send(
            request,
            stream=stream,
            timeout=timeout,
            verify=verify,
            cert=cert,
            proxies=proxies,
        )

    def get_connection_with_tls_context(
        self,
        request,
        verify,
        proxies=None,
        cert=None,
    ):
        proxy = requests.utils.select_proxy(request.url, proxies)
        host_params, pool_kwargs = self.build_connection_pool_key_attributes(
            request,
            verify,
            cert,
        )
        host = host_params["host"]
        port = host_params["port"]
        effective_port = port or (443 if host_params["scheme"] == "https" else 80)
        pinned = self._pinned_ips.get((host.lower(), effective_port))

        if pinned and host.lower() != pinned.lower():
            if host_params["scheme"] == "https":
                pool_kwargs["server_hostname"] = host
                pool_kwargs["assert_hostname"] = host
            host_params["host"] = pinned

        if proxy:
            proxy = requests.utils.prepend_scheme_if_needed(proxy, "http")
            proxy_url = requests.packages.urllib3.util.parse_url(proxy)
            if not proxy_url.host:
                raise requests.exceptions.InvalidProxyURL(
                    "Please check proxy URL. It is malformed "
                    "and could be missing the host."
                )
            proxy_manager = self.proxy_manager_for(proxy)
            return proxy_manager.connection_from_host(
                **host_params,
                pool_kwargs=pool_kwargs,
            )

        return self.poolmanager.connection_from_host(
            **host_params,
            pool_kwargs=pool_kwargs,
        )
