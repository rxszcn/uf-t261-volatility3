"""macOS dump address families must not depend on the analysis host OS.

A macOS memory image stores ``AF_INET6`` as 30. Linux stores 10 and Windows
stores 23, so comparing the image's family value against the analysis host's
``socket.AF_INET6`` silently drops every macOS IPv6 socket row whenever the
analysis host is not macOS (the conversion returns ``None`` and the macOS
netstat plugin skips rows with a falsy conversion). These tests pin the
conversion entry point to the dump's own family values.
"""

import inspect
import ipaddress
import socket
import struct
from types import SimpleNamespace

import pytest

from volatility3.framework import constants
from volatility3.framework.renderers import conversion
from volatility3.framework.symbols.mac import extensions

HOST_IPV6_VALUES = [
    pytest.param(10, id="linux-host"),
    pytest.param(23, id="windows-host"),
    pytest.param(30, id="macos-host"),
]

IPV6_TEXT = "2001:db8:1234::5678"
IPV6_PACKED = ipaddress.ip_address(IPV6_TEXT).packed
IPV6_WORDS = list(struct.unpack("<IIII", IPV6_PACKED))
IPV4_LOCAL_TEXT = "192.0.2.123"
IPV4_REMOTE_TEXT = "198.51.100.7"
IPV4_LOCAL_WORD = int.from_bytes(ipaddress.ip_address(IPV4_LOCAL_TEXT).packed, "little")
IPV4_REMOTE_WORD = int.from_bytes(
    ipaddress.ip_address(IPV4_REMOTE_TEXT).packed, "little"
)
LOCAL_PORT = 0x1234
REMOTE_PORT = 0x0050


def _ipv6_four_tuple():
    return [IPV6_WORDS, LOCAL_PORT, IPV6_WORDS, REMOTE_PORT]


def _ipv4_four_tuple():
    return [IPV4_LOCAL_WORD, LOCAL_PORT, IPV4_REMOTE_WORD, REMOTE_PORT]


# --- 1. Cross-host IPv6 decoding -------------------------------------------


@pytest.mark.parametrize("host_ipv6", HOST_IPV6_VALUES)
def test_darwin_ipv6_decodes_on_every_host(monkeypatch, host_ipv6):
    """Darwin family 30 must decode identically on Linux, Windows and macOS."""
    monkeypatch.setattr(socket, "AF_INET", 2)
    monkeypatch.setattr(socket, "AF_INET6", host_ipv6)

    result = conversion.convert_network_four_tuple(
        constants.mac.AF_INET6, _ipv6_four_tuple()
    )

    assert result is not None
    assert result == (
        IPV6_TEXT,
        conversion.convert_port(LOCAL_PORT),
        IPV6_TEXT,
        conversion.convert_port(REMOTE_PORT),
    )
    # The decoded address really is an IPv6 address, not a misparsed one.
    assert ipaddress.ip_address(result[0]).version == 6


# --- 2. IPv4 control ------------------------------------------------------


@pytest.mark.parametrize("host_ipv6", HOST_IPV6_VALUES)
def test_darwin_ipv4_is_unchanged(monkeypatch, host_ipv6):
    """Darwin family 2 keeps its existing behaviour on every host."""
    monkeypatch.setattr(socket, "AF_INET", 2)
    monkeypatch.setattr(socket, "AF_INET6", host_ipv6)

    result = conversion.convert_network_four_tuple(
        constants.mac.AF_INET, _ipv4_four_tuple()
    )

    assert result == (
        IPV4_LOCAL_TEXT,
        conversion.convert_port(LOCAL_PORT),
        IPV4_REMOTE_TEXT,
        conversion.convert_port(REMOTE_PORT),
    )


def test_linux_family_is_not_decoded_as_darwin_ipv6():
    """A Linux-image family value must not be reinterpreted as Darwin IPv6."""
    # 10 is Linux's AF_INET6. It is not a Darwin family, so nothing is decoded.
    assert conversion.convert_network_four_tuple(10, _ipv6_four_tuple()) is None


def test_unknown_family_still_returns_none():
    assert conversion.convert_network_four_tuple(99, _ipv6_four_tuple()) is None


# --- 3. Host dependency ---------------------------------------------------


def test_conversion_entry_does_not_use_host_socket_module(monkeypatch):
    """The host's socket.AF_* values must not be consulted at the entry point."""
    # The conversion module must not resolve the host socket module at all.
    assert "socket" not in vars(conversion)

    # Poison the host constants: if the entry point consulted them, decoding
    # would break or change. It must not.
    monkeypatch.setattr(socket, "AF_INET", 0xBEEF)
    monkeypatch.setattr(socket, "AF_INET6", 0xDEAD)
    assert conversion.convert_network_four_tuple(
        constants.mac.AF_INET6, _ipv6_four_tuple()
    ) == (
        IPV6_TEXT,
        conversion.convert_port(LOCAL_PORT),
        IPV6_TEXT,
        conversion.convert_port(REMOTE_PORT),
    )
    assert conversion.convert_network_four_tuple(
        constants.mac.AF_INET, _ipv4_four_tuple()
    ) == (
        IPV4_LOCAL_TEXT,
        conversion.convert_port(LOCAL_PORT),
        IPV4_REMOTE_TEXT,
        conversion.convert_port(REMOTE_PORT),
    )
    assert conversion.convert_network_four_tuple(0xBEEF, _ipv4_four_tuple()) is None
    assert conversion.convert_network_four_tuple(0xDEAD, _ipv6_four_tuple()) is None


def test_conversion_entry_uses_dump_family_parameters():
    """Callers for another OS can supply that OS' own family values."""
    signature = inspect.signature(conversion.convert_network_four_tuple)
    assert signature.parameters["af_inet"].default == constants.mac.AF_INET
    assert signature.parameters["af_inet6"].default == constants.mac.AF_INET6


def test_darwin_constants_match_the_dump_not_the_host(monkeypatch):
    assert (constants.mac.AF_INET, constants.mac.AF_INET6) == (2, 30)
    # Forcing the host constants to look like a Darwin dump must not change
    # Darwin decoding: the decision is made on the raw dump family value.
    monkeypatch.setattr(socket, "AF_INET", constants.mac.AF_INET)
    monkeypatch.setattr(socket, "AF_INET6", constants.mac.AF_INET6)
    result = conversion.convert_network_four_tuple(
        constants.mac.AF_INET6, _ipv6_four_tuple()
    )
    assert result is not None and result[0] == IPV6_TEXT


# --- macOS consumer chain -------------------------------------------------


def _mac_socket(family, four_tuple):
    """Build a stand-in for extensions.socket bound to the real methods."""
    inpcb = SimpleNamespace(
        get_ipv4_info=lambda: four_tuple,
        get_ipv6_info=lambda: four_tuple,
    )
    sock = SimpleNamespace()
    sock.get_family = lambda: family
    sock.get_inpcb = lambda: inpcb
    sock.get_connection_info = lambda: extensions.socket.get_connection_info(sock)
    sock.get_converted_connection_info = lambda: (
        extensions.socket.get_converted_connection_info(sock)
    )
    return sock


@pytest.mark.parametrize("host_ipv6", HOST_IPV6_VALUES)
def test_mac_consumer_chain_keeps_ipv6_rows(monkeypatch, host_ipv6):
    """mac netstat only emits rows with a truthy conversion; IPv6 must survive."""
    monkeypatch.setattr(socket, "AF_INET", 2)
    monkeypatch.setattr(socket, "AF_INET6", host_ipv6)

    sock = _mac_socket(constants.mac.AF_INET6, _ipv6_four_tuple())
    assert sock.get_connection_info() == _ipv6_four_tuple()

    vals = sock.get_converted_connection_info()
    assert vals is not None
    assert vals[0] == IPV6_TEXT
    assert vals[2] == IPV6_TEXT


@pytest.mark.parametrize("host_ipv6", HOST_IPV6_VALUES)
def test_mac_consumer_chain_ipv4_unchanged(monkeypatch, host_ipv6):
    monkeypatch.setattr(socket, "AF_INET", 2)
    monkeypatch.setattr(socket, "AF_INET6", host_ipv6)

    sock = _mac_socket(constants.mac.AF_INET, _ipv4_four_tuple())
    assert sock.get_converted_connection_info() == (
        IPV4_LOCAL_TEXT,
        conversion.convert_port(LOCAL_PORT),
        IPV4_REMOTE_TEXT,
        conversion.convert_port(REMOTE_PORT),
    )
