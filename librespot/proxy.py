#!/usr/bin/env python3
from requests import Session, codes
from requests.auth import HTTPProxyAuth
from socks import socksocket
from socks import SOCKS4, SOCKS5, HTTP
from socks import ProxyError, ProxyConnectionError
from socket import AF_INET, SOCK_STREAM

__author__ = "Cool Guy, Hichigo"
__license__ = "GPL v3"
__status__ = "Production"


class SpotifyProxy:
    """
    Custom Spotify proxy class.
    """

    def __init__(self, proxy_type, host, port, username=None, password=None):
        self.proxy_type = proxy_type.lower()
        self.host = host.lower()
        self.port = int(port)
        self.username = username
        self.password = password

        if username is not None and password is not None:
            self.url = f"{self.proxy_type}://{self.username}:{self.password}@{self.host}:{self.port}"
        else:
            self.url = f"{self.proxy_type}://{self.host}:{self.port}"

    def get_as_dict(self) -> dict:
        """
        Gets proxy as dict for requests.
        https://requests.readthedocs.io/en/master/user/advanced/
        :return:
        """
        return {
            "http": self.url,
            "https": self.url
        }

    def set_to_socket(self, s) -> socksocket:
        """
        Sets socket's proxy
        :param s: socket.socket
        :return: Proxied socket.socket
        """
        if self.proxy_type == "http" or self.proxy_type == "https":
            s.set_proxy(HTTP, self.host, self.port, username=self.username, password=self.password)
        elif self.proxy_type == "socks4":
            s.set_proxy(SOCKS4, self.host, self.port, username=self.username, password=self.password)
        elif self.proxy_type == "socks5":
            s.set_proxy(SOCKS5, self.host, self.port, username=self.username, password=self.password)
        else:
            raise ProxyError("Proxy type not found: " + self.proxy_type)

        return s

    def check(self, timeout=5):
        """
        Checks proxy by getting IP address from net.
        :param timeout:
        :return:
        """
        try_ses = Session()
        try_socket = socksocket(AF_INET, SOCK_STREAM)

        # Get original ip
        ses_res = try_ses.get("http://api.ipify.org", timeout=timeout)
        if ses_res.status_code != codes.ok: raise ProxyConnectionError("Proxy status code is not ok!")

        original_ip = ses_res.text

        # Set proxy for socket and session
        try_socket = self.set_to_socket(try_socket)

        # Check if proxy is working on session
        ses_res = try_ses.get("http://api.ipify.org", timeout=timeout, proxies=self.get_as_dict())
        if ses_res.status_code != codes.ok: raise ProxyConnectionError("Proxy status code is not ok!")

        proxied_ip = ses_res.text

        if proxied_ip == original_ip: raise ProxyError("Proxy is not working! IPs are same in session!")

        # Check if proxy is working on socket
        try_socket.settimeout(timeout)
        try_socket.connect(("api.ipify.org", 80))
        try_socket.sendall(bytes("GET / HTTP/1.1\r\nHost: api.ipify.org\r\n\r\n", "ascii"))

        proxied_ip = try_socket.recv(512)
        proxied_ip = str(proxied_ip, "ascii").split("\r\n\r\n")[-1]

        if proxied_ip == original_ip: raise ProxyError("Proxy is not working! IPs are same in socket!")

        try_socket.close()
        try_ses.close()
        return
