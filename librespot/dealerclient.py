#!/usr/bin/env python3
import ssl

from librespot.scopes import WebTokenScopes
from logging import getLogger
from websocket import WebSocket, WebSocketApp, enableTrace, create_connection
from json import dumps, loads
from json.decoder import JSONDecodeError
from time import sleep
from socket import IPPROTO_TCP, TCP_NODELAY, AF_INET, SOCK_STREAM
from socket import SOL_SOCKET, SO_REUSEADDR
from socks import socksocket
from zlib import decompress, MAX_WBITS
from threading import Lock, Thread, Event

__author__ = "Cool Guy, Hichigo"
__license__ = "GPL v3"
__status__ = "Production"


class DealerClient(Thread):
    """
    Dealer client for Spotify
    """

    def __init__(self, session):
        super(DealerClient, self).__init__()

        self.__logger = getLogger("spotify-session")
        self.__proxy = session.get_proxy()
        self.__session = session
        self.__headers_event = Event()
        self.__headers = None
        self.__terminated = False
        self.__listeners = None
        self.__listener_lock = Lock()
        self.__ping_thread = None
        self.__spotify_connection_id = None

        access_token = self.__session.get_web_token([WebTokenScopes.READ_PLAYLIST])["accessToken"]
        dealer_str = self.__session.find_dealer()
        self.__dealer_uri = \
            f"wss://{dealer_str}/?access_token={access_token}"

        # Connect to Spotify dealer
        self.__logger.debug("Connecting to dealer: " + self.__dealer_uri)

        # Set proxy
        if self.__proxy:
            proxied_sock = socksocket()
            proxied_sock = self.__proxy.set_to_socket(proxied_sock)
            dealer_tuple = (dealer_str.split(":")[0], int(dealer_str.split(":")[1]))
            proxied_sock.connect(dealer_tuple)
            proxied_sock = ssl.wrap_socket(proxied_sock)
            self.__logger.debug("Dealer client wrapped with proxy!")
            self.__ws = create_connection(self.__dealer_uri, socket=proxied_sock)
        else:
            self.__ws = create_connection(self.__dealer_uri)

        self.__on_open()
        self.start()

    def terminate(self):
        """
        Terminates the dealer
        :return:
        """

        self.__terminated = True
        self.__ping_thread.join()
        self.__ws.close()
        self.join()

        del self.__spotify_connection_id
        del self.__headers_event
        del self.__headers
        del self.__listeners
        del self.__ws

    def is_terminated(self) -> bool:
        """
        Check if dealer is terminated.
        :return:
        """
        return self.__terminated

    def get_connection_id(self) -> str:
        """
        Return the Spotify-Connection-Id header.
        :return:
        """
        return self.__spotify_connection_id

    def get_headers(self) -> dict:
        """
        Get headers that we got from Websocket
        :return:
        """
        return self.__headers

    def get_headers_event(self) -> Event:
        """
        Get event to wait until headers is assigned
        :return:
        """
        return self.__headers_event

    def get_websocket(self) -> WebSocket:
        """
        Get dealer's websocket.
        :return:
        """
        return self.__ws

    def get_dealer_host(self) -> str:
        """
        Get dealer host that WS connected.
        :return:
        """
        return self.__dealer_host

    def __send_ping(self) -> int:
        """
        Send ping request to WS.
        :return:
        """
        self.__ws.send("{\"type\":\"ping\"}")

    def __send_reply(self, key, is_success) -> int:
        """
        Send reply to WS.
        :param key: TODO: Find out wtf is this ???
        :param is_success: Is command succeded
        :return:
        """
        return self.__ws.send(
            dumps({
                "type": "reply",
                "key": key,
                "payload": {
                    "success": is_success
                }
            })
        )

    def __send_ping_interval(self):
        """
        Send ping on interval.
        :return:
        """
        self.__logger.debug("Websocket ping thread is started!")
        while not self.__terminated:
            self.__send_ping()
            sleep(3)

    def __on_message(self, message):
        message_json = None
        try:
            message_json = loads(message)
        except JSONDecodeError:
            self.__logger.warning("Couldn't parse websocket message: " + message)
            return

        if "type" not in message_json:
            self.__logger.debug("Unknown websocket message: " + message)
            return

        message_type = message_json["type"].upper()
        message_method, message_uri = "", ""
        if "method" in message_json:
            message_method = message_json["method"].upper()
        if "uri" in message_json:
            message_uri = message_json["uri"]

        if message_type == "PONG":
            # Silent
            return

        if message_type == "PING":
            # That's unexpected but ok...
            self.__logger.debug("Ping received from websocket!?")
            return

        if message_type == "MESSAGE":
            # Decode GZIP If payload is sent
            payload = None
            if "payload" in message_json:
                payload = decompress(message_json["payload"], 16 + MAX_WBITS)

            if message_uri.startswith("hm://pusher/v1/connections/"):
                # Update the headers and set event.
                self.__logger.debug("Headers received from websocket!")
                self.__headers = message_json["headers"]
                if "Spotify-Connection-Id" in self.__headers:
                    self.__spotify_connection_id = self.__headers["Spotify-Connection-Id"]
                if not self.__headers_event.is_set():
                    self.__headers_event.set()

    def __on_error(self, error):
        self.__logger.debug("Websocket error: " + error)

    def __on_close(self):
        self.__logger.debug("Websocket closed!")

    def __on_open(self):
        """Start ping thread"""
        self.__logger.debug("Connected to websocket!")

        self.__ping_thread = Thread(target=self.__send_ping_interval, args=())
        self.__ping_thread.start()

    def run(self) -> None:
        while not self.__terminated:
            try:
                message = self.__ws.recv()
                self.__on_message(message)
            except Exception as e:
                self.__on_error(str(e))

