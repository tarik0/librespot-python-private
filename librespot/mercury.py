#!/usr/bin/env python3
from threading import Thread, Lock, Event
from time import time

from librespot.commands import SpotifyCommands
from socket import timeout
from logging import getLogger
from struct import unpack, pack

from librespot.eventtypes import EventTypes

"""Import protobuffers"""
import librespot.protobuffers.mercury_pb2 as mercury

__author__ = "Cool Guy, Hichigo"
__license__ = "GPL v3"
__status__ = "Production"


class MercuryManager(Thread):
    """
    A class to communicate with Mercury (Hermes) protocol.
    """

    def __init__(self, spotify_session):
        super(MercuryManager, self).__init__()
        self.__spotify_session = spotify_session
        self.__logger = getLogger("spotify-session")
        self.__callbacks = {}
        self.__terminated = False
        self.__license_version = None
        self.__country = None
        self.__details = ""
        self.__ready_event = Event()
        self.__sequence_lock = Lock()
        self.__sequence = 0x0
        self.start()

    def get_ready_event(self) -> Event:
        """
        Get ready event to wait or check.
        :return:
        """
        return self.__ready_event

    def get_country(self) -> str:
        """
        Get country of spotify session
        :return:
        """
        return self.__country

    def get_account_details(self) -> str:
        """
        Get account details coming from socket
        :return:
        """
        return self.__details

    def get_license_version(self) -> str:
        """
        Get license version of session
        :return:
        """
        return self.__license_version

    def is_terminated(self) -> bool:
        """
        Check if manager is terminated.
        :return:
        """
        return self.__terminated

    def terminate(self):
        """
        Terminates the manager.
        :return:
        """
        self.__terminated = True
        self.join()

        del self.__logger
        del self.__country
        del self.__callbacks
        del self.__terminated
        del self.__sequence
        del self.__sequence_lock
        del self.__details
        del self.__license_version

    @staticmethod
    def __parse_mercury_request(command, packet) -> (int, bytes, list):
        """
        Parses the mercury request.
        :param command: Command byte
        :param packet: Payload of packet
        :return:
        """
        header_size = unpack(">H", packet[13: 15])[0]
        header = mercury.Header()
        header.ParseFromString(packet[15: 15 + header_size])

        # Parse all chunks
        pos = 15 + header_size
        chunks = []
        while pos < len(packet):
            chunk_size = unpack(">H", packet[pos: pos + 2])[0]
            chunk = packet[pos + 2: pos + 2 + chunk_size]
            chunks.append(chunk)
            pos += 2 + chunk_size

        return int.from_bytes(packet[2: 10], byteorder="big"), header, chunks

    def execute_request(self, request_type, uri, callback, user_fields=None, payload=None):
        """
        Sends a Mercury Request to server.
        :param request_type: Mercury request type (ex. GET)
        :param uri: URI to send the request
        :param callback: Callback function for request
        :return:
        """
        header = None
        if user_fields is None:
            header = mercury.Header(**{
                "uri": uri,
                "method": request_type
            })
        else:
            header = mercury.Header(**{
                "uri": uri,
                "method": request_type,
                "user_fields": user_fields
            })

        header_serialized = header.SerializeToString()

        buffer = b"\x00\x08" + self.__sequence.to_bytes(8, byteorder="big")

        # If there is no payload the part count that we are going to send is one
        if payload is None:
            buffer += b"\x01" + b"\x00\x01" + pack(">H", len(header_serialized)) + header_serialized
        else:
            buffer += b"\x01" + b"\x00\x02" + pack(">H", len(header_serialized)) + header_serialized

        # Add payloads to buffer
        if payload:
            buffer += pack(">H", len(payload)) + payload

        # Add to callbacks
        self.__callbacks[self.__sequence] = callback

        with self.__sequence_lock:
            self.__sequence += 1

        self.__spotify_session.send_encoded(SpotifyCommands.MERCURY_REQUEST, buffer)

    def execute_event(self, timestamp: int, body: bytes, timeout=15) -> (str, list):
        """
        Execute new mercury event.
        :return:
        """
        event = Event()
        event.clear()

        def callback(__seq_id, __header, __chunks):
            event.header = __header
            event.chunks = __chunks
            event.set()

        # Generate user fields
        user_fields = [
            mercury.UserField(**{
                "key": "Accept-Language",
                "value": bytes("en", "utf8")
            }),
            mercury.UserField(**{
                "key": "X-ClientTimeStamp",
                "value": bytes(str(timestamp), "utf8")
            })
        ]

        self.execute_request("POST", "hm://event-service/v1/events", callback, user_fields=user_fields, payload=body)

        # Wait response
        event.wait(timeout=timeout)

        if not hasattr(event, "chunks"):
            raise TimeoutError("Mercury request timed out!")

        body_str = str(body.replace(b"\x09", bytes("|", "utf8")), "utf8")
        header_str = str(event.header).strip().replace("\n", " ")
        self.__logger.debug(f"Event sent: {body_str}, res: {header_str}")

        return event.header, event.chunks

    def run(self):
        """
        Main thread to read Mercury packets.
        :return:
        """

        while not self.__terminated:
            try:
                command, packet = self.__spotify_session.recv_encoded()

                if command == SpotifyCommands.PING:
                    """Send pong"""
                    self.__spotify_session.send_encoded(SpotifyCommands.PONG, packet)
                elif command == SpotifyCommands.PONG_ACK:
                    # Silent
                    pass
                elif command == SpotifyCommands.LICENSE_VERSION:
                    id = int.from_bytes(packet[:4], byteorder="big")
                    if id != 0:
                        self.__license_version = str(packet[2:], "ascii")
                    else:
                        self.__license_version = str(id)
                    self.__logger.debug("License version found: " + self.__license_version)
                elif command == SpotifyCommands.COUNTRY_CODE_RESPONSE:
                    """Parse country code response"""
                    self.__country = packet.decode("ascii").upper()
                    self.__ready_event.set()
                    self.__logger.debug(f"Country found: {self.__country}")
                elif command == SpotifyCommands.ACCOUNT_DETAILS:
                    """Parse account details"""
                    self.__details = packet.decode("utf8")
                elif command == SpotifyCommands.MERCURY_EVENT:
                    """Parse a Mercury event"""
                    self.__logger.debug("New mercury event!")
                elif command == SpotifyCommands.MERCURY_REQUEST:
                    """Parse a Mercury request"""
                    seq_id, header, chunks = self.__parse_mercury_request(command, packet)

                    # Check if seq_id is in our callbacks
                    try:
                        callback = self.__callbacks[seq_id]
                        del self.__callbacks[seq_id]
                    except:
                        # Callback not found
                        callback = None

                    if not callback:
                        self.__logger.debug(f"Callback for {seq_id} is not found!")
                    else:
                        callback(seq_id, header, chunks)

                else:
                    self.__logger.debug(f"Received unknown response {hex(command)}, length: {len(packet)}")
            except timeout:
                pass
            except OSError:
                if self.__terminated: return
            except TypeError:
                if self.__terminated: return
