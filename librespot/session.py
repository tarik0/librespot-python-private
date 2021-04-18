#!/usr/bin/env python3
import hmac
import logging
import sys
from base64 import b64encode
from binascii import b2a_hex
from hashlib import sha1
from json import loads
from os import urandom
from random import choice, random
from socket import *
from struct import pack, unpack
from threading import Lock, Event
from time import sleep
import re

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from requests import Session, codes, post, get, Response
from socks import socksocket

from librespot.base62 import Base62
from librespot.dealerclient import DealerClient
from librespot.scopes import WebTokenScopes

"""Import shannon and diffie-hellman"""
from librespot.shannon import Shannon
from diffiehellman.diffiehellman import DiffieHellman, PRIMES

"""Import custom exceptions"""
from librespot.exceptions import StatusException
from librespot.exceptions import SpotifyAuthException
from librespot.exceptions import SpotifyRegisterException

"""Import protobuffers"""
import librespot.protobuffers.keyexchange_pb2 as keyexchange
import librespot.protobuffers.authentication_pb2 as authentication
import librespot.protobuffers.metadata_pb2 as metadata

"""Import utility classses"""
from librespot.commands import SpotifyCommands
from librespot.mercury import MercuryManager

__author__ = "Cool Guy, Hichigo"
__license__ = "GPL v3"
__status__ = "Production"

REGISTRATION_KEY = "4c7a36d5260abca4af282779720cf631"
ACCESS_POINT_DEALER = "http://apresolve.spotify.com/"
KEY_LENGTH = 96
MAC_SIZE = 4
HEADER_SIZE = 3
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Spotify/1.1.42.622 " \
             "Safari/537.36 "

if not 1 in PRIMES:
    """
    Patch DH with non RFC prime to be used for handshake
    """
    PRIMES.update({1: {
        "prime": 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff,
        "generator": 2
    }})

""" Server Key as byte array """
SERVER_KEY = bytes([
        0xac, 0xe0, 0x46, 0x0b, 0xff, 0xc2, 0x30, 0xaf, 0xf4, 0x6b, 0xfe, 0xc3,
        0xbf, 0xbf, 0x86, 0x3d, 0xa1, 0x91, 0xc6, 0xcc, 0x33, 0x6c, 0x93, 0xa1,
        0x4f, 0xb3, 0xb0, 0x16, 0x12, 0xac, 0xac, 0x6a, 0xf1, 0x80, 0xe7, 0xf6,
        0x14, 0xd9, 0x42, 0x9d, 0xbe, 0x2e, 0x34, 0x66, 0x43, 0xe3, 0x62, 0xd2,
        0x32, 0x7a, 0x1a, 0x0d, 0x92, 0x3b, 0xae, 0xdd, 0x14, 0x02, 0xb1, 0x81,
        0x55, 0x05, 0x61, 0x04, 0xd5, 0x2c, 0x96, 0xa4, 0x4c, 0x1e, 0xcc, 0x02,
        0x4a, 0xd4, 0xb2, 0x0c, 0x00, 0x1f, 0x17, 0xed, 0xc2, 0x2f, 0xc4, 0x35,
        0x21, 0xc8, 0xf0, 0xcb, 0xae, 0xd2, 0xad, 0xd7, 0x2b, 0x0f, 0x9d, 0xb3,
        0xc5, 0x32, 0x1a, 0x2a, 0xfe, 0x59, 0xf3, 0x5a, 0x0d, 0xac, 0x68, 0xf1,
        0xfa, 0x62, 0x1e, 0xfb, 0x2c, 0x8d, 0x0c, 0xb7, 0x39, 0x2d, 0x92, 0x47,
        0xe3, 0xd7, 0x35, 0x1a, 0x6d, 0xbd, 0x24, 0xc2, 0xae, 0x25, 0x5b, 0x88,
        0xff, 0xab, 0x73, 0x29, 0x8a, 0x0b, 0xcc, 0xcd, 0x0c, 0x58, 0x67, 0x31,
        0x89, 0xe8, 0xbd, 0x34, 0x80, 0x78, 0x4a, 0x5f, 0xc9, 0x6b, 0x89, 0x9d,
        0x95, 0x6b, 0xfc, 0x86, 0xd7, 0x4f, 0x33, 0xa6, 0x78, 0x17, 0x96, 0xc9,
        0xc3, 0x2d, 0x0d, 0x32, 0xa5, 0xab, 0xcd, 0x05, 0x27, 0xe2, 0xf7, 0x10,
        0xa3, 0x96, 0x13, 0xc4, 0x2f, 0x99, 0xc0, 0x27, 0xbf, 0xed, 0x04, 0x9c,
        0x3c, 0x27, 0x58, 0x04, 0xb6, 0xb2, 0x19, 0xf9, 0xc1, 0x2f, 0x02, 0xe9,
        0x48, 0x63, 0xec, 0xa1, 0xb6, 0x42, 0xa0, 0x9d, 0x48, 0x25, 0xf8, 0xb3,
        0x9d, 0xd0, 0xe8, 0x6a, 0xf9, 0x48, 0x4d, 0xa1, 0xc2, 0xba, 0x86, 0x30,
        0x42, 0xea, 0x9d, 0xb3, 0x08, 0x6c, 0x19, 0x0e, 0x48, 0xb3, 0x9d, 0x66,
        0xeb, 0x00, 0x06, 0xa2, 0x5a, 0xee, 0xa1, 0x1b, 0x13, 0x87, 0x3c, 0xd7,
        0x19, 0xe6, 0x55, 0xbd
])
BASE62 = Base62.create_instance_with_inverted_character_set()


class SpotifySession:
    """
    Session class holds our connection with Spotify
    access point. Its our main class to connect.
    """

    def __init__(self,
                 proxy=None,
                 version_str="Spotify v3.15",
                 product=keyexchange.PRODUCT_MOBILE,
                 platform=keyexchange.PLATFORM_LINUX_X86,
                 api_version=0x10800000000,
                 cpu_family=authentication.CPU_X86,
                 os=authentication.OS_ANDROID,
                 system_information_string="Android"
                 ):
        """
        Initializes SpotifySession class with
        given proxy. Set proxy to None if you don't
        want to use proxy.
        :type device_id: Spotify device id
        :type version_str: Spotify version string
        :type proxy: SpotifyProxy
        """

        # Create new logger
        self.__logger = logging.getLogger("spotify-session")
        self.__log_handler = logging.StreamHandler(sys.stdout)
        self.__log_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s"))
        self.__logger.addHandler(self.__log_handler)

        self.__cpu_family = cpu_family
        self.__os = os
        self.__system_info = system_information_string
        self.__product = product
        self.__platfrom = platform
        self.__version = api_version
        self.__proxy = proxy
        self.__session = Session()
        self.__player_name = None
        self.__player_type = None
        self.__encoder = None
        self.__dealer = None
        self.__decoder = None
        self.__ap_welcome = None
        self.__auth_decline = None
        self.__mercury_manager = None
        self.__device_id = str(b2a_hex(urandom(20)), "utf8")
        self.__version_str = version_str
        self.__proxy_dict = {}
        self.__socket = socksocket(AF_INET, SOCK_STREAM)

        # Set proxy to session
        if self.__proxy is not None:
            self.__socket = self.__proxy.set_to_socket(self.__socket)
            self.__proxy_dict = self.__proxy.get_as_dict()
            self.__logger.debug("Wrapped session with proxy.")

        self.__api_base_url = None
        self.__access_point = None
        self.__connected_to_ap = False
        self.__lock = Lock()
        self.__keys = DiffieHellman(group=1, key_length=KEY_LENGTH)
        self.__keys.generate_private_key()
        self.__keys.generate_public_key()
        self.__accumulator = None
        self.__encoder_nonce = 0
        self.__decoder_nonce = 0
        self.__encoder_nonce_lock = Lock()
        self.__decoder_nonce_lock = Lock()

        self.__logger.debug("New Spotify session created!")

    def disconnect(self):
        """
        Disconnects and disposes the class
        :return:
        """
        if self.__socket:
            self.__socket.close()
            del self.__socket

        if self.__dealer:
            self.__dealer.terminate()
            del self.__dealer

        if self.__session:
            self.__session.close()
            del self.__session

        if self.__mercury_manager:
            self.__mercury_manager.terminate()
            del self.__mercury_manager

        del self.__player_type
        del self.__player_name
        del self.__api_base_url
        del self.__cpu_family
        del self.__os
        del self.__system_info
        del self.__proxy
        del self.__product
        del self.__proxy_dict
        del self.__version_str
        del self.__version
        del self.__encoder
        del self.__decoder
        del self.__encoder_nonce
        del self.__decoder_nonce
        del self.__encoder_nonce_lock
        del self.__lock
        del self.__decoder_nonce_lock
        del self.__accumulator
        del self.__access_point
        del self.__keys
        del self.__connected_to_ap
        del self.__platfrom

    def is_connected(self) -> bool:
        """
        Checks if session is connected to access point.
        :return: bool
        """
        return self.__connected_to_ap

    def is_logged_in(self) -> bool:
        """
        Gets the login status of session.
        :return:
        """
        if self.__ap_welcome is not None: return True
        return False

    def get_dealer(self) -> DealerClient:
        """
        Gets DealerClient of session
        :return:
        """
        return self.__dealer

    def get_ap_welcome(self) -> authentication.APWelcome:
        """
        Gets APWelcome of session.
        :return:
        """
        return self.__ap_welcome

    def get_auth_failure(self) -> keyexchange.APLoginFailed:
        """
        Gets the auth failure of session.
        :return:
        """
        return self.__auth_decline

    def get_proxy(self) -> dict:
        """ Return session's proxy. """
        return self.__proxy

    def get_device_os(self) -> int:
        """
        Get device's given operation system.
        :return:
        """
        return self.__os

    def get_mercury_manager(self) -> MercuryManager:
        """
        Get device's mercury manager.
        :return:
        """
        return self.__mercury_manager

    def get_cpu_family(self) -> int:
        """
        Get device's given CPU family.
        :return:
        """
        return self.__cpu_family

    def get_system_info_str(self) -> str:
        """
        Gets given device system information string.
        :return:
        """
        return self.__system_info

    def get_access_point(self) -> (str, int):
        """
        Get access point of connected socket.
        :return: Tuple
        """
        return self.__access_point

    def get_device_id(self) -> str:
        """
        Gets device id of SpotifySession
        :return:
        """
        return self.__device_id

    def get_device_platform(self) -> str:
        """
        Gets device platform of SpotifySession.
        :return:
        """
        return self.__platfrom

    def get_socket(self) -> socket:
        """
        Gets SpotifySession's socket.
        :return:
        """
        return self.__socket

    def get_http_session(self) -> Session:
        """
        Gets the Http Session that class uses.
        :return:
        """
        return self.__session

    def find_access_point(self) -> (str, int):
        """
        Gets random access point from dealer.
        :return: str
        """
        res = self.__session.get(ACCESS_POINT_DEALER + "?type=accesspoint", proxies=self.__proxy_dict, timeout=5)
        if res.status_code != codes.ok: raise StatusException("Dealer status code is not ok!")

        json = loads(res.text)
        ap_str = choice(json["accesspoint"])
        ap_host = ap_str.split(":")[0]
        ap_port = int(ap_str.split(":")[1])

        self.__logger.debug(f"New Spotify access point {ap_str}!")
        return ap_host, ap_port

    def find_dealer(self) -> str:
        """
        Gets random dealer from Spotify
        :return:
        """
        res = self.__session.get(ACCESS_POINT_DEALER + "?type=dealer", proxies=self.__proxy_dict, timeout=5)
        if res.status_code != codes.ok: raise StatusException("Dealer status code is not ok!")

        json = loads(res.text)
        ap_str = choice(json["dealer"])

        self.__logger.debug(f"New Spotify dealer {ap_str}!")
        return ap_str

    def find_spclient(self) -> str:
        """
        Gets random spclient from dealer.
        :return: str
        """
        res = self.__session.get(ACCESS_POINT_DEALER + "?type=spclient", proxies=self.__proxy_dict, timeout=5)
        if res.status_code != codes.ok: raise StatusException("Dealer status code is not ok!")

        json = loads(res.text)
        ap_str = "https://" + choice(json["spclient"])

        self.__logger.debug(f"New Spotify spclient {ap_str}!")
        return ap_str

    def send_encoded(self, prefix, data) -> (bytes, int):
        """
        Sends an encoded request to the socket.
        :param prefix: Command prefix
        :param data: Non-encoded request data
        :return: sent request, written byte count
        """
        if prefix is None:
            prefix = b""

        with self.__encoder_nonce_lock:
            self.__encoder.set_nonce(self.__encoder_nonce)
            self.__encoder_nonce += 1

        request = bytes([prefix]) + pack(">H", len(data)) + data
        request = self.__encoder.encrypt(request)
        request += self.__encoder.finish(MAC_SIZE)

        try:
            bytes_written = self.__socket.send(request)
        except AttributeError:
            # Socket is terminated by us
            return

        # Sleep a bit cuz it's too fast bruh
        sleep(0.2)
        return request, bytes_written

    def recv_encoded(self) -> (bytes, bytes):
        """
        Recieves encoded packet from socket and decodes it.
        :return: command prefix, packet bytes
        """
        with self.__decoder_nonce_lock:
            self.__decoder.set_nonce(self.__decoder_nonce)
            self.__decoder_nonce += 1

        try:
            header_bytes = self.__socket.recv(HEADER_SIZE)
            header_bytes = self.__decoder.decrypt(header_bytes)
        except AttributeError and IndexError:
            # Socket is terminated by us
            return

        if len(header_bytes) == 0:
            return

        cmd = header_bytes[0]
        packet_size = (header_bytes[1] << 8) | (header_bytes[2] & 0xFF)

        packet = self.__socket.recv(packet_size)
        packet = self.__decoder.decrypt(packet)

        mac = self.__socket.recv(MAC_SIZE)
        expected_mac = self.__decoder.finish(MAC_SIZE)

        if mac != expected_mac: raise ConnectionError("MACs don't match!")

        # Sleep a bit cuz it's too fast bruh
        sleep(0.2)
        return cmd, packet

    def connect(self) -> bool:
        """
        Connects to the access point and does
        the handshakes with it.
        :return:
        """
        with self.__lock:
            self.__connected_to_ap = False

        self.__session = Session()
        self.__access_point = self.find_access_point()
        self.__api_base_url = self.find_spclient()
        self.__socket.connect(self.__access_point)
        self.__logger.debug(f"Connected to {self.__access_point}!")

        """Send ClientHello request"""
        diffie_hellman_hello = keyexchange.LoginCryptoDiffieHellmanHello(**{
            "gc": self.__keys.public_key.to_bytes(KEY_LENGTH, byteorder="big"),
            "server_keys_known": 1
        })

        client_hello = keyexchange.ClientHello(**{
            "cryptosuites_supported": [keyexchange.CRYPTO_SUITE_SHANNON],
            "login_crypto_hello": keyexchange.LoginCryptoHelloUnion(**{"diffie_hellman": diffie_hellman_hello}),
            "client_nonce": bytes([int(random() * 0xFF) for x in range(0, 0x10)]),
            "padding": bytes([0x1E]),
            "feature_set": keyexchange.FeatureSet(**{"autoupdate2": True}),
            "build_info": keyexchange.BuildInfo(**{
                "product": self.__product,
                "platform": self.__platfrom,
                "version": self.__version
            })
        })

        client_hello_serialized = client_hello.SerializeToString()

        """Send to socket"""
        self.__logger.debug("Sending ClientHello!")
        size = 2 + 4 + len(client_hello_serialized)
        request = b"\x00\x04" + pack(">I", size) + client_hello_serialized
        self.__socket.send(request)

        """Process APResponseMessage response"""
        size_bytes = self.__socket.recv(4)
        size = unpack(">I", size_bytes)
        buffer = self.__socket.recv(size[0] - 4)
        packet = size_bytes + buffer

        response = keyexchange.APResponseMessage()
        response.ParseFromString(packet[4:])
        self.__logger.debug("Got new APResponseMessage!")

        """Check GS Signature"""

        _rsa = RSA.construct((int.from_bytes(SERVER_KEY, "big"), 65537))
        pkcs1_v1_5 = PKCS1_v1_5.new(_rsa)
        _sha1 = SHA1.new()
        _sha1.update(response.challenge.login_crypto_challenge.diffie_hellman.gs)

        # noinspection PyTypeChecker
        if not pkcs1_v1_5.verify(_sha1, response.challenge.login_crypto_challenge.diffie_hellman.gs_signature):
            raise RuntimeError("Failed signature check!")

        """Solve diffie-hellman challenge"""
        remote_key = response.challenge.login_crypto_challenge.diffie_hellman.gs

        # Write to accumulator we will send this later.
        self.__accumulator = request + size_bytes + buffer

        self.__keys.generate_shared_secret(int.from_bytes(remote_key, byteorder="big"))
        shared_keys = self.__keys.shared_secret.to_bytes(KEY_LENGTH, byteorder="big")
        original_mac = hmac.new(shared_keys, digestmod=sha1)

        data = []
        for i in range(1, 6):
            mac = original_mac.copy()
            mac.update(self.__accumulator + bytes([i]))
            digest = mac.digest()
            data += digest

        mac = hmac.new(bytes(data[:0x14]), digestmod=sha1)
        mac.update(self.__accumulator)

        challenge = mac.digest()
        send_key = bytes(data[0x14:0x34])
        recv_key = bytes(data[0x34:0x54])

        self.__logger.debug("Session keys are set!")

        """Send ClientHandshakeChallenge"""
        diffie_hellman_response = keyexchange.LoginCryptoDiffieHellmanResponse(**{
            "hmac": challenge
        })

        crypto_response = keyexchange.LoginCryptoResponseUnion(**{
            "diffie_hellman": diffie_hellman_response
        })

        client_response_pt = keyexchange.ClientResponsePlaintext(**{
            "login_crypto_response": crypto_response,
            "pow_response": keyexchange.PoWResponseUnion(),
            "crypto_response": keyexchange.CryptoResponseUnion()
        })

        """Send ClientResponsePlaintext to socket"""
        self.__logger.debug("Sending ClientResponsePlaintext!")
        client_response_pt_serialized = client_response_pt.SerializeToString()
        size = 4 + len(client_response_pt_serialized)
        request = pack(">I", size) + client_response_pt_serialized
        self.__socket.send(request)

        try:
            """Parse junk response"""
            old_socket_timeout = self.__socket.gettimeout()
            scrap = bytearray([0, 0, 0, 0])
            self.__socket.settimeout(0.3)
            read_bytes = self.__socket.recv_into(scrap)
            if read_bytes == len(scrap):
                length = (scrap[0] << 24) | (scrap[1] << 16) | (scrap[2] << 8) | (scrap[3] & 0xFF)
                payload = self.__socket.recv(length)
                ap_failed = keyexchange.APResponseMessage()
                ap_failed.ParseFromString(payload)
                raise SpotifyAuthException(ap_failed)
            elif read_bytes > 0:
                raise ValueError("Read unknown data!")
        except timeout:
            # Ignored
            pass
        finally:
            self.__socket.settimeout(old_socket_timeout)
            self.__logger.debug("Junkcode parsed!")

        """Complete handshake"""
        with self.__lock:
            self.__encoder_nonce = 0
            self.__decoder_nonce = 0
            self.__encoder = Shannon(send_key)
            self.__decoder = Shannon(recv_key)
            self.__connected_to_ap = True

        self.__logger.debug("Handshake successful with Spotify!")
        return self.__connected_to_ap

    def login(self, username, password) -> bool:
        """
        Send a login request to the Spotify.
        :param username: Spotify username
        :param password: Spotify password
        :return:
        """

        """Send ClientResponseEncrypted"""
        auth_request = authentication.ClientResponseEncrypted(**{
            "login_credentials": authentication.LoginCredentials(**{
                "username": username,
                "typ": authentication.AUTHENTICATION_USER_PASS,
                "auth_data": bytes(password, "utf8")
            }),
            "system_info": authentication.SystemInfo(**{
                "cpu_family": self.__cpu_family,
                "os": self.__os,
                "system_information_string": self.__system_info,
                "device_id": self.__device_id
            }),
            "version_string": self.__version_str
        })

        auth_request_serialized = auth_request.SerializeToString()
        self.send_encoded(SpotifyCommands.LOGIN_REQUEST_COMMAND, auth_request_serialized)

        """Get login response"""
        command, packet = self.recv_encoded()

        if command == SpotifyCommands.AUTH_SUCCESSFUL_COMMAND:
            auth_welcome = authentication.APWelcome()
            auth_welcome.ParseFromString(packet)
            self.__logger.debug(f"Successfully logged into {username}!")
            self.__ap_welcome = auth_welcome
            self.__mercury_manager = MercuryManager(self)

            # Wait mercury manager to be ready.
            self.__mercury_manager.get_ready_event().wait(timeout=15)

            self.__dealer = DealerClient(self)
            return True
        elif command == SpotifyCommands.AUTH_DECLINED_COMMAND:
            auth_decline = keyexchange.APLoginFailed()
            auth_decline.ParseFromString(packet)
            self.__auth_decline = auth_decline
            raise SpotifyAuthException(self.__auth_decline)

        raise SpotifyAuthException("Unknown Auth Failure Code: %02X" % command)

    @staticmethod
    def register(display_name="", gender="", password="", email="", birth_day="", birth_month="", birth_year="",
                 proxy=None) \
            -> dict:
        """
        Registers to the Spotify with given data.
        :param display_name: Display name of account (ex. your fullname)
        :param gender: "male" or "female"
        :param password: Account password
        :param email: E-Mail of the account
        :param birth_day: Birthday of account (ex. 01)
        :param birth_month: Birth month of account (ex. 06)
        :param birth_year: Birth year of account (ex. 1999)
        :return: Registration JSON response as dict
        """
        tmp_proxy = {}
        if proxy: tmp_proxy = proxy.get_as_dict()

        res = get(ACCESS_POINT_DEALER + "?type=spclient", proxies=tmp_proxy, timeout=5)
        if res.status_code != codes.ok: raise StatusException("Dealer status code is not ok!")

        host = choice(res.json()["spclient"])
        res = post(
            f"https://{host}/signup/public/v1/account/",
            data={
                "displayname": display_name,
                "gender": gender,
                "key": REGISTRATION_KEY,
                "password_repeat": password,
                "birth_day": str(birth_day),
                "email": email,
                "iagree": "1",
                "platfrom": "desktop",
                "referrer": "msft_1",
                "birth_month": str(birth_month),
                "creation_point": "https://login.app.spotify.com?utm_source=spotify&utm_medium=desktop-win32-store"
                                  "&utm_campaign=msft_1&referral=msft_1&referrer=msft_1",
                "creation_flow": "desktop",
                "birth_year": str(birth_year),
                "password": password
            },
            headers={
                "Connection": "close",
                "Host": host.replace("https://", ""),
                "X-Client-Id": "",
                "Origin": "https://login.app.spotify.com",
                "Spotify-App-Version": "1.1.42.622.gbd112320",
                "App-Platform": "Win32",
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Sec-Fetch-Site": "same-site",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Dest": "empty",
                "Accept-Language": "en"
            },
            proxies=tmp_proxy,
        )

        if res.status_code != codes.ok:
            raise StatusException("Register status is not ok!")

        json_obj = res.json()

        if json_obj["status"] != 1 or not json_obj["username"]:
            raise SpotifyRegisterException("Register status is not ok!")

        return json_obj

    def put_connect_state(self, connection_id, put_state_req) -> Response:
        """
        Set connection state of device.
        :param: connection_id: Spotify connection id that coming from DealerClient's WS
        :param state_protobuffer: PutStateRequest protobuffer
        :param scopes: A list of WebTokenScopes
        :return:
        """
        access_token = self.get_web_token([WebTokenScopes.READ_PLAYLIST])["accessToken"]
        endpoint = f"{self.__api_base_url}/connect-state/v1/devices/{self.__device_id}"
        res = self.__session.put(
            endpoint,
            headers={
                "Authorization": "Bearer " + access_token,
                "X-Spotify-Connection-Id": connection_id,
                "Content-Type": "application/protobuf"
            },
            data=put_state_req.SerializeToString(),
        )

        if res.status_code != 200:
            raise StatusException(f"Put state status is {res.status_code}!")

        return res

    def get_track_metadata(self, track_uri: str):
        """
        Get track metadata from SPClient.
        :return:
        """
        # Parse URI
        pattern = re.compile("spotify:track:(.{22})")
        search = pattern.search(track_uri)
        if search is None:
            raise Exception("Unknown Spotify Track URI")

        # Get Track's HEX ID
        tmp = BASE62.decode(search.group(1), 16)
        hex_id = str(b2a_hex(tmp), "ascii").lower()

        # Send request
        access_token = self.get_web_token([WebTokenScopes.READ_PLAYLIST])["accessToken"]
        endpoint = f"{self.__api_base_url}/metadata/4/track/{hex_id}"
        res = self.__session.get(
            endpoint,
            headers={
                "Authorization": "Bearer " + access_token
            },
        )

        if res.status_code != 200:
            raise StatusException(f"Put state status is {res.status_code}!")

        tm = metadata.Track()
        tm.ParseFromString(res.content)
        return tm

    def get_web_token(self, scopes, timeout=10) -> dict:
        """
        Get Web token with given scopes from Mercury request.
        :return:
        """
        if self.__mercury_manager is None or self.__ap_welcome is None or \
                not self.__mercury_manager.get_ready_event().is_set():
            raise SpotifyAuthException("Session is not authenticated yet!")

        event = Event()
        event.clear()

        def callback(__seq_id, __header, __chunks):
            event.header = __header
            event.chunks = __chunks
            event.set()

        # Send mercury request
        scopes_str = ",".join(scopes)
        self.__mercury_manager.execute_request(
            "GET",
            f"hm://keymaster/token/authenticated?client_id=65b708073fc0480ea92a077233ca87bd&scope={scopes_str}&device_id={self.__device_id}",
            callback
        )

        # Wait response
        event.wait(timeout=timeout)

        if not hasattr(event, "chunks"):
            raise TimeoutError("Mercury request timed out!")

        api_key = loads(str(event.chunks[0], "utf8"))
        return api_key

    def follow_user(self, user_type, user_ids):
        """
        Follow an user or artist.
        :param user_type: User type (ex. "USER" or "ARTIST")
        :param user_ids: An list of user ids
        :return:
        """
        # Get web token
        token_dict = self.get_web_token(WebTokenScopes.follow_scopes())
        web_token = token_dict["accessToken"]

        res = self.__session.put(
            "https://api.spotify.com/v1/me/following?type=" + user_type.lower() + "&ids=" + "%2C".join(user_ids),
            headers={
                "Authorization": "Bearer " + web_token,
                "Content-Type": "application/json"
            }
        )

        if res.status_code != 204:
            raise StatusException(f"Follow status is {res.status_code}!")
        return

    def get_version_str(self) -> str:
        """
        Get session's version string.
        :return:
        """
        return self.__version_str
