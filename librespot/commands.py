#!/usr/bin/env python3

__author__ = "Cool Guy, Hichigo"
__license__ = "GPL v3"
__status__ = "Production"


class SpotifyCommands:
    """
    We are using this command headers to communicate
    with Spotify server socket.
    """
    INVALID_COMMAND = 0xFFFF
    LOGIN_REQUEST_COMMAND = 0xAB
    AUTH_SUCCESSFUL_COMMAND = 0xAC
    AUTH_DECLINED_COMMAND = 0xAD
    PING = 0x04
    AUDIO_CHUNK_REQUEST_COMMAND = 0x08
    AUDIO_CHUNK_SUCCESS_RESPONSE = 0x09
    AUDIO_CHUNK_FAILURE_RESPONSE = 0x0A
    AUDIO_KEY_REQUEST_COMMAND = 0x0C
    AUDIO_KEY_SUCCESS_RESPONSE = 0x0D
    AUDIO_KEY_FAILURE_RESPONSE = 0x0E
    COUNTRY_CODE_RESPONSE = 0x1B
    MERCURY_REQUEST = 0xB2
    MERCURY_EVENT = 0xB5
    MERCURY_SUB = 0xB3
    PREFERED_LOCALE = 0x74
    ACCOUNT_DETAILS = 0x50
    LICENSE_VERSION = 0x76
    PONG = 0x49
    PONG_ACK = 0x4A
    AES_KEY = 0x0D
    AES_KEY_ERROR = 0x0E
    STREAM_CHUNK = 0x08
    STREAM_CHUNK_RES = 0x09
