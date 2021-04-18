#!/usr/bin/env python3

__author__ = "Cool Guy, Hichigo"
__license__ = "GPL v3"
__status__ = "Production"


class StatusException(Exception):
    """
    Raised when http session request's
    status is not ok!
    """

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class SpotifyAuthException(Exception):
    """Raised when Spotify login is failed."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class SpotifyRegisterException(Exception):
    """
    Raised when register status is not ok
    or username is blank.
    """

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class SpotifyURIException(Exception):
    """
    Raised when an invalid URI passed to
    play functions.
    """

    def __init__(self, message):
        super().__init__(message)
        self.message = message
