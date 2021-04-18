#!/usr/bin/env python3


class WebTokenScopes:
    """
    Web token scopes for getting web token.
    https://developer.spotify.com/documentation/general/guides/scopes/
    """
    UGC_IMAGE_UPLOAD = "ugc-image-upload"
    USER_READ_PLAYBACK_STATE = "user-read-playback-state"
    USER_READ_PLAYBACK_POSITION = "user-read-playback-position"
    USER_READ_EMAIL = "user-read-email"
    USER_LIBRARY_READ = "user-library-read"
    USER_TOP_READ = "user-top-read",
    STREAMING = "streaming",
    APP_REMOTE_CONTROL = "app-remote-control",
    PLAYLIST_MODIFY_PUBLIC = "playlist-modify-public"
    USER_FOLLOW_READ = "user-follow-read"
    USER_MODIFY_PLAYBACK_STATE = "user-modify-playback-state"
    USER_READ_RECENTLY_PLAYED = "user-read-recently-played"
    USER_READ_PRIVATE = "user-read-private"
    PLAYLIST_READ_PRIVATE = "playlist-read-private"
    USER_LIBRARY_MODIFY = "user-library-modify"
    PLAYLIST_READ_COLLABORATIVE = "playlist-read-collaborative"
    PLAYLIST_MODIFY_PRIVATE = "playlist-modify-private"
    USER_FOLLOW_MODIFY = "user-follow-modify"
    USER_READ_CURRENTLY_PLAYING = "user-read-currently-playing"
    READ_PLAYLIST = "playlist-read"

    @staticmethod
    def image_scopes() -> list:
        """
        Get token scopes used for uploading images.
        :return:
        """
        return [WebTokenScopes.UGC_IMAGE_UPLOAD]

    @staticmethod
    def listening_history_scopes() -> list:
        """
        Get token scopes for listening history.
        """
        return [
            WebTokenScopes.USER_TOP_READ,
            WebTokenScopes.USER_READ_PLAYBACK_POSITION,
            WebTokenScopes.USER_READ_RECENTLY_PLAYED
        ]

    @staticmethod
    def spotify_connect_scopes() -> list:
        """
        Get scopes for connecting spotify.
        :return:
        """
        return [
            WebTokenScopes.USER_READ_PLAYBACK_STATE,
            WebTokenScopes.USER_READ_CURRENTLY_PLAYING,
            WebTokenScopes.USER_MODIFY_PLAYBACK_STATE
        ]

    @staticmethod
    def library_scopes() -> list:
        """
        Get scopes for reading library.
        :param self:
        :return:
        """
        return [
            WebTokenScopes.USER_LIBRARY_MODIFY,
            WebTokenScopes.USER_LIBRARY_READ
        ]

    @staticmethod
    def playback_scopes() -> list:
        """
        Get scopes for playback.
        :param self:
        :return:
        """
        return [
            WebTokenScopes.STREAMING,
            WebTokenScopes.APP_REMOTE_CONTROL
        ]

    @staticmethod
    def user_scopes() -> list:
        """
        Get scopes for user readings.
        :return:
        """
        return [
            WebTokenScopes.USER_READ_PRIVATE,
            WebTokenScopes.USER_READ_EMAIL
        ]

    @staticmethod
    def follow_scopes() -> list:
        """
        Get scopes for following things.
        :return:
        """
        return [
            WebTokenScopes.USER_FOLLOW_MODIFY,
            WebTokenScopes.USER_FOLLOW_READ
        ]

    @staticmethod
    def playlist_scopes() -> list:
        """
        Get scopes for getting playlist data.
        :return:
        """
        return [
            WebTokenScopes.PLAYLIST_MODIFY_PRIVATE,
            WebTokenScopes.PLAYLIST_READ_PRIVATE,
            WebTokenScopes.PLAYLIST_READ_COLLABORATIVE,
            WebTokenScopes.PLAYLIST_MODIFY_PUBLIC
        ]

    @staticmethod
    def all() -> list:
        """
        Get all token scopes as a list.
        :return:
        """
        return [
            WebTokenScopes.USER_READ_PLAYBACK_STATE,
            WebTokenScopes.USER_READ_PLAYBACK_POSITION,
            WebTokenScopes.USER_READ_EMAIL,
            WebTokenScopes.USER_LIBRARY_READ,
            WebTokenScopes.USER_TOP_READ,
            WebTokenScopes.PLAYLIST_MODIFY_PUBLIC,
            WebTokenScopes.USER_FOLLOW_READ,
            WebTokenScopes.USER_MODIFY_PLAYBACK_STATE,
            WebTokenScopes.USER_READ_RECENTLY_PLAYED,
            WebTokenScopes.USER_READ_PRIVATE,
            WebTokenScopes.PLAYLIST_READ_PRIVATE,
            WebTokenScopes.USER_LIBRARY_MODIFY,
            WebTokenScopes.PLAYLIST_READ_COLLABORATIVE,
            WebTokenScopes.PLAYLIST_MODIFY_PRIVATE,
            WebTokenScopes.USER_FOLLOW_MODIFY,
            WebTokenScopes.USER_READ_CURRENTLY_PLAYING,
            WebTokenScopes.UGC_IMAGE_UPLOAD,
            WebTokenScopes.STREAMING
        ]
