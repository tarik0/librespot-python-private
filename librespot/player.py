#!/usr/bin/env python3
from base64 import b64encode, urlsafe_b64encode
from binascii import b2a_hex
from calendar import timegm
from json import loads
from logging import getLogger
from os import urandom
from threading import Event
from time import gmtime, time, sleep

from librespot.eventtypes import EventTypes
from librespot.protobuffers.connect_pb2 import PutStateReason, PutStateRequest, MemberType, Device, DeviceInfo, \
    COMPUTER, Capabilities, NEW_DEVICE, PLAYER_STATE_CHANGED
from librespot.protobuffers.player_pb2 import PlayerState, Restrictions, ContextPlayerOptions, Suppressions, PlayOrigin, \
    ContextIndex, ProvidedTrack


class SpotifyPlayer:
    """
    Player class to fake stream medias.
    """

    def __init__(self, session, player_name="librespot-python", player_type=COMPUTER):
        self.__session = session
        self.__dealer = session.get_dealer()
        self.__player_type = player_type
        self.__player_name = player_name
        self.__session_id = None
        self.__logger = getLogger("spotify-session")
        self.__terminated = False
        self.__is_active = False
        self.__device_info = self.__init_device_info()
        self.__state = self.__init_state()
        self.__spotify_connection_id = None
        self.__mercury_manager = self.__session.get_mercury_manager()
        self.__track_transition_incremental = 0
        self.__put_state = PutStateRequest(**{
            "member_type": MemberType.CONNECT_STATE,
            "device": Device(**{
                "device_info": self.__device_info
            })
        })

    @staticmethod
    def __init_state() -> PlayerState:
        """
        Generate new player state.
        """
        return PlayerState(**{
            "context_restrictions": Restrictions(),
            "playback_speed": 1.0,
            "position": 0,
            "position_as_of_timestamp": 0,
            "is_system_initiated": True,
            "options": ContextPlayerOptions(**{
                "shuffling_context": False,
                "repeating_context": False,
                "repeating_track": False
            }),
            "suppressions": Suppressions()
        })

    def __init_device_info(self) -> DeviceInfo:
        """
        Generate new device info.
        :return:
        """
        return DeviceInfo(**{
            "can_play": True,
            "volume": 65536,
            "name": self.__player_name,
            "device_id": self.__session.get_device_id(),
            "device_type": self.__player_type,
            "device_software_version": self.__session.get_version_str(),
            "spirc_version": "3.2.6",
            "capabilities": Capabilities(**{
                "can_be_player": True,
                "gaia_eq_connect_id": True,
                "supports_logout": True,
                "is_observable": True,
                "volume_steps": 5,
                "supported_types": ["audio/track", "audio/episode"],
                "command_acks": True,
                "supports_playlist_v2": True,
                "is_controllable": True,
                "supports_transfer_command": True,
                "supports_command_request": True,
                "supports_gzip_pushes": True
            })
        })

    @staticmethod
    def get_random_session_id():
        """
        Generate random session id for player.
        :return:
        """
        return str(urlsafe_b64encode(urandom(16)).rstrip(bytes("=", "utf8")), "utf8")

    @staticmethod
    def get_random_playback_id():
        """
        Generate random playback id for player
        :return:
        """
        tmp_bytes = b"\x01" + urandom(15)
        return str(b2a_hex(tmp_bytes), "utf8").lower()

    def connect(self, timeout=15):
        """
        Start the player and notify the Spotify.
        :return:
        """
        # Wait until all headers are set.
        self.__dealer.get_headers_event().wait(15)
        self.__spotify_connection_id = self.__dealer.get_connection_id()

    def load(self, spotify_uri: str, timeout=15):
        """
        Load a Spotify URI and start playing.
        :param spotify_uri: Spotify URI
        :return:
        """
        # Load context.
        self.__state.play_origin.CopyFrom(PlayOrigin())
        self.__state.options.CopyFrom(ContextPlayerOptions())
        self.__playback_id = SpotifyPlayer.get_random_playback_id()
        self.__state.context_uri = spotify_uri
        self.__session_id = SpotifyPlayer.get_random_session_id()

        # Get track metadata
        track_metadata = self.__session.get_track_metadata(spotify_uri)

        # Activate player
        timestamp = round(time() * 1000)
        if not self.__is_active:
            self.__put_state.is_active = True
            self.__put_state.started_playing_at = timestamp
            self.__update_state(NEW_DEVICE, -1, self.__state)
            self.__logger.debug("Player is active now.")
            self.__is_active = True

        # Send NEW_SESSION_ID event.
        body = bytes(EventTypes.NEW_SESSION_ID["id"], "utf8")
        body += b"\x09" + bytes(EventTypes.NEW_SESSION_ID["unknown"], "utf8")
        body += b"\x09" + bytes(self.__session_id, "utf8")
        body += b"\x09" + bytes(spotify_uri, "utf8")
        body += b"\x09" + bytes(spotify_uri, "utf8")
        body += b"\x09" + bytes(str(timestamp), "utf8")
        body += b"\x09"
        body += b"\x09" + bytes(str(1), "utf8")
        body += b"\x09"

        self.__mercury_manager.execute_event(timestamp=timestamp, body=body)

        # Start playing
        self.__state.timestamp = timestamp
        self.__state.context_uri = spotify_uri
        self.__state.is_playing = True
        self.__state.is_buffering = True
        self.__state.context_restrictions.CopyFrom(Restrictions(**{
            "disallow_skipping_prev_reasons": "no_prev_track"
        }))
        self.__state.index.CopyFrom(ContextIndex(**{"track": 0}))
        self.__state.track.CopyFrom(ProvidedTrack(**{
            "uri": spotify_uri,
            "provider": "context"
        }))
        self.__state.playback_id = self.__playback_id
        self.__state.is_system_initiated = True
        self.__state.options.CopyFrom(ContextPlayerOptions(**{
            "shuffling_context": False,
            "repeating_context": False,
            "repeating_track": False,
        }))
        self.__state.restrictions.CopyFrom(Restrictions(**{
            "disallow_skipping_prev_reasons": "no_prev_track"
        }))
        self.__state.session_id = self.__session_id
        self.__update_state(PLAYER_STATE_CHANGED, 0, self.__state)

        # Send NEW_PLAYBACK_ID event
        body = bytes(EventTypes.NEW_PLAYBACK_ID["id"], "utf8")
        body += b"\x09" + bytes(EventTypes.NEW_PLAYBACK_ID["unknown"], "utf8")
        body += b"\x09" + bytes(self.__playback_id, "utf8")
        body += b"\x09" + bytes(self.__session_id, "utf8")
        body += b"\x09" + bytes(str(timestamp), "utf8")

        self.__mercury_manager.execute_event(timestamp=timestamp, body=body)

        """
        TODO: Send TRACK_TRANSITION event.
        self.__track_transition_incremental += 1
        body = bytes(EventTypes.TRACK_TRANSITION["id"], "utf8")
        body += b"\x09" + bytes(EventTypes.NEW_PLAYBACK_ID["unknown"], "utf8")
        body += b"\x09" + bytes(str(self.__track_transition_incremental), "utf8")
        body += b"\x09" + bytes(self.__session.get_device_id(), "utf8")
        body += b"\x09" + bytes(self.__playback_id, "utf8")
        body += b"\x09" + bytes("00000000000000000000000000000000", "utf8")
        body += b"\x09" + bytes("unknown", "utf8")
        body += b"\x09" + bytes("clickrow", "utf8")
        body += b"\x09" + bytes("unknown", "utf8")
        body += b"\x09" + bytes("endplay", "utf8")
        body += b"\x09" + bytes("endplay", "utf8")
        
        self.__mercury_manager.execute_event(timestamp=timestamp, body=body)
        """

        # Send the last play put state request
        new_timestamp = round(time() * 1000)
        self.__state.timestamp = new_timestamp
        self.__state.track.CopyFrom(ProvidedTrack(**{
            "uri": spotify_uri,
            "provider": "context",
            "metadata": {"key": "duration", "value": str(track_metadata.duration)}
        }))
        self.__state.position_as_of_timestamp = new_timestamp - timestamp
        self.__state.duration = track_metadata.duration
        self.__state.context_metadata["track_count"] = "1"
        self.__update_state(PLAYER_STATE_CHANGED, new_timestamp - timestamp, self.__state)

    def __update_state(self, reason: PutStateReason, player_time: int, state: PlayerState):
        """
        Update player state.
        """
        if player_time == -1:
            self.__put_state.ClearField("has_been_playing_for_ms")
        else:
            self.__put_state.has_been_playing_for_ms = player_time

        self.__put_state.put_state_reason = reason
        self.__put_state.client_side_timestamp = timegm(gmtime())
        self.__put_state.device.device_info.CopyFrom(self.__device_info)
        self.__put_state.device.player_state.CopyFrom(state)

        self.__session.put_connect_state(self.__spotify_connection_id, self.__put_state)
        tmp = str(self.__put_state).replace("\n", "").replace("  ", " ")
        self.__logger.debug(f"New connection state: {tmp}")

    def disconnect(self):
        """
        Stop playing and
        dispose the player.
        :return:
        """
        self.__terminated = True

        del self.__session
        del self.__dealer
        del self.__player_name
        del self.__state
        del self.__device_info
        del self.__spotify_connection_id
