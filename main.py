#!/usr/bin/env python3
from librespot.player import SpotifyPlayer
from librespot.proxy import SpotifyProxy
from librespot.session import SpotifySession
from librespot.scopes import WebTokenScopes
from time import sleep
import logging

# Enable logger
logger = logging.getLogger("spotify-session")
logger.setLevel(logging.DEBUG)

# p = SpotifyProxy("SOCKS5", "4g.hydraproxy.com", 11598)
# p.check(timeout=15)

# Start new Spotify session
s = SpotifySession()

# Login with Spotify
s.connect()
s.login("88465525b02a8d65d3460de473498445@gmail.com", "WrJGtxRs6oJApyE")

player = SpotifyPlayer(session=s)
player.connect()
player.load("spotify:track:2akY1ilCFDpmpesr7UuCCi")

