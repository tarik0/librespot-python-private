class EventTypes:
    """
    Event types to send through Mercury.
    """

    LANGUAGE = {"id": "812", "unknown": "1"}
    FETCHED_FILE_ID = {"id": "274", "unknown": "3"}
    NEW_SESSION_ID = {"id": "557", "unknown": "3"}
    NEW_PLAYBACK_ID = {"id": "558", "unknown": "1"}
    TRACK_PLAYED = {"id": "372", "unknown": "1"}
    TRACK_TRANSITION = {"id": "12", "unknown": "37"}
    CDN_REQUEST = {"id": "10", "unknown": "20"}
