from copy import deepcopy


# --------------------------------------------------
# DEMONSTRATION DEVICE INVENTORY
# --------------------------------------------------

DEVICE_PROFILES = {

    "sensor-001": {

        "device_id": "sensor-001",

        "device_name": "Temperature Sensor",

        "device_type": "sensor",

        "criticality": 0.25,

        "exposure": 0.30,

        "business_function":
            "Environmental monitoring",

        "containment_allowed": True,
    },

    "camera-001": {

        "device_id": "camera-001",

        "device_name": "Security Camera",

        "device_type": "camera",

        "criticality": 0.70,

        "exposure": 0.60,

        "business_function":
            "Physical security monitoring",

        "containment_allowed": True,
    },

    "gateway-001": {

        "device_id": "gateway-001",

        "device_name": "IoT Gateway",

        "device_type": "gateway",

        "criticality": 0.90,

        "exposure": 0.90,

        "business_function":
            "IoT network communication",

        "containment_allowed": False,
    },

    "medical-001": {

        "device_id": "medical-001",

        "device_name": "Medical IoT Device",

        "device_type": "medical",

        "criticality": 1.00,

        "exposure": 0.40,

        "business_function":
            "Patient monitoring",

        "containment_allowed": False,
    },

    "industrial-001": {

        "device_id": "industrial-001",

        "device_name": "Industrial Controller",

        "device_type": "industrial",

        "criticality": 0.95,

        "exposure": 0.50,

        "business_function":
            "Industrial process control",

        "containment_allowed": False,
    },
}


# --------------------------------------------------
# UNKNOWN DEVICE FALLBACK
# --------------------------------------------------

UNKNOWN_DEVICE_PROFILE = {

    "device_id": None,

    "device_name": "Unknown Device",

    "device_type": "unknown",

    "criticality": 0.50,

    "exposure": 0.50,

    "business_function": "Unknown",

    "containment_allowed": False,
}


# --------------------------------------------------
# RETRIEVE DEVICE CONTEXT
# --------------------------------------------------

def get_device_context(
    device_id: str | None = None,
) -> dict:

    if device_id is not None:

        if not isinstance(device_id, str):

            raise ValueError(
                "device_id must be a string."
            )

        if not device_id.strip():

            raise ValueError(
                "device_id cannot be empty."
            )

    if device_id in DEVICE_PROFILES:

        context = deepcopy(
            DEVICE_PROFILES[device_id]
        )

        context.update({

            "context_known": True,

            "context_source":
                "demonstration_inventory",

            "identity_verified": False,

            "simulation_only": True,
        })

        return context

    context = deepcopy(
        UNKNOWN_DEVICE_PROFILE
    )

    context.update({

        "requested_device_id": device_id,

        "context_known": False,

        "context_source":
            "unknown_device_fallback",

        "identity_verified": False,

        "simulation_only": True,
    })

    return context


# --------------------------------------------------
# LIST DEMONSTRATION DEVICES
# --------------------------------------------------

def list_device_profiles() -> list[dict]:

    return [

        get_device_context(device_id)

        for device_id in DEVICE_PROFILES
    ]