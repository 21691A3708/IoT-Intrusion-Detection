
# from .response_audit_service import (
#     utc_timestamp,
# )


# SUPPORTED_SIMULATED_ACTIONS = {
#     "simulate_device_isolation",
#     "simulate_rate_limiting",
#     "simulate_traffic_filtering",
# }


# def execute_simulated_response(
#     action: str,
#     device_id: str,
# ) -> dict:

#     if action not in SUPPORTED_SIMULATED_ACTIONS:

#         raise ValueError(
#             "Unsupported simulated response action."
#         )

#     if (
#         not isinstance(device_id, str)
#         or not device_id.strip()
#     ):

#         raise ValueError(
#             "A valid device identifier is required."
#         )

#     simulated_states = {

#         "simulate_device_isolation":
#             "simulated_isolated",

#         "simulate_rate_limiting":
#             "simulated_rate_limited",

#         "simulate_traffic_filtering":
#             "simulated_filtered",
#     }

#     return {

#         "action": action,

#         "device_id": device_id,

#         "execution_status": "success",

#         "previous_device_state":
#             "simulated_unmodified",

#         "new_device_state":
#             simulated_states[action],

#         "simulation_executed": True,

#         "response_executed": False,

#         "real_network_action_executed": False,

#         "simulation_only": True,

#         "executed_at": utc_timestamp(),

#         "message": (
#             "Response simulation completed. "
#             "No network infrastructure was modified."
#         ),
#     }


# def rollback_simulated_response(
#     execution_result: dict,
# ) -> dict:

#     if (
#         execution_result.get(
#             "simulation_executed"
#         ) is not True
#     ):

#         raise ValueError(
#             "No completed simulation to roll back."
#         )

#     if (
#         execution_result.get(
#             "real_network_action_executed"
#         ) is not False
#     ):

#         raise ValueError(
#             "Only simulated responses are supported."
#         )

#     return {

#         "device_id":
#             execution_result["device_id"],

#         "original_action":
#             execution_result["action"],

#         "previous_device_state":
#             execution_result["new_device_state"],

#         "restored_device_state":
#             execution_result["previous_device_state"],

#         "rollback_status": "success",

#         "simulation_rollback_executed": True,

#         "real_network_action_executed": False,

#         "simulation_only": True,

#         "rolled_back_at": utc_timestamp(),

#         "message": (
#             "Simulated response reversed. "
#             "No actual device state was changed."
#         ),
#     }

from datetime import datetime, timezone
from uuid import uuid4
from copy import deepcopy


def utc_timestamp() -> str:

    return datetime.now(
        timezone.utc
    ).isoformat()


def create_audit_event(
    response_id: str,
    action: str,
    actor: str,
    previous_status: str | None,
    new_status: str,
    details: dict | None = None,
) -> dict:

    return {
        "audit_id": str(uuid4()),
        "response_id": response_id,
        "action": action,
        "actor": actor,
        "actor_authenticated": False,
        "previous_status": previous_status,
        "new_status": new_status,
        "details": deepcopy(details or {}),
        "timestamp": utc_timestamp(),
        "simulation_only": True,
    }
