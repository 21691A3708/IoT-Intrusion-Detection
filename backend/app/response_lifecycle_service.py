
from copy import deepcopy
from threading import RLock
from uuid import uuid4

from .response_policy_service import (
    evaluate_response_policy,
)

from .context_risk_service import (
    assess_traffic_risk,
)

from .response_audit_service import (
    create_audit_event,
    utc_timestamp,
)

from .response_execution_service import (
    execute_simulated_response,
    rollback_simulated_response,
)


class ResponseStateError(ValueError):
    pass


class ResponseLifecycleService:

    def __init__(self, max_records: int = 1000):

        self._records = {}
        self._lock = RLock()
        self._max_records = max_records

    # --------------------------------------------------
    # VALIDATE ACTOR AND REASON
    # --------------------------------------------------

    @staticmethod
    def _validate_text(value, name):

        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > 500
        ):
            raise ValueError(f"Invalid {name}.")

        return value.strip()

    # --------------------------------------------------
    # GET INTERNAL RECORD
    # --------------------------------------------------

    def _find(self, response_id):

        if response_id not in self._records:
            raise KeyError(
                "Response record not found."
            )

        return self._records[response_id]

    # --------------------------------------------------
    # RECORD STATE TRANSITION
    # --------------------------------------------------

    def _transition(
        self,
        record,
        new_status,
        action,
        actor,
        details=None,
    ):

        old_status = record["status"]

        event = create_audit_event(
            response_id=record["response_id"],
            action=action,
            actor=actor,
            previous_status=old_status,
            new_status=new_status,
            details=details,
        )

        record["status"] = new_status
        record["updated_at"] = utc_timestamp()
        record["audit_logs"].append(event)

    # --------------------------------------------------
    # CREATE RESPONSE FROM TRAFFIC
    # --------------------------------------------------

    def create_from_traffic(
        self,
        features: dict,
        device_id: str | None = None,
    ) -> dict:

        assessment = assess_traffic_risk(
            features=features,
            device_id=device_id,
        )

        return self._create_from_assessment(
            prediction=assessment["prediction"],
            risk=assessment["risk_assessment"],
            synthetic_fixture=False,
        )

    # --------------------------------------------------
    # INTERNAL RESPONSE CREATION
    # Synthetic fixtures are for internal testing only.
    # Do not expose this method through an API.
    # --------------------------------------------------

    def _create_from_assessment(
        self,
        prediction: dict,
        risk: dict,
        synthetic_fixture: bool = False,
    ) -> dict:

        prediction = deepcopy(prediction)
        risk = deepcopy(risk)

        plan = evaluate_response_policy(
            prediction,
            risk,
        )

        if (
            plan["containment_eligible"]
            and not synthetic_fixture
        ):
            raise ResponseStateError(
                "Verified identity infrastructure "
                "is not available."
            )

        with self._lock:

            if len(self._records) >= self._max_records:
                raise ResponseStateError(
                    "Response storage capacity reached."
                )

            response_id = str(uuid4())
            timestamp = utc_timestamp()

            record = {
                "response_id": response_id,
                "status": plan["response_status"],

                "prediction": prediction,
                "risk_assessment": risk,
                "response_plan": plan,

                "synthetic_fixture":
                    synthetic_fixture,

                "approval": None,
                "approval_granted": False,
                "simulation_authorized": False,
                "containment_authorized": False,

                "execution": None,
                "rollback": None,

                "simulation_executed": False,
                "response_executed": False,
                "real_network_action_executed": False,

                "incident_created": False,
                "simulation_only": True,
                "storage_mode": "in_memory",

                "created_at": timestamp,
                "updated_at": timestamp,

                "audit_logs": [],
            }

            record["audit_logs"].append(
                create_audit_event(
                    response_id=response_id,
                    action="response_created",
                    actor="system",
                    previous_status=None,
                    new_status=record["status"],
                    details={
                        "containment_eligible":
                            plan["containment_eligible"],

                        "restriction_reasons":
                            plan["restriction_reasons"],

                        "synthetic_fixture":
                            synthetic_fixture,
                    },
                )
            )

            self._records[response_id] = record

            return deepcopy(record)

    # --------------------------------------------------
    # RETRIEVE RESPONSE
    # --------------------------------------------------

    def get_response(
        self,
        response_id: str,
    ) -> dict:

        with self._lock:

            return deepcopy(
                self._find(response_id)
            )

    # --------------------------------------------------
    # RECHECK SAFETY POLICY
    # --------------------------------------------------

    def _check_eligibility(self, record):

        if not record["synthetic_fixture"]:
            raise ResponseStateError(
                "Approval and execution are limited "
                "to internal synthetic fixtures."
            )

        current_plan = evaluate_response_policy(
            record["prediction"],
            record["risk_assessment"],
        )

        if not current_plan["containment_eligible"]:
            raise ResponseStateError(
                "Response no longer satisfies "
                "the safety policy."
            )

        if (
            current_plan["eligible_containment_action"]
            != record["response_plan"][
                "eligible_containment_action"
            ]
        ):
            raise ResponseStateError(
                "Response action has changed."
            )

        return current_plan

    # --------------------------------------------------
    # APPROVE OR REJECT
    # --------------------------------------------------

    def decide(
        self,
        response_id: str,
        decision: str,
        actor: str,
        reason: str,
    ) -> dict:

        actor = self._validate_text(
            actor, "actor"
        )

        reason = self._validate_text(
            reason, "reason"
        )

        if decision not in ("approve", "reject"):
            raise ValueError(
                "Decision must be approve or reject."
            )

        with self._lock:

            record = self._find(response_id)

            if record["status"] != "pending_approval":
                raise ResponseStateError(
                    "Response is not pending approval."
                )

            if decision == "approve":

                self._check_eligibility(record)
                new_status = "approved"

            else:

                new_status = "rejected"

            record["approval"] = {
                "decision": decision,
                "actor": actor,
                "actor_authenticated": False,
                "reason": reason,
                "decided_at": utc_timestamp(),
            }

            record["approval_granted"] = (
                decision == "approve"
            )

            record["simulation_authorized"] = (
                decision == "approve"
            )

            self._transition(
                record,
                new_status,
                f"response_{new_status}",
                actor,
                {"reason": reason},
            )

            return deepcopy(record)

    # --------------------------------------------------
    # EXECUTE APPROVED SIMULATION
    # --------------------------------------------------

    def execute(
        self,
        response_id: str,
        actor: str,
    ) -> dict:

        actor = self._validate_text(
            actor, "actor"
        )

        with self._lock:

            record = self._find(response_id)

            if record["status"] != "approved":
                raise ResponseStateError(
                    "Response must be approved "
                    "before execution."
                )

            if (
                not record["approval_granted"]
                or not record["simulation_authorized"]
            ):
                raise ResponseStateError(
                    "Simulation is not authorized."
                )

            plan = self._check_eligibility(record)

            execution = execute_simulated_response(
                action=plan[
                    "eligible_containment_action"
                ],
                device_id=plan["device_id"],
            )

            record["execution"] = execution
            record["simulation_executed"] = True
            record["simulation_authorized"] = False

            self._transition(
                record,
                "simulated",
                "simulation_executed",
                actor,
                execution,
            )

            return deepcopy(record)

    # --------------------------------------------------
    # ROLLBACK SIMULATED RESPONSE
    # --------------------------------------------------

    def rollback(
        self,
        response_id: str,
        actor: str,
        reason: str,
    ) -> dict:

        actor = self._validate_text(
            actor, "actor"
        )

        reason = self._validate_text(
            reason, "reason"
        )

        with self._lock:

            record = self._find(response_id)

            if record["status"] != "simulated":
                raise ResponseStateError(
                    "Only completed simulations "
                    "can be rolled back."
                )

            result = rollback_simulated_response(
                record["execution"]
            )

            record["rollback"] = result

            self._transition(
                record,
                "rolled_back",
                "simulation_rolled_back",
                actor,
                {
                    "reason": reason,
                    **result,
                },
            )

            return deepcopy(record)
