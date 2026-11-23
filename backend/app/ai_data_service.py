
from sqlalchemy import text
from .database import SessionLocal


class IoTDataService:
    """
    Read-only data service for the custom IoT Security Agent.

    Uses the existing SQLAlchemy database connection.
    Only predefined SELECT queries are permitted.
    """

    # ------------------------------------------
    # DATABASE CONNECTION
    # ------------------------------------------

    def _execute_read_query(self, query, params=None):

        with SessionLocal() as session:

            # Make this database transaction read-only.
            session.execute(
                text("SET TRANSACTION READ ONLY")
            )

            result = session.execute(
                text(query),
                params or {}
            )

            return [dict(row) for row in result.mappings().all()]

    # ------------------------------------------
    # SECURITY OVERVIEW
    # ------------------------------------------

    def get_security_overview(self):

        prediction_query = """
            SELECT
                COUNT(*) AS total_predictions,

                COUNT(*) FILTER (
                    WHERE predicted_label = 0
                ) AS normal_predictions,

                COUNT(*) FILTER (
                    WHERE predicted_label = 1
                ) AS attack_predictions,

                COUNT(*) FILTER (
                    WHERE risk_level = 'low'
                ) AS low_risk,

                COUNT(*) FILTER (
                    WHERE risk_level = 'medium'
                ) AS medium_risk,

                COUNT(*) FILTER (
                    WHERE risk_level = 'high'
                ) AS high_risk,

                COUNT(*) FILTER (
                    WHERE risk_level = 'critical'
                ) AS critical_risk

            FROM predictions
        """

        incident_query = """
            SELECT
                COUNT(*) AS total_incidents,

                COUNT(*) FILTER (
                    WHERE status = 'open'
                ) AS open_incidents,

                COUNT(*) FILTER (
                    WHERE status = 'acknowledged'
                ) AS acknowledged_incidents,

                COUNT(*) FILTER (
                    WHERE status = 'investigating'
                ) AS investigating_incidents,

                COUNT(*) FILTER (
                    WHERE status NOT IN (
                        'resolved',
                        'false_positive'
                    )
                ) AS active_incidents

            FROM incidents
        """

        device_query = """
            SELECT
                COUNT(*) AS total_devices,

                COUNT(*) FILTER (
                    WHERE LOWER(status) IN ('active', 'online')
                ) AS online_devices,

                COUNT(*) FILTER (
                    WHERE LOWER(status) IN ('inactive', 'offline')
                ) AS offline_devices

            FROM devices
        """

        with SessionLocal() as session:

            session.execute(
                text("SET TRANSACTION READ ONLY")
            )

            predictions = dict(
                session.execute(
                    text(prediction_query)
                ).mappings().one()
            )

            incidents = dict(
                session.execute(
                    text(incident_query)
                ).mappings().one()
            )

            devices = dict(
                session.execute(
                    text(device_query)
                ).mappings().one()
            )

        return {
            "predictions": predictions,
            "incidents": incidents,
            "devices": devices
        }

    # ------------------------------------------
    # RECENT INCIDENTS
    # ------------------------------------------

    def get_recent_incidents(self, limit=10):

        limit = max(1, min(int(limit), 50))

        query = """
            SELECT
                i.id,
                i.prediction_id,
                i.device_id,
                i.title,
                i.description,
                i.severity,
                i.status,
                i.created_at,
                i.resolved_at,
                d.device_name

            FROM incidents i

            LEFT JOIN devices d
                ON d.id = i.device_id

            ORDER BY i.created_at DESC

            LIMIT :limit
        """

        rows = self._execute_read_query(
            query,
            {"limit": limit}
        )

        return self._serialize_rows(rows)

    # ------------------------------------------
    # INCIDENTS FILTERED BY STATUS
    # ------------------------------------------

    def get_incidents_by_status(self, status, limit=20):

        allowed_statuses = {
            "open",
            "acknowledged",
            "investigating",
            "resolved",
            "false_positive"
        }

        status = status.lower().strip()

        if status not in allowed_statuses:
            raise ValueError("Unsupported incident status.")

        limit = max(1, min(int(limit), 50))

        query = """
            SELECT
                i.id,
                i.title,
                i.description,
                i.severity,
                i.status,
                i.created_at,
                d.device_name

            FROM incidents i

            LEFT JOIN devices d
                ON d.id = i.device_id

            WHERE i.status = :status

            ORDER BY i.created_at DESC

            LIMIT :limit
        """

        rows = self._execute_read_query(
            query,
            {
                "status": status,
                "limit": limit
            }
        )

        return self._serialize_rows(rows)

    # ------------------------------------------
    # REGISTERED IOT DEVICES
    # ------------------------------------------

    def get_registered_devices(self, limit=50):

        limit = max(1, min(int(limit), 100))

        query = """
            SELECT
                id,
                device_name,
                device_identifier,
                device_type,
                location,
                status,
                last_seen_at,
                created_at

            FROM devices

            ORDER BY created_at DESC

            LIMIT :limit
        """

        rows = self._execute_read_query(
            query,
            {"limit": limit}
        )

        return self._serialize_rows(rows)

    # ------------------------------------------
    # RECENT PREDICTIONS
    # ------------------------------------------

    def get_recent_predictions(self, limit=20):

        limit = max(1, min(int(limit), 100))

        query = """
            SELECT
                p.id,
                p.device_id,
                p.predicted_label,
                p.attack_probability,
                p.risk_level,
                p.source,
                p.model_version,
                p.created_at,
                d.device_name

            FROM predictions p

            LEFT JOIN devices d
                ON d.id = p.device_id

            ORDER BY p.created_at DESC

            LIMIT :limit
        """

        rows = self._execute_read_query(
            query,
            {"limit": limit}
        )

        return self._serialize_rows(rows)

    # ------------------------------------------
    # DEVICE-WISE ATTACK STATISTICS
    # ------------------------------------------

    def get_device_attack_counts(self):
        """
        Count attack predictions (predicted_label = 1) per registered device.
        Predictions without a device_id are counted separately and are never
        attributed to a registered device.
        """

        device_query = """
            SELECT
                d.id,
                d.device_name,
                d.device_identifier,
                d.device_type,
                COUNT(p.id) AS attack_count
            FROM devices d
            LEFT JOIN predictions p
                ON p.device_id = d.id
                AND p.predicted_label = 1
            GROUP BY
                d.id,
                d.device_name,
                d.device_identifier,
                d.device_type
            ORDER BY attack_count DESC, d.device_name ASC
        """

        unassigned_query = """
            SELECT COUNT(*) AS unassigned_attack_count
            FROM predictions
            WHERE predicted_label = 1
              AND device_id IS NULL
        """

        devices = self._execute_read_query(device_query)
        unassigned = self._execute_read_query(unassigned_query)

        for device in devices:
            device["attack_count"] = int(device["attack_count"] or 0)

        unassigned_count = (
            int(unassigned[0]["unassigned_attack_count"])
            if unassigned else 0
        )

        return {
            "devices": self._serialize_rows(devices),
            "unassigned_attack_count": unassigned_count,
        }

    # ------------------------------------------
    # SERIALIZE DATABASE RESULTS
    # ------------------------------------------

    @staticmethod
    def _serialize_rows(rows):

        serialized = []

        for row in rows:

            item = {}

            for key, value in row.items():

                if value is None:
                    item[key] = None

                elif hasattr(value, "isoformat"):
                    item[key] = value.isoformat()

                else:
                    item[key] = str(value) if key == "id" or key.endswith("_id") else value

            serialized.append(item)

        return serialized

    # ------------------------------------------
    # CONTEXT RETRIEVAL
    # ------------------------------------------

    def get_context_for_intent(self, intent):

        if intent == "incidents":
            return {
                "recent_incidents": self.get_recent_incidents(10)
            }

        elif intent == "open_incidents":
            return {
                "open_incidents": self.get_incidents_by_status(
                    "open",
                    20
                )
            }

        elif intent == "devices":
            return {
                "registered_devices": self.get_registered_devices(50)
            }

        elif intent == "predictions":
            return {
                "recent_predictions": self.get_recent_predictions(20)
            }

        elif intent == "attacks":
            overview = self.get_security_overview()

            return {
                "total_predictions": overview["predictions"]["total_predictions"],
                "attack_predictions": overview["predictions"]["attack_predictions"],
                "normal_predictions": overview["predictions"]["normal_predictions"]
            }

        else:
            return self.get_security_overview()


# ----------------------------------------------
# INDEPENDENT DATABASE TEST
# ----------------------------------------------

if __name__ == "__main__":

    import json

    service = IoTDataService()

    print("=" * 55)
    print("       IoT SECURITY DATABASE TEST")
    print("=" * 55)

    try:

        overview = service.get_security_overview()

        print("\nSECURITY OVERVIEW:")
        print(
            json.dumps(
                overview,
                indent=4,
                default=str
            )
        )

        print("\nRECENT INCIDENTS:")

        incidents = service.get_recent_incidents(5)

        print(
            json.dumps(
                incidents,
                indent=4,
                default=str
            )
        )

        print("\nREGISTERED DEVICES:")

        devices = service.get_registered_devices(5)

        print(
            json.dumps(
                devices,
                indent=4,
                default=str
            )
        )

        print("\nDATABASE INTEGRATION TEST COMPLETED.")

    except Exception as error:

        print("\nDATABASE INTEGRATION FAILED:")
        print(str(error))
