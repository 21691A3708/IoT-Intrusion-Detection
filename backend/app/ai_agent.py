
import re
from datetime import datetime
from difflib import get_close_matches

from .ai_data_service import IoTDataService


class IoTSecurityAgent:

    def __init__(self):

        # ------------------------------------------
        # DATABASE SERVICE
        # ------------------------------------------

        self.data_service = IoTDataService()

        # ------------------------------------------
        # CYBERSECURITY KNOWLEDGE BASE
        # ------------------------------------------

        self.knowledge_base = {

            "network": {
                "title": "Computer Network",
                "keywords": [
                    "network", "networks", "internet",
                    "communication", "networking",
                    "router", "switch", "protocol"
                ],
                "answer": (
                    "A computer network is a collection of "
                    "interconnected devices that communicate "
                    "and exchange information.\n\n"
                    "Common network components include:\n"
                    "- Routers\n"
                    "- Switches\n"
                    "- Servers\n"
                    "- Network cables\n"
                    "- Wireless access points\n"
                    "- Communication protocols\n\n"
                    "In IoT networks, connected devices exchange "
                    "data using wired or wireless communication."
                )
            },

            "iot": {
                "title": "Internet of Things",
                "keywords": [
                    "iot", "internet of things",
                    "smart device", "sensor", "sensors",
                    "camera", "cameras", "smart camera",
                    "smart cameras", "temperature sensor",
                    "humidity sensor", "motion sensor",
                    "smart meter", "smart meters"
                ],
                "answer": (
                    "The Internet of Things (IoT) refers to "
                    "physical devices connected to a network "
                    "that collect and exchange data.\n\n"
                    "Examples of IoT devices:\n"
                    "- Temperature sensors\n"
                    "- Humidity sensors\n"
                    "- Motion detectors\n"
                    "- Smart cameras\n"
                    "- Smart meters\n\n"
                    "IoT security is important because connected "
                    "devices can be targeted by cyberattacks."
                )
            },

            "udp_flood": {
                "title": "UDP Flood Attack",
                "keywords": [
                    "udp", "udp flood", "udp flooding",
                    "udp attack"
                ],
                "answer": (
                    "A UDP Flood is a Denial-of-Service attack "
                    "where an attacker sends a large volume of "
                    "UDP packets toward a target system.\n\n"
                    "Common indicators:\n"
                    "- Unusually high UDP traffic\n"
                    "- Increased packet rate\n"
                    "- Abnormal resource consumption\n"
                    "- Unexpected network activity\n\n"
                    "Recommended actions:\n"
                    "- Monitor UDP packet rates.\n"
                    "- Apply appropriate traffic filtering.\n"
                    "- Use rate limiting where appropriate.\n"
                    "- Investigate suspicious traffic sources."
                )
            },

            "dos": {
                "title": "Denial-of-Service Attack",
                "keywords": [
                    "dos", "denial of service",
                    "service unavailable", "overload",
                    "service disruption"
                ],
                "answer": (
                    "A Denial-of-Service (DoS) attack attempts "
                    "to make a network, device or service "
                    "unavailable by overwhelming its resources.\n\n"
                    "Common indicators:\n"
                    "- Unusually high network traffic\n"
                    "- Increased resource consumption\n"
                    "- Slow or unavailable services\n\n"
                    "Monitor network traffic and investigate "
                    "abnormal communication patterns."
                )
            },

            "ddos": {
                "title": "Distributed Denial-of-Service Attack",
                "keywords": [
                    "ddos", "distributed denial",
                    "botnet", "multiple attackers",
                    "distributed attack"
                ],
                "answer": (
                    "A Distributed Denial-of-Service (DDoS) "
                    "attack uses multiple sources to overwhelm "
                    "a target with network traffic.\n\n"
                    "Unlike a traditional DoS attack, traffic "
                    "can originate from many compromised devices.\n\n"
                    "Mitigation techniques include traffic "
                    "filtering, rate limiting and distributed "
                    "network protection."
                )
            },

            "intrusion_detection": {
                "title": "Intrusion Detection System",
                "keywords": [
                    "ids", "intrusion detection",
                    "detect attack", "detect intrusion",
                    "security monitoring",
                    "network monitoring"
                ],
                "answer": (
                    "An Intrusion Detection System (IDS) monitors "
                    "network or system activity to identify "
                    "suspicious behavior and potential attacks.\n\n"
                    "Common detection approaches:\n"
                    "- Signature-based detection\n"
                    "- Anomaly-based detection\n"
                    "- Machine learning-based detection\n\n"
                    "Our project uses a Random Forest model "
                    "to classify IoT network traffic as normal "
                    "or attack."
                )
            },

            "machine_learning": {
                "title": "Machine Learning",
                "keywords": [
                    "machine learning", "random forest",
                    "classification", "prediction",
                    "ml model", "model training",
                    "artificial intelligence", "ai"
                ],
                "answer": (
                    "Machine Learning allows computer systems "
                    "to learn patterns from data and make "
                    "predictions.\n\n"
                    "Our IoT intrusion detection project uses "
                    "a Random Forest classifier trained using "
                    "CICIoT2023 network traffic data.\n\n"
                    "The model uses 36 network traffic features "
                    "to classify records as normal traffic "
                    "or attack traffic."
                )
            },

            "risk": {
                "title": "Risk Classification",
                "keywords": [
                    "risk", "risk level", "risk levels",
                    "severity", "critical", "high risk",
                    "medium risk", "low risk", "probability"
                ],
                "answer": (
                    "Our system calculates risk based on "
                    "predicted attack probability.\n\n"
                    "LOW: Probability below 0.25.\n"
                    "MEDIUM: Probability from 0.25 to below 0.50.\n"
                    "HIGH: Probability from 0.50 to below 0.75.\n"
                    "CRITICAL: Probability of 0.75 or higher.\n\n"
                    "Risk classification and the model's "
                    "normal/attack prediction are separate."
                )
            },

            "shap": {
                "title": "SHAP Explainability",
                "keywords": [
                    "shap", "explainability",
                    "feature importance",
                    "feature contribution",
                    "explain prediction",
                    "explainable ai"
                ],
                "answer": (
                    "SHAP stands for SHapley Additive exPlanations.\n\n"
                    "It helps explain how individual input "
                    "features contribute to a machine learning "
                    "prediction.\n\n"
                    "Positive contributions can support the "
                    "explained attack class, while negative "
                    "contributions can support the normal class, "
                    "depending on the explained output.\n\n"
                    "Our project uses SHAP TreeExplainer with "
                    "the Random Forest model."
                )
            },

            "recommendation": {
                "title": "Security Recommendations",
                "keywords": [
                    "recommendation", "recommendations",
                    "prevent", "protection", "secure",
                    "mitigation", "security action",
                    "how to protect", "how to prevent"
                ],
                "answer": (
                    "Recommended IoT security practices:\n\n"
                    "1. Monitor network traffic continuously.\n"
                    "2. Investigate high and critical incidents.\n"
                    "3. Monitor unusual UDP and TCP traffic.\n"
                    "4. Review SHAP explanations.\n"
                    "5. Apply appropriate network filtering.\n"
                    "6. Use rate limiting where appropriate.\n"
                    "7. Maintain incident audit records.\n\n"
                    "These are recommendations. Our current "
                    "project does not automatically block traffic."
                )
            }
        }

        # ------------------------------------------
        # SPELLING CORRECTIONS
        # ------------------------------------------

        self.corrections = {

            "net work": "network",
            "netwrk": "network",
            "netwrok": "network",

            "leval": "level",
            "lavel": "level",
            "levle": "level",

            "securty": "security",
            "attak": "attack",
            "atack": "attack",

            "camras": "cameras",
            "camra": "camera",
            "camer": "camera",

            "sencor": "sensor",
            "sensr": "sensor",

            "recomendation": "recommendation",
            "explainabilty": "explainability",

            "after noon": "afternoon",
            "thnks": "thanks",
            "thnk": "thank"
        }

    # ------------------------------------------
    # TEXT NORMALIZATION
    # ------------------------------------------

    def normalize_question(self, question):

        question = question.lower().strip()

        question = re.sub(
            r"[^a-z0-9\s]",
            " ",
            question
        )

        question = re.sub(
            r"\s+",
            " ",
            question
        )

        for wrong, correct in self.corrections.items():

            question = re.sub(
                r"\b" + re.escape(wrong) + r"\b",
                correct,
                question
            )

        return question

    # ------------------------------------------
    # FUZZY WORD MATCHING
    # ------------------------------------------

    def correct_spelling(self, question):

        words = question.split()

        known_words = set()

        for information in self.knowledge_base.values():

            for keyword in information["keywords"]:

                known_words.update(keyword.split())

        corrected_words = []

        for word in words:

            if len(word) < 4 or word in known_words:
                corrected_words.append(word)
                continue

            matches = get_close_matches(
                word,
                known_words,
                n=1,
                cutoff=0.82
            )

            if matches:
                corrected_words.append(matches[0])
            else:
                corrected_words.append(word)

        return " ".join(corrected_words)

    # ------------------------------------------
    # INTENT DETECTION
    # ------------------------------------------

    def detect_intent(self, question):

        normalized = self.normalize_question(question)
        normalized = self.correct_spelling(normalized)

        # Greeting
        if re.search(
            r"\b(hello|hi|hey|good morning|good afternoon|good evening)\b",
            normalized
        ):
            return "greeting"

        # Goodbye
        if re.search(
            r"\b(bye|goodbye|see you|farewell)\b",
            normalized
        ):
            return "goodbye"

        # Thank you
        if re.search(
            r"\b(thank|thanks|thank you)\b",
            normalized
        ):
            return "thanks"

        # Date
        if re.search(
            r"\b(date|today|present date|current date)\b",
            normalized
        ):
            return "date"

        # Time
        if re.search(
            r"\b(time|current time)\b",
            normalized
        ):
            return "time"

        # Personal information
        if re.search(
            r"\b(what is my name|who am i|tell me my name)\b",
            normalized
        ):
            return "personal_information"

        # Agent capabilities
        if re.search(
            r"\b(what can you do|your capabilities|help me|"
            r"what do you know|your features)\b",
            normalized
        ):
            return "capabilities"

        # --------------------------------------
        # LIVE DATABASE INTENTS
        # --------------------------------------

        # Overall security overview
        if re.search(
            r"\b(overview|dashboard summary|security summary|"
            r"overall status|system status)\b",
            normalized
        ):
            return "overview"

        # Critical incidents
        if re.search(
            r"\b(critical incidents|high severity incidents|"
            r"critical alerts)\b",
            normalized
        ):
            return "critical_incidents"

        # Open incidents
        if re.search(
            r"\b(open incidents|unresolved incidents|"
            r"pending incidents|incidents open|incidents are open|"
            r"incidents still open)\b",
            normalized
        ):
            return "open_incidents"

        # Devices
        if re.search(
            r"\b(devices|registered devices|iot devices|"
            r"connected devices|online devices|show me my devices)\b",
            normalized
        ):
            return "devices"

        # Attacks
        if re.search(
            r"\b(attacks|attack count|detected attacks|"
            r"how many attacks|number of attacks|"
            r"attack predictions)\b",
            normalized
        ):
            return "attacks"

        # Predictions
        if re.search(
            r"\b(predictions|prediction count|"
            r"total predictions|normal predictions)\b",
            normalized
        ):
            return "predictions"

        # Incidents
        if re.search(
            r"\b(incidents|incident count|security alerts|"
            r"how many alerts)\b",
            normalized
        ):
            return "incidents"

        # --------------------------------------
        # KNOWLEDGE BASE MATCHING
        # --------------------------------------

        scores = {}

        for topic, information in self.knowledge_base.items():

            score = 0

            for keyword in information["keywords"]:

                keyword = keyword.lower()

                if keyword in normalized:

                    score += 3 if " " in keyword else 1

            scores[topic] = score

        if not scores:
            return "unknown"

        best_topic = max(
            scores,
            key=scores.get
        )

        if scores[best_topic] > 0:
            return best_topic

        return "unknown"

    # ------------------------------------------
    # LIVE DATABASE ANSWER GENERATION
    # ------------------------------------------

    def answer_live_data(self, intent):

        try:

            # Overall security overview
            if intent == "overview":

                data = self.data_service.get_security_overview()

                p = data["predictions"]
                i = data["incidents"]
                d = data["devices"]

                return (
                    "LIVE IoT SECURITY OVERVIEW\n\n"

                    "PREDICTIONS\n"
                    f"Total: {p['total_predictions']}\n"
                    f"Normal: {p['normal_predictions']}\n"
                    f"Attacks: {p['attack_predictions']}\n\n"

                    "RISK DISTRIBUTION\n"
                    f"Low: {p['low_risk']}\n"
                    f"Medium: {p['medium_risk']}\n"
                    f"High: {p['high_risk']}\n"
                    f"Critical: {p['critical_risk']}\n\n"

                    "INCIDENTS\n"
                    f"Total: {i['total_incidents']}\n"
                    f"Open: {i['open_incidents']}\n"
                    f"Acknowledged: {i['acknowledged_incidents']}\n"
                    f"Investigating: {i['investigating_incidents']}\n"
                    f"Active: {i['active_incidents']}\n\n"

                    "DEVICES\n"
                    f"Total: {d['total_devices']}\n"
                    f"Online: {d['online_devices']}\n"
                    f"Offline: {d['offline_devices']}"
                )

            # Attack statistics
            elif intent == "attacks":

                data = self.data_service.get_security_overview()
                p = data["predictions"]

                return (
                    "LIVE ATTACK STATISTICS\n\n"
                    f"Total predictions: {p['total_predictions']}\n"
                    f"Detected attacks: {p['attack_predictions']}\n"
                    f"Normal predictions: {p['normal_predictions']}\n"
                )

            # Prediction statistics
            elif intent == "predictions":

                data = self.data_service.get_security_overview()
                p = data["predictions"]

                return (
                    "LIVE PREDICTION STATISTICS\n\n"
                    f"Total predictions: {p['total_predictions']}\n"
                    f"Normal predictions: {p['normal_predictions']}\n"
                    f"Attack predictions: {p['attack_predictions']}\n"
                )

            # Incident statistics
            elif intent == "incidents":

                data = self.data_service.get_security_overview()
                i = data["incidents"]

                return (
                    "LIVE INCIDENT STATISTICS\n\n"
                    f"Total incidents: {i['total_incidents']}\n"
                    f"Open incidents: {i['open_incidents']}\n"
                    f"Acknowledged: {i['acknowledged_incidents']}\n"
                    f"Investigating: {i['investigating_incidents']}\n"
                    f"Active incidents: {i['active_incidents']}\n"
                )

            # Open incidents
            elif intent == "open_incidents":

                incidents = self.data_service.get_incidents_by_status(
                    "open",
                    10
                )

                if not incidents:
                    return "There are currently no open incidents."

                lines = ["LATEST OPEN INCIDENTS\n"]

                for index, incident in enumerate(incidents, 1):

                    lines.append(
                        f"{index}. {incident['title']}\n"
                        f"Severity: {incident['severity']}\n"
                        f"Device: {incident.get('device_name') or 'Not linked'}\n"
                        f"Created: {incident['created_at']}\n"
                    )

                return "\n".join(lines)

            # Critical incidents
            elif intent == "critical_incidents":

                incidents = self.data_service.get_recent_incidents(50)

                critical = [
                    incident for incident in incidents
                    if str(incident["severity"]).lower() == "critical"
                    and incident["status"] not in [
                        "resolved",
                        "false_positive"
                    ]
                ]

                if not critical:
                    return "No critical active incidents were found in the latest 50 incidents."

                lines = [
                    f"CRITICAL ACTIVE INCIDENTS: {len(critical)}\n"
                ]

                for index, incident in enumerate(critical, 1):

                    lines.append(
                        f"{index}. {incident['title']}\n"
                        f"Severity: {incident['severity']}\n"
                        f"Status: {incident['status']}\n"
                        f"Device: {incident.get('device_name') or 'Not linked'}\n"
                        f"Created: {incident['created_at']}\n"
                    )

                return "\n".join(lines)

            # Registered devices
            elif intent == "devices":

                devices = self.data_service.get_registered_devices(50)

                if not devices:
                    return "No registered IoT devices were found."

                lines = [
                    f"REGISTERED IoT DEVICES: {len(devices)}\n"
                ]

                for index, device in enumerate(devices, 1):

                    lines.append(
                        f"{index}. {device['device_name']}\n"
                        f"Type: {device['device_type']}\n"
                        f"Identifier: {device['device_identifier']}\n"
                        f"Location: {device['location']}\n"
                        f"Status: {device['status']}\n"
                    )

                return "\n".join(lines)

        except Exception as error:

            print("AI Agent database error:", str(error))

            return (
                "I could not retrieve live information from "
                "the security database. Please check the "
                "backend database connection."
            )

        return "I could not process this database request."

    # ------------------------------------------
    # MAIN ANSWER GENERATION
    # ------------------------------------------

    def answer_question(self, question):

        if not isinstance(question, str) or not question.strip():

            return {
                "success": False,
                "intent": "invalid",
                "answer": "Please enter a valid question."
            }

        normalized = self.normalize_question(question)

        intent = self.detect_intent(normalized)

        # --------------------------------------
        # LIVE DATABASE QUESTIONS
        # --------------------------------------

        live_intents = {
            "overview",
            "attacks",
            "predictions",
            "incidents",
            "open_incidents",
            "critical_incidents",
            "devices"
        }

        if intent in live_intents:

            return {
                "success": True,
                "intent": intent,
                "answer": self.answer_live_data(intent)
            }

        # --------------------------------------
        # GENERAL CONVERSATION
        # --------------------------------------

        if intent == "greeting":

            answer = (
                "Hello! I am your IoT Security Assistant.\n\n"
                "I can help you understand networks, IoT devices, "
                "cybersecurity attacks, intrusion detection, "
                "machine learning, risk levels and SHAP.\n\n"
                "I can also retrieve live predictions, incidents "
                "and device information from your security database."
            )

        elif intent == "goodbye":

            answer = "Goodbye! Stay safe and secure."

        elif intent == "thanks":

            answer = "You're welcome! I'm happy to help."

        elif intent == "date":

            now = datetime.now()

            answer = (
                "Today's date is "
                + now.strftime("%d %B %Y")
                + "."
            )

        elif intent == "time":

            now = datetime.now()

            answer = (
                "Current local time is "
                + now.strftime("%I:%M:%S %p")
                + "."
            )

        elif intent == "personal_information":

            answer = (
                "I don't have your name configured in this "
                "assistant yet."
            )

        elif intent == "capabilities":

            answer = (
                "I am your IoT Security Assistant.\n\n"
                "I can help you with:\n"
                "1. Computer networks.\n"
                "2. Internet of Things.\n"
                "3. UDP Flood, DoS and DDoS attacks.\n"
                "4. Intrusion Detection Systems.\n"
                "5. Machine Learning and Random Forest.\n"
                "6. Risk classification.\n"
                "7. SHAP explainability.\n"
                "8. Security recommendations.\n"
                "9. Live attack statistics.\n"
                "10. Current incidents.\n"
                "11. Registered IoT devices.\n"
                "12. Overall security overview."
            )

        elif intent in self.knowledge_base:

            information = self.knowledge_base[intent]

            answer = (
                information["title"]
                + "\n\n"
                + information["answer"]
            )

        else:

            answer = (
                "I could not find a suitable answer in my "
                "current knowledge base.\n\n"
                "Try asking about:\n"
                "- Computer networks\n"
                "- IoT devices and sensors\n"
                "- UDP Flood, DoS and DDoS attacks\n"
                "- Intrusion Detection Systems\n"
                "- Machine Learning and Random Forest\n"
                "- Risk classification\n"
                "- SHAP explainability\n"
                "- Security recommendations\n"
                "- Live attack statistics\n"
                "- Current incidents and devices\n\n"
                "You can also ask: What can you do?"
            )

        return {
            "success": True,
            "intent": intent,
            "answer": answer
        }


# ----------------------------------------------
# INDEPENDENT TERMINAL TESTING
# ----------------------------------------------

if __name__ == "__main__":

    agent = IoTSecurityAgent()

    print("=" * 60)
    print("           CUSTOM IoT SECURITY AI AGENT")
    print("=" * 60)

    print("Type 'exit' or 'quit' to close the assistant.")

    while True:

        question = input("\nYou: ").strip()

        if question.lower() in ["exit", "quit"]:
            print("Agent: Goodbye!")
            break

        response = agent.answer_question(question)

        print("\nDetected intent:", response["intent"])

        print("\nAgent:")
        print(response["answer"])
