LABEL_MAPPING = {
    "Benign": 0,
    "DDoS": 1,
    "DoS": 2,
    "Reconnaissance": 3,
    "BruteForce": 4,
    "Spoofing": 5,
    "Mirai": 6,
    "WebBased": 7,
}

ID_TO_LABEL = {
    value: key
    for key, value in LABEL_MAPPING.items()
}


def get_attack_family(folder_name):

    name = folder_name.lower().strip()

    if name == "benign_final":
        return "Benign"

    if name.startswith("ddos-"):
        return "DDoS"

    if name.startswith("dos-"):
        return "DoS"

    if (
        name.startswith("recon-")
        or name == "vulnerabilityscan"
    ):
        return "Reconnaissance"

    if name == "dictionarybruteforce":
        return "BruteForce"

    if name in {
        "dns_spoofing",
        "mitm-arpspoofing",
    }:
        return "Spoofing"

    if name.startswith("mirai-"):
        return "Mirai"

    if name in {
        "backdoor_malware",
        "browserhijacking",
        "commandinjection",
        "sqlinjection",
        "uploading_attack",
        "xss",
    }:
        return "WebBased"

    raise ValueError(
        f"Unknown attack folder: {folder_name}"
    )


def get_label(folder_name):

    family = get_attack_family(folder_name)

    return LABEL_MAPPING[family]


if __name__ == "__main__":

    print("MULTICLASS LABEL MAPPING")
    print("=" * 40)

    for family, label in LABEL_MAPPING.items():
        print(f"{label}: {family}")

    print("\nVulnerabilityScan mapping:")
    print(get_attack_family("VulnerabilityScan"))