def detect_events(logs):
    failed_logins = []
    privileged_logons = []

    for log in logs:
        msg = log.get("Message", "").lower()
        if "failed login" in msg:
            failed_logins.append(f"{log['EventTime']} - {log.get('IpAddress', '')} - {msg}")
        if "special privileges" in msg:
            privileged_logons.append(f"{log['EventTime']} - {log.get('SubjectUserName', '')} got special privileges")

    return {
        "failed_logins": failed_logins,
        "privileged_logons": privileged_logons
    }
