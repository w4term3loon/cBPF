"""Small shared receipt checks; no native execution or general decoder."""
import hashlib
import re


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checksums(path):
    result = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match and match[2] not in result, "Malformed/duplicate checksum: " + str(path))
        result[match[2]] = match[1]
    require(result, "Empty checksum list")
    return result


def by_suffix(rows, suffix):
    matches = [value for name, value in rows.items() if name.endswith(suffix)]
    require(len(matches) == 1, "Expected one checksum for " + suffix)
    return matches[0]


def validate_completion(text, exit_text):
    require(exit_text.strip() == "0", "QEMU did not exit zero")
    require(not re.search(
        r"result=FAIL|identity=FAIL|poweroff=FAIL|Kernel panic|Oops:|BUG:|WARNING:|"
        r"refcount_t:|Unable to handle kernel|timeout|timed out", text, re.I),
        "Fatal/failing log marker")
    require(len(re.findall(r"reboot: Power down\s*(?:\n|$)", text)) == 1,
            "Missing or duplicate kernel shutdown completion")
    return {"qemu_exit": 0, "kernel_powerdown": True, "failure_markers": False}
