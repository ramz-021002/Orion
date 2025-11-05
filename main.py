import os
import sys
import re
import time
import argparse
import json
import datetime
import hashlib
import requests
import markdown
from typing import Callable, Optional
import google.genai as genai
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
from dotenv import load_dotenv
import getMaliciousIps

load_dotenv()

logging.basicConfig(filename="tool.log",
                    format='%(asctime)s %(message)s',
                    filemode='w')

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

api_key = os.getenv("GEMINI_API_KEY")
update_flag = False
def parse_ips_from_fast_log_line(line: str) -> tuple[str | None, str | None]:
    """Parse a Suricata fast.log line and return (src_ip, dst_ip).

    Expected format (simplified):
    ts [Action] [**] [gid:sid:rev] msg [**] [Classification: ...] [Priority: ...] {PROTO} src:port -> dst:port

    Returns a tuple (blocked_src_ip, user_dst_ip). If parsing fails, values may be None.
    """
    ipv4_re = r"(?:\d{1,3}\.){3}\d{1,3}"
    try:
        if '}' in line:
            after_brace = line.split('}', 1)[1].strip()
            # Try to split around the arrow
            if '->' in after_brace:
                left, right = after_brace.split('->', 1)
                left = left.strip()
                right = right.strip()
                src_token = left.split()[0] if left else ''
                dst_token = right.split()[0] if right else ''
                src_ip = src_token.split(':', 1)[0] if ':' in src_token else src_token
                dst_ip = dst_token.split(':', 1)[0] if ':' in dst_token else dst_token
                if re.fullmatch(ipv4_re, src_ip) and re.fullmatch(ipv4_re, dst_ip):
                    return src_ip, dst_ip
                # Allow partial matches: validate individually
                src_ok = src_ip if re.fullmatch(ipv4_re, src_ip) else None
                dst_ok = dst_ip if re.fullmatch(ipv4_re, dst_ip) else None
                if src_ok or dst_ok:
                    return src_ok, dst_ok
    except Exception:
        pass

    # Fallback: find first two IPv4s in the entire line
    matches = re.findall(ipv4_re, line)
    if len(matches) >= 2:
        return matches[0], matches[1]
    if len(matches) == 1:
        return matches[0], None
    return None, None


def read_fast_log(file_path: str) -> tuple[str | None, str | None]:
    """Read Suricata's fast.log and return (blocked_src_ip, user_dst_ip) for the last DROP event.

    Example line:
    10/18/2025-19:54:56.851821 [Drop] [**] [1:109975:1] Blocked malicious IP 220.86.113.155 [**] [Classification: Potentially Bad Traffic] [Priority: 8] {ICMP} 220.86.113.155:0 -> 192.168.0.101
    """
    if not os.path.exists(file_path):
        logger.critical(f"[warn] fast.log not found: {file_path}", file=sys.stderr)
        return None, None

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            lines = [ln.strip() for ln in file.readlines() if ln.strip()]
            if not lines:
                return None, None
            last_log = lines[-1]
            if ('Drop' in last_log) or ('DROP' in last_log) or ("ET CINS Active Threat Intelligence Poor" in last_log):
                #print(last_log)
                return parse_ips_from_fast_log_line(last_log)
    except PermissionError as e:
        logger.error(f"[error] Permission denied reading fast.log at {file_path}: {e}", file=sys.stderr)
        return None, None
    except OSError as e:
        logger.error(f"[error] Failed to read fast.log at {file_path}: {e}", file=sys.stderr)
        return None, None

    return None, None


# Deduplication cache for printed Zeek log lines within the sliding window.
# Maps (file_path, sha1(line)) -> timestamp (float seconds)
_SEEN_ZEEK_LINES: dict[tuple[str, str], float] = {}
def check_zeek_logs(
    ip_address: str,
    log_path: str,
    minutes: float = 5.0,
    header: str | None = None,
    emit: Optional[Callable[[str], None]] = None,
) -> int:
    """Check Zeek logs for activity related to the given IP in the last N minutes.

    Supports Zeek ASCII (TSV) logs with headers and Zeek JSON logs.
    Prints matching lines with the filename. If 'header' is provided, it is printed
    once before the first new matching line (based on dedup cache) in this call.

    Returns the number of lines printed.
    """

    def _parse_ts_value(raw) -> float | None:
        """Parse a Zeek 'ts' value into a Unix timestamp (float seconds)."""
        if raw is None:
            return None
        # Numeric string or number
        try:
            if isinstance(raw, (int, float)):
                return float(raw)
            s = str(raw).strip().strip('"')
            if re.fullmatch(r"\d+(?:\.\d+)?", s):
                return float(s)
        except Exception:
            pass

        # Try common ISO-8601 representations
        s = str(raw).strip()
        fmts = [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
        ]
        for fmt in fmts:
            try:
                if fmt.endswith("Z") and s.endswith("Z"):
                    dt = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
                else:
                    dt = datetime.datetime.strptime(s, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=datetime.timezone.utc)
                return dt.timestamp()
            except Exception:
                continue
        return None

    def _decode_separator(header_line: str) -> str:
        """Decode Zeek '#separator' directive to a real character; default to tab."""
        try:
            parts = header_line.split(None, 1)
            if len(parts) == 2:
                raw = parts[1].strip()
                # Interpret sequences like \x09
                return bytes(raw, "utf-8").decode("unicode_escape")
        except Exception:
            pass
        return "\t"

    now_ts = time.time()
    min_ts = now_ts - max(0.0, minutes) * 60.0

    # Prune old entries from dedup cache
    try:
        stale_keys = [k for k, ts in _SEEN_ZEEK_LINES.items() if ts < min_ts]
        for k in stale_keys:
            _SEEN_ZEEK_LINES.pop(k, None)
    except Exception:
        # Non-fatal if pruning fails
        pass

    exculuded = ["broker.log", "reporter.log"]
    try:
        files = os.listdir(log_path)
    except PermissionError as e:
        logger.error(
            f"[error] Permission denied accessing Zeek logs at {log_path}. "
            f"Add your user to the 'zeek' group or adjust ACLs. Details: {e}",
            file=sys.stderr,
        )
        return
    except FileNotFoundError:
        print(f"[warn] Zeek log directory not found: {log_path}", file=sys.stderr)
        return
    except OSError as e:
        print(f"[error] Failed to list Zeek log directory {log_path}: {e}", file=sys.stderr)
        return

    printed_count = 0

    for fname in files:
        if not fname.endswith('.log') or fname in exculuded:
            continue
        fpath = os.path.join(log_path, fname)

        # Optional: skip very old files by mtime to reduce I/O
        try:
            if os.path.getmtime(fpath) < min_ts:
                continue
        except OSError:
            # If we can't stat the file, try reading anyway
            pass

        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                # Track Zeek headers per-file
                fields: list[str] | None = None
                ts_idx: int | None = None
                sep: str = "\t"
                # Special-case: include entire ssh.log contents (deduplicated) regardless of timestamps.
                # This will emit all non-empty lines from ssh.log using the same deduplication cache.
                if fname == 'ssh.log':
                    for raw_line in f:
                        line = raw_line.rstrip("\n")
                        if not line:
                            continue
                        try:
                            h = hashlib.sha1(line.encode('utf-8', errors='ignore')).hexdigest()
                            key = (fpath, h)
                            # For ssh.log we don't consult timestamps; just emit if not seen or newer
                            last_ts = _SEEN_ZEEK_LINES.get(key)
                            # Use current time as marker for dedup cache
                            now_marker = now_ts
                            if last_ts is None or now_marker > last_ts:
                                if emit:
                                    if header is not None and printed_count == 0:
                                        emit(header)
                                    emit(f"{fname}: {line.strip()}")
                                else:
                                    if header is not None and printed_count == 0:
                                        print(header)
                                    print(f"{fname}: {line.strip()}")
                                _SEEN_ZEEK_LINES[key] = now_marker
                                printed_count += 1
                        except Exception:
                            if emit:
                                if header is not None and printed_count == 0:
                                    emit(header)
                                emit(f"{fname}: {line.strip()}")
                            else:
                                if header is not None and printed_count == 0:
                                    print(header)
                                print(f"{fname}: {line.strip()}")
                            printed_count += 1
                    # After handling ssh.log fully, skip the regular per-line timestamped processing
                    continue

                for raw_line in f:
                    line = raw_line.rstrip("\n")
                    if not line:
                        continue

                    # Handle Zeek ASCII headers
                    if line.startswith('#'):
                        if line.startswith('#separator'):
                            sep = _decode_separator(line) or "\t"
                        elif line.startswith('#fields'):
                            # '#fields' is space-delimited regardless of data separator
                            parts = line.split()
                            # parts[0] == '#fields'
                            fields = parts[1:] if len(parts) > 1 else None
                            ts_idx = None
                            if fields and 'ts' in fields:
                                ts_idx = fields.index('ts')
                        continue

                    ts_val: float | None = None

                    # Try JSON logs first
                    if line.lstrip().startswith('{'):
                        try:
                            obj = json.loads(line)
                            ts_raw = obj.get('ts')
                            ts_val = _parse_ts_value(ts_raw)
                        except Exception:
                            ts_val = None
                    else:
                        # ASCII/TSV logs
                        if ts_idx is not None:
                            try:
                                cols = line.split(sep) if sep else line.split()
                                if 0 <= ts_idx < len(cols):
                                    ts_raw = cols[ts_idx]
                                    if ts_raw not in (None, '', '-'):
                                        ts_val = _parse_ts_value(ts_raw)
                            except Exception:
                                ts_val = None

                    # Only consider recent lines
                    if ts_val is None or ts_val < min_ts:
                        continue

                    if ip_address in line:
                        # Deduplicate using file path and content hash within time window
                        try:
                            h = hashlib.sha1(line.encode('utf-8', errors='ignore')).hexdigest()
                            key = (fpath, h)
                            last_ts = _SEEN_ZEEK_LINES.get(key)
                            if last_ts is None or ts_val > last_ts:
                                if emit:
                                    if header is not None and printed_count == 0:
                                        emit(header)
                                    emit(f"{fname}: {line.strip()}")
                                else:
                                    if header is not None and printed_count == 0:
                                        print(header)
                                    print(f"{fname}: {line.strip()}")
                                _SEEN_ZEEK_LINES[key] = ts_val
                                printed_count += 1
                        except Exception:
                            # On hashing/cache error, fall back to printing
                            if emit:
                                if header is not None and printed_count == 0:
                                    emit(header)
                                emit(f"{fname}: {line.strip()}")
                            else:
                                if header is not None and printed_count == 0:
                                    print(header)
                                print(f"{fname}: {line.strip()}")
                            printed_count += 1
        except PermissionError as e:
            logger.error(f"[error] Permission denied reading {fpath}: {e}", file=sys.stderr)
        except OSError as e:
            logger.error(f"[error] Failed reading {fpath}: {e}", file=sys.stderr)
    # print(f"[info] Zeek log check for IP {ip_address} completed, {printed_count} new lines found.")
    return printed_count

def get_from_gemini(user_address, output_txt, info):
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=f"Suricata has blocked IP address {info} from internal user {user_address}, analyze the following Zeek log output for security insights:\n\n{output_txt}\n\n Tell if any logs looks like malicious and why. Ignore DUCKDNS logs. Report as if you are security analyst reporting to senior.\n\n Do not include To, Subject, From, Date and write it in a way it would look good in email. Don't mention Gemini AI, Copilot, smtp.gmail.com, connectivity-check.ubuntu.com, Invalid Checksums, ip-api.com, and other traffic anywhere in the report. Try to focus on traffic which is suspicious and related to malicious IP given from user behavior perspective. Do not include log files names in the report. Keep it concise and precise. Remember the blocked Ip address will not show up in zeek logs as it wont be logged. So focus on user behavior analysis only. Try to find how the user might have logged in usng ssh or how using the zeek logs and try to include that in the email if you find any traces using the logs. If you want to include timestamp convert the unix to human-readable time stamp and include the malicous ip details given(isp, country, city).",
    ) 
    return response.text

def get_ip_info(ip_address):
    url = f'http://ip-api.com/json/{ip_address}'
    response = requests.get(url)
    data = response.json()
    city = data['city']
    country = data['country']
    isp = data['isp']
    return city, country, isp


def send_mail(subject: str, body: str, to_address: str):
    from_address = os.getenv("MAIL_ADDRESS")
    password = os.getenv("MAIL_PASSOWORD")

    if not from_address or not password:
        logger.error("[error] Email credentials are not set in environment variables.", file=sys.stderr)
        return

    try:
        # Set up email mime
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_address
        msg["To"] = to_address

        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(from_address, password)
            server.send_message(msg)
            logger.info(f"[info] Email sent to {to_address}")
    except Exception as e:
        logger.error(f"[error] Failed to send email: {e}", file=sys.stderr)

def update_suricata_rules():
    os.system("rm /var/lib/suricata/rules/block_ips.rules")
    getMaliciousIps.getMaliciousIps()
    os.system("suricata-update")
    os.system("systemctl restart suricata")
    
def main():
    parser = argparse.ArgumentParser(description='Correlate Suricata DROP IPs with Zeek logs.')
    parser.add_argument('--fast-log', default='/var/log/suricata/fast.log', help='Path to Suricata fast.log')
    parser.add_argument('--zeek-logs', default='/opt/zeek/logs/current', help='Path to Zeek current log directory')
    parser.add_argument('--interval', type=float, default=5.0, help='Polling interval in seconds')
    parser.add_argument('--test-ip', default=None, help='Override IP address for testing (skips reading fast.log)')
    parser.add_argument('--once', action='store_true', help='Run a single iteration and exit')
    parser.add_argument('--output', default='output.txt', help='File to write results; replaced on new IP output')
    args = parser.parse_args()

    try:
        # Prepare per-IP emitter that truncates file on first output for a new IP
        output_path = args.output
        last_written_ip: Optional[str] = None

        def make_emit_for_ip(current_ip: str) -> Callable[[str], None]:
            first_emission_done = False

            def _emit(msg: str) -> None:
                nonlocal first_emission_done, last_written_ip
                mode = 'a'
                if not first_emission_done and last_written_ip != current_ip:
                    mode = 'w'  # replace file for new IP
                try:
                    with open(output_path, mode, encoding='utf-8') as fh:
                        fh.write(msg + "\n")
                except Exception:
                    # Non-fatal: still printed to stdout
                    pass
                if not first_emission_done:
                    first_emission_done = True
                    if last_written_ip != current_ip:
                        last_written_ip = current_ip

            return _emit

        while True:
            global update_flag
            day = datetime.datetime.now().day

            if day == 1:
                if not update_flag:
                    logger.info("Updating Suricata rules with latest malicious IPs...")
                    update_suricata_rules()
                    update_flag = True
            else:
                update_flag = False

            blocked_address, user_address = None, None
            os.system("rm output.txt")
            os.system("touch output.txt")
            if args.test_ip:
                blocked_address, user_address = args.test_ip, None
            else:
                # print(f"[info] Reading Suricata fast.log at {args.fast_log}...")
                blocked_address, user_address = read_fast_log(args.fast_log)
                logger.info(f"[info] Parsed blocked IP: {blocked_address}, user IP: {user_address}")

            # Report parsed IPs for visibility, but only print headers when there are new matching log lines
            if blocked_address or user_address:
                if blocked_address:
                    emit_blocked = make_emit_for_ip(blocked_address)
                    logger.info(f"Checking Zeek logs for blocked IP: {blocked_address}...")
                    check_zeek_logs(
                        blocked_address,
                        args.zeek_logs,
                        header=blocked_address,
                        emit=emit_blocked,
                    )
                if user_address:
                    emit_user = make_emit_for_ip(user_address)
                    logger.info(f"Checking Zeek logs for user IP: {user_address}...")
                    check_zeek_logs(
                        user_address,
                        args.zeek_logs,
                        header=user_address,
                        emit=emit_user,
                    )            
            
            with open(output_path, 'r', encoding='utf-8') as fh:
                output = fh.read()
            
            if output:
                logger.info("Sending logs for analysis to Gemini...")
                try:
                    city, country, isp = get_ip_info(blocked_address)
                    info = f"Blocked Malicious IP Address: {blocked_address}\nLocation: {city}, {country}\nISP: {isp}\n\n"
                    response = get_from_gemini(user_address, output, info)
                    response = markdown.markdown(response) # Convert Gemini response to HTML
                    send_mail(
                    subject="Security Analysis Report",
                    body = response,
                    to_address="parnandi.2@osu.edu"
                    )
                    send_mail(
                    subject="Security Analysis Report",
                    body=response,
                    to_address="sung.260@osu.edu"
                    )
                    logger.info("[info] Response sent via email.\n")
                except Exception as e:
                    response = f"Error getting response from Gemini: {e}"
                    logger.error(response)
            if args.once:
                break
            time.sleep(max(0.1, args.interval))
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")


if __name__ == '__main__':
    main()
