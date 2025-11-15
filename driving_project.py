import sys                      # for detecting operating system and exit
import os                       # for environment variables and file operations
import stat                     # for POSIX file permission flags
import subprocess               # run the 'icacls' command on Windows
import json, time               # for writing/reading an audit log with timestamps
import base64, hmac             # for HMAC signatures (authenticity)
import pandas as pd             # for handling tabular data
import numpy as np              # for random number generation
import hashlib                  # for cybersecurity (hashing)
import matplotlib               # for graphs and plots
import shutil                   # copy/restore entire snapshot folders
import getpass as gp            # username on Windows (gp.getuser)
from pathlib import Path        # for path files
from getpass import getpass     # for hidden password input (no echo)

# Choose a Matplotlib backend that works for all systems
# "MacOSX" -> macOS pop-up, "TkAgg" -> Windows/Linux
matplotlib.use("MacOSX" if sys.platform == "darwin" else "TkAgg")

# Import pyplot after choosing the backend, plotting API
import matplotlib.pyplot as plt

# Global constants for units, thresholds, locations
KMH_TO_MPH = 0.621371 # conversion factor (km/h -> mph)
HIGH_KMH = 120 # km/h threshold
HIGH_MPH = 75 # mph threshold (approximately 120 km/h)
RUNS_DIR = Path("runs") # where each run’s files live
CURRENT_DIR = Path("current") # restore destination
AUDIT_LOG = Path("audit.log") # append-only audit log file (hash-chained)
RUNS_DIR.mkdir(exist_ok=True) # ensure base folder exists

# Define a function named 'authenticate' that checks the user's password
# The default correct password is set to "secure123"
def authenticate(secret="secure123"):
    # Use getpass() to ask for the password (input is hidden for security)
    # Whatever the user types is stored in the variable 'pwd'
    pwd = getpass("Enter password to access driving data: ")
    # Compare what the user typed (pwd) to the correct password (secret)
    if pwd != secret:
        # If the password is wrong, print an error message
        print("Access denied! Exiting...")
        # Stop the entire program right away (exit code 1 means failure)
        sys.exit(1)
    # If the password matches, print a success message
    print("Access granted!\n")

# Define a function that will generate one stimulated driving trip
def simulate_trip(trip_type='city', min_seconds=30, max_seconds=180):
    # Chooses a random trip length (between 30-180 seconds)
    duration = np.random.randint(min_seconds, max_seconds)

    # Create a time column: 0, 1, 2, ... up to duration
    time_s = np.arange(duration)

    # Depending on the type of trip, generate different driving patterns
    if trip_type == "city": # use == for comparison
        # city: slower and more variable: clip to a realistic range
        speed_kmh = np.clip(np.random.normal(40, 10, duration), 0, 60)
        acceleration = np.random.normal(0, 2, duration)
        tilt = np.random.normal(0, 5, duration)
    else:
        # highway: faster and smoother: clip to a realistic range
        speed_kmh = np.clip(np.random.normal(100, 15, duration), 60, 130)
        acceleration = np.random.normal(0, 1, duration)
        tilt = np.random.normal(0, 2, duration)

    # Computes mph from km/h so the CSV file always have both units
    speed_mph = speed_kmh * KMH_TO_MPH

    # Returns a table (DataFrame) with all columns
    return pd.DataFrame({
        "time": time_s,                   # seconds within this trip
        "trip_type": trip_type,         # "city" or "highway"
        "speed_kmh": speed_kmh,         # speed in km/h
        "speed_mph": speed_mph,         # speed in mph
        "acceleration": acceleration,
        "tilt": tilt,
    })

# Build a dataset of random trips
def simulate_dataset() -> pd.DataFrame:
    # New randomness for every run
    np.random.seed(None)

    # Pick a random number of trips: 2..5
    n_trips = int(np.random.randint(2, 6))

    trips = []
    for trip_id in range(1, n_trips + 1):
        # Choose trip type randomly each time (50/50 city vs highway)
        trip_type = np.random.choice(["city", "highway"])

        # Make one trip
        trip = simulate_trip(trip_type)

        # Tap which trip each row belongs to (1 . . n_trips)
        trip = trip.assign(trip_id=trip_id)

        # Collect it
        trips.append(trip)

    # Stack all trips into one table
    data = pd.concat(trips, ignore_index=True)

    # Make a continuous timeline across trips
    # Compute how long each trip is, then cumulative starting offsets
    lengths = [len(t) for t in trips]
    offsets = np.cumsum([0] + lengths[:-1])

    # Map trip_id -> its starting offset, then add to per-trip time
    offset_map = {i + 1: offsets[i] for i in range(n_trips)}
    data["global_time"] = data["time"] + data["trip_id"].map(offset_map)

    return data


# Calculates and returns the SHA_256 hash (fingerprint) of a file for integrity verification
def sha256_file(path: Path) -> str:
    # Create a new SHA-256 hashing object
    h = hashlib.sha256()

    # Open the file in binary mode, so we can read raw bytes
    with open(path, "rb") as f:
        # Read the file in chunks of 8 KB (8192 bytes)
        # This prevents memory issues for large files
        for chunk in iter(lambda: f.read(8192), b""):
            # Update the hash with each chunk of data
            h.update(chunk)

    # Return the final hash as a 64-character hexadecimal string
    return h.hexdigest()

# Saves a DataFrame to CSV and prints its SHA-256 hash to confirm the file's authenticity
def save_with_hash(df: pd.DataFrame, path: Path):
    # Save the DataFrame to a CSV file without including row indexes
    df.to_csv(path, index=False)

    # Print to file name and how many rows were saved
    print(f"Saved dataset: {path} (rows: {len(df)})")

    # Compute and print the file's SHA-256 fingerprint for verification
    # This lets you check later if the file was modified or corrupted
    print("SHA-256:", sha256_file(path))

# Returns a 32-byte secret key: prefer SECRET_KEY_HEX from the environment, else generate a random key for this run
def load_or_generate_secret_key() -> bytes:
    # Read the signing key from the environment (expected as a 64-character hex string), use empty string if not set
    env_hex = os.environ.get("SECRET_KEY_HEX", "").strip()

    # If an environment value exists, try to parse it as hex and ensure it's at least 32 bytes
    if env_hex:
        try:
            # Convert the hex string to raw bytes (raises ValueError if not valid hex)
            key = bytes.fromhex(env_hex)

            # If the key is long enough, return exactly 32 bytes (truncate if longer)
            if len(key) >= 32:
                return key[:32]
        except ValueError:
            # If the value isn't valid hex, ignore it and fall back to a random key below
            pass

    # If no valid env key is available, create a new random 32-byte key (for this run only)
    return os.urandom(32)

# Creates a unique Base64 HMAC-SHA256 signature for a file using a secret key to prove the file's authenticity and integrity
def hmac_sha256_file(path: Path, key: bytes) -> str:
    # Start an HMAC-SHA256 object using the secret key
    mac = hmac.new(key, digestmod=hashlib.sha256)
    # Open the file in binary mode so the exact file bytes can be read
    with open(path, "rb") as f:
        # Read the file in chunks of 8KB to handle large files efficiently
        for chunk in iter(lambda: f.read(8192), b""):
            # Update the HMAC with each chunk of data read from the file
            mac.update(chunk)
    # Convert the final HMAC (binary) into a Base64 text string and return it
    return base64.b64encode(mac.digest()).decode("utf-8")

# Checks if a file’s digital signature matches its expected HMAC-SHA256 signature to confirm it hasn’t been tampered with
def verify_hmac_file(path: Path, sig_b64: str, key: bytes) -> bool:
    # Recreate the expected HMAC signature using the same key and file
    expected = hmac_sha256_file(path, key)
    # Compares the real signature to the expected one using a safe equality check (prevents timing attacks)
    return hmac.compare_digest(expected, sig_b64)

# Returns the previous entry's hash from the audit log, or "GENESIS" if no log/entries exist
def _last_log_hash() -> str:
    # If the log file doesn't exist, we're at the start of the chain
    if not AUDIT_LOG.exists():
        return "GENESIS"
    # Read all non-empty lines from the log so we can inspect the last entry
    lines = [ln for ln in AUDIT_LOG.read_text(encoding="utf-8").splitlines() if ln.strip()]
    # If the file is empty, we're still at the start of the chain
    if not lines:
        return "GENESIS"
    try:
        # Parse the last JSON record and return its entry hash to chain the next one
        return json.loads(lines[-1]).get("entry_hash", "GENESIS")
    except Exception:
        # If parsing fails, treat it like we're at the start to avoid crashing
        return "GENESIS"

# Adds a new audit log record that includes a hash of the previous record (makes the log tamper-evident)
def audit_event(event: str, details: dict):
    # Grab the previous entry's hash to chain this new entry to the last one
    prev_hash = _last_log_hash()
    # Record the current UTC time in a standard, sortable string format
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    # Turn the details into a stable JSON string so hashing is consistent
    body = json.dumps(details, sort_keys=True)
    # Build the exact bytes we will hash (previous hash + time + event + details)
    entry_bytes = (prev_hash + ts + event + body).encode("utf-8")
    # Create this entry's hash, which "locks" this line to the previous one
    entry_hash = hashlib.sha256(entry_bytes).hexdigest()
    # Prepare the JSON record that will be written to the log
    record = {"ts": ts, "event": event, "details": details, "prev_hash": prev_hash, "entry_hash": entry_hash}
    # Adds the record as a single JSON line at the end of the log file
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

# Rebuilds the chain from start to finish to confirm no entries were edited or removed
def verify_audit_log() -> bool:
    # If there's no audit.log file, say so and treat it as nothing to verify (return True)
    if not AUDIT_LOG.exists():
        print("Audit log: none found")
        return True
    # ok tracks whether the chain is still valid: prev holds the "previous hash" we expect ("GENESIS" for the first line)
    ok, prev = True, "GENESIS"
    # Read the whole file as text, split into lines, and loop through them with a 1-based line number
    for i, ln in enumerate(AUDIT_LOG.read_text(encoding="utf-8").splitlines(), start=1):
        # Ignore blank lines so they don't count as broken entries
        if not ln.strip():
            continue
        # Turn the JSON text on this line into a Python dict (rec)
        rec = json.loads(ln)

        # Pull out the timestamp and event name we stored when writing this entry
        ts, ev = rec["ts"], rec["event"]

        # Recreate the exact JSON string for the details dict (sorted keys to match the write-time format)
        det = json.dumps(rec["details"], sort_keys=True)

        # Recompute what this line's hash should be using (previous hash + ts + event + details), then SHA-256
        expected = hashlib.sha256((prev + ts + ev + det).encode("utf-8")).hexdigest()

        # If the stored hash in the file doesn't match the recomputed expected one, the log was altered
        if rec.get("entry_hash") != expected:
            print(f"Audit chain broken at line {i}")
            ok = False
            break
        # Advance the chain by setting prev to this entry's hash
        prev = rec["entry_hash"]

    # Say whether the chain stayed intact for all lines, and return True/False accordingly
    print("Audit log OK (chain intact)." if ok else "Audit log FAILED.")
    return ok

# Makes a safer copy of the data to share by hiding exact times and slightly blurring speeds
def export_privacy_copy(df: pd.DataFrame, out_path: Path):
    # Make a copy so we don't change the original data
    pub = df.copy()
    # Group time into 5-second chunks so exact seconds aren't shown
    pub["time_bucket_s"] = (pub["global_time"] // 5) * 5
    # Create tiny random bumps we'll add to speeds (about +- 0.5 mph)
    noise = np.random.normal(0, 0.5, len(pub)) # small, harmless wiggle
    # Make a public mph speed: real speed + tiny noise, rounded to 1 decimal
    pub["speed_mph_public"] = (pub["speed_mph"] + noise).round(1)
    # Make a public km/h speed: same idea as above, but in km/h
    pub["speed_kmh_public"] = (pub["speed_kmh"] + noise / KMH_TO_MPH).round(1)
    # Keep only the simple, non-sensitive columns for sharing
    pub = pub[["trip_id", "time_bucket_s", "speed_kmh_public", "speed_mph_public"]]
    # Save this privacy-safe table to a CSV file (no row numbers)
    pub.to_csv(out_path, index=False)
    # Let the user know where the safe file was written
    print(f"Privacy export written: {out_path}")

# Restricts a file’s access so only the current user can read and write it (uses chmod 0600 on Mac/Linux, and icacls on Windows)
def set_strict_perms(path: Path):
    try:
        if sys.platform.startswith("win"):
            # On Windows, find the current logged-in username
            user = gp.getuser()

        # Run the 'icacls' command to:
        # - Remove inherited permissions ("/inheritance:r")
        # - Grant only the current user full control ("/grant:r")
        # - Remove broad access groups like 'Users' or 'Everyone'
            subprocess.run(
        [
                "icacls", str(path),
                "/inheritance:r",
                "/grant:r", f"{user}:F",
                "/remove", "Users", "Authenticated Users", "Everyone",
                ],
                capture_output=True, # Prevents console spam
                check=False,         # Doesn't crash if the command fails
            )
        else:
            # On macOS/Linux, set file permissions to 0600 (only owner can read/write)
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        # If anything fails (no permission, filesystem doesn’t support chmod), skip quietly so the program continues running
        pass

# Builds a per-trip summary table with core KPIs and a simple 0-100 safety score derived from speeding and harsh braking
def trip_kpis_and_score(df: pd.DataFrame) -> pd.DataFrame:

# Prepare a list where we’ll collect one small results dict per trip
    rows = []

    # Iterate over the data grouped by trip_id so we compute KPIs for each trip separately
    for tid, g in df.groupby("trip_id"):

        # Compute the average speed in mph for this trip to reflect typical driving pace
        avg_mph = float(g["speed_mph"].mean())
        # Compute the maximum speed in mph for this trip to capture peak speed behavior
        max_mph = float(g["speed_mph"].max())
        # Count how many samples were at or above the “high speed” threshold (75 mph) as a simple speeding metric
        secs_over = int((g["speed_mph"] >= HIGH_MPH).sum())
        # Count how many samples indicate harsh braking (acceleration ≤ −3.0 m/s²) as a rough safety signal
        harsh_brakes = int((g["acceleration"] <= -3.0).sum())
        # Start from a perfect score (100) and subtract a small penalty for each speeding second and a larger penalty per harsh brake
        score = 100 - secs_over * 0.2 - harsh_brakes * 2
        # Clamp the score so it never goes below 0 or above 100 for clean presentation
        score = max(0, min(100, score))
        # Store this trip's KPIs and score in a compact dict (rounded for readability)
        rows.append({
            "trip_id": int(tid),                       # the trip number we summarized
            "avg_speed_mph": round(avg_mph, 1),        # average speed to one decimal place
            "max_speed_mph": round(max_mph, 1),        # maximum speed to one decimal place
            "secs_over_75mph": secs_over,              # total samples at/over the threshold (≈ seconds)
            "harsh_brakes": harsh_brakes,              # count of harsh braking events
            "score_0_100": round(score, 1),            # final safety score on a 0–100 scale
        })

    # Convert the list of per-trip dicts into a tidy DataFrame (one row per trip) and return it
    return pd.DataFrame(rows)

# Plots driving speed over time with both km/h (left axis) and mph (right axis), highlighting high-speed points above set thresholds
def plot_speed_dual_units(df: pd.DataFrame):
    # Create a new figure (12x6 inches) and the primary y-axis (left side)
    fig, ax_left = plt.subplots(figsize=(12, 6))

    # Plot speed in km/h on the left y-axis against the continuous time axis
    ax_left.plot(df["global_time"], df["speed_kmh"], label="Speed (km/h)")
    ax_left.set_xlabel("Global Time (seconds)")     # x-axis label
    ax_left.set_ylabel("Speed (km/h)")              # left y-axis label
    ax_left.grid(True, alpha=0.3)            # light grid for readability

    # Create a secondary y-axis that shares the same x-axis (right side)
    ax_right = ax_left.twinx()

    # Plot speed in mph on the right y-axis (dashed to distinguish from km/h)
    ax_right.plot(df["global_time"], df["speed_mph"], linestyle="--", label="Speed (mph)")
    ax_right.set_ylabel("Speed (mph)") # right y-axis label

    # Find rows where speed exceeds the high-speed thresholds (km/h and mph)
    hi_kmh = df[df["speed_kmh"] >= HIGH_KMH]
    hi_mph = df[df["speed_mph"] >= HIGH_MPH]

    # If there are high-speed points in km/h, mark them with red dots on the left axis
    if not hi_kmh.empty:
        ax_left.scatter(
            hi_kmh["global_time"], hi_kmh["speed_kmh"],
            color="red", s=14, label=f"≥ {HIGH_KMH} km/h"
        )

    # If there are high-speed points in mph, mark them with purple dots on the right axis
    if not hi_mph.empty:
        ax_right.scatter(
            hi_mph["global_time"], hi_mph["speed_mph"],
            color="purple", s=14, label=f"≥ {HIGH_MPH} mph"
        )

    # Each axis has its own legend entries, grab them from both axes
    lines_l, labels_l = ax_left.get_legend_handles_labels()
    lines_r, labels_r = ax_right.get_legend_handles_labels()

    # Combines into a single legend shown on the left axis
    ax_left.legend(lines_l + lines_r, labels_l + labels_r, loc="upper left")

    # Add a title, fix layout so labels don’t get cut off, and show the plot window
    plt.title("Driving Speed Over Time (km/h & mph)")
    plt.tight_layout()
    plt.show(block=True)

# Plots any single time-based variable (like acceleration or tilt) against global time
def plot_series(df: pd.DataFrame, column: str, ylabel: str, title: str):
    # Create a single single-axis figure for a generic time-series column
    plt.figure(figsize=(12, 6))

    # Plot the specified column (acceleration or tilt) versus global time
    plt.plot(df["global_time"], df[column], label=ylabel)

    # Axis labels and title
    plt.xlabel("Global Time (seconds)")
    plt.ylabel(ylabel)
    plt.title(title)

    # Light grid and a legend using the provided label
    plt.grid(True)
    plt.legend()

    # Adjust layout and display the plot window (blocks until closed)
    plt.tight_layout()
    plt.show(block=True)

# Returns run folders sorted newest-first by their timestamped names
def _get_snapshots() -> list[Path]:
    # If the base runs/ directory doesn't exist, there are no snapshots
    if not RUNS_DIR.exists():
        return []
    # Collect only subdirectories inside runs/ because each run is a folder
    runs = [p for p in RUNS_DIR.iterdir() if p.is_dir()]
    # Sort by folder name descending so lexicographic timestamps put newest first
    runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    # Hand back the ordered list of snapshot directories
    return runs

# Prints a simple table showing index, run folder name, and files inside each snapshot
def list_snapshots():
    # Fetch all snapshot directories in newest-first order
    runs = _get_snapshots()
    # If none exist, tell the user and stop
    if not runs:
        print("No snapshots found in 'runs/'.")
        return
    # Print a fixed-width header for readability
    print(f"{'Idx':>3}  {'Run Folder':<20}  Files")
    # Print a separator line under the header
    print("-" * 60)
    # For each run, list its index, folder name, and a comma-separated file list
    for i, r in enumerate(runs):
        files = [p.name for p in r.iterdir()]
        print(f"{i:>3}  {r.name:<20}  {', '.join(files)}")

# Resolves a user-supplied selector to an actual run folder path
def _select_snapshot(selector: str | int | None) -> Path | None;
    # Load the available snapshots in newest-first order
    runs = _get_snapshots()
    # If there are no snapshots, nothing can be selected
    if not runs:
        return None
    # Treat None or the string "latest" as a request for the newest snapshot
    if selector in (None, "latest"):
        return runs[0]
    # If selector is an integer (or a numeric string), treat it as an index
    if isinstance(selector, int) or (isinstance(selector, str) and selector.isdigit()):
        idx = int(selector)
        # Return the run at that index if it is within range, else NONE
        return runs[idx] if 0 <= idx < len(runs) else None
    # Otherwise match by timestamp prefix
    for r in runs:
        if r.name.startswith(str(selector)):
            return r
    # If nothing matched, indicate failure with None
        return None

# Verifies a chosen snapshot's CSV integrity and audit-log chain, printing results
def verify_snapshot(selector: str | int = "latest") -> bool:
    # Resolve the selector to a concrete run folder
    run = _select_snapshot(selector)
    # If no run matches, report and fail
    if not run:
        print("Snapshot not found.")
        return False
    # Define key file paths within the snapshot
    meta_path = run / "run_meta.json"
    csv_path = run / "driving_data.csv"
    audit_path = run / "audit.log"

    # Track overall verification status starting as good
    ok = True

    # Require both the metadata and raw CSV to exist for verification to proceed
    if not meta_path.exists() or not csv_path.exists():
        print("Snapshot missing required files.")
        return False

    # Load stored metadata describing the snapshot
    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    # Recompute the CSV's SHA-256 to detect any modification
    actual_sha = sha256_file(csv_path)

    # Compare stored hash to actual hash and report mismatch or success
    if meta.get("csv_sha256") != actual_sha:
        print("CSV SHA-256 mismatch! (file was changed)")
        ok = False
    else:
        print("CSV SHA-256 matches ✅")

    # Next, verify the audit log's hash chain integrity if present
    if not audit_path.exists():
        print("Audit log missing.")
        ok = False
    else:
        # Temporarily point the global AUDIT_LOG to this snapshot's log for reuse
        global AUDIT_LOG
        old = AUDIT_LOG
        AUDIT_LOG = audit_path

        # Run the chain verification and combine with current status
        ok = verify_audit_log() and ok

        # Restore the original global AUDIT_LOG path afterward
        AUDIT_LOG = old

    # Note that HMAC cannot be re-verified unless the original secret key is available
    # Print a final verdict message specific to the snapshot folder
    if ok:
        print(f"Snapshot '{run.name}' verified OK.")
    else:
        print(f"Snapshot '{run.name}' failed verification.")

    # Return the boolean verification result to the caller
    return ok

# Copies all files from a chosen snapshot into current/ for quick inspection or use
def restore_snapshot(selector: str | int = "latest", overwrite: bool = False):
    # Resolve which snapshot should be restored
    run = _select_snapshot(selector)
    # If the snapshot cannot be found, bail out with a message
    if not run:
        print("Snapshot not found.")
        return

    # Optionally wipe the existing current/ directory to avoid stale files
    if CURRENT_DIR.exists() and overwrite:
        shutil.rmtree(CURRENT_DIR)

    # Ensure current/ exists so we have a destination for the copy
    CURRENT_DIR.mkdir(exist_ok=True)

    # Copy each item from the snapshot, preserving files and replacing dirs cleanly
    for p in run.iterdir():
        dst = CURRENT_DIR / p.name
        if p.is_file():
            # Copy regular files with metadata (timestamps and permissions) where possible
            shutil.copy2(p, dst)
        elif p.is_dir():
            # Replace any existing destination directory before copying a fresh tree
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(p, dst)

    # Confirm to the user which snapshot was restored and where it went
    print(f"Restored snapshot '{run.name}' to '{CURRENT_DIR}/'")

# Runs one secure cycle and saves everything inside a unique timestamp folder
def run_pipeline():
    authenticate()
    # Makes a unique run folder
    run_ts = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    run_dir = RUNS_DIR / run_ts
    run_dir.mkdir(parents=True, exist_ok=False)

    # Moves this run's audit log into the run folder
    global AUDIT_LOG
    AUDIT_LOG = run_dir / "audit.log"
    audit_event("AUTH_OK", {})

    # Generate data
    data = simulate_dataset()
    audit_event("SIMULATED", {"trips": int(data["trip_id"].nunique()), "rows": int(len(data))})

    # Save raw CSV
    csv_path = run_dir / "driving_data.csv"
    save_with_hash(data, csv_path)
    set_strict_perms(csv_path)
    audit_event("RAW_CSV_WRITTEN", {"path": str(csv_path), "rows": int(len(data))})

    # HMAC signature (without a stable env key you can't re-verify later)
    key = load_or_generate_secret_key()
    sig_b64 = hmac_sha256_file(csv_path, key)
    sig_path = run_dir / "driving_data.sig"
    sig_path.write_text(sig_b64, encoding="utf-8")
    set_strict_perms(sig_path)
    print("HMAC-SHA256 signature written to:", sig_path)
    audit_event("RAW_CSV_SIGNED", {"sig_path": str(sig_path)})

    # Immediate self-check
    ok = verify_hmac_file(csv_path, sig_b64, key)
    print("Signature verification:", "VALID ✅" if ok else "INVALID ❌")
    audit_event("RAW_CSV_SIGNED", {"sig_path": str(sig_path)})

    # Privacy export
    public_path = run_dir / "driving_data_public.csv"
    export_privacy_copy(data, public_path)
    set_strict_perms(public_path)
    audit_event("PRIVACY_EXPORT_WRITTEN", {"path": str(public_path)})


# Runs the whole project in a safe, logical order (auth -> simulate -> save/sign -> privacy export -> KPIs -> plots -> audit check)
def main():
    # Ask for a password so only authorized users can run the workflow
    authenticate()
    # Record that authentication succeeded in the tamper-evident audit log
    audit_event("AUTH_OK", {})

    # Create a brand-new random dataset of several trips (city/highway) with speed/acceleration/tilt
    data = simulate_dataset()
    # Log what we generated so we can trace when and how many rows were created
    audit_event("SIMULATED", {"trips": int(data["trip_id"].nunique()), "rows": int(len(data))})

    # Save the raw dataset to CSV and print a SHA-256 fingerprint so future changes are detectable
    csv_path = Path("driving_data.csv")
    save_with_hash(data, csv_path)
    # Lock down the raw CSV so only the current user can read/write it
    set_strict_perms(csv_path)
    # Log that the raw CSV was written and where
    audit_event("RAW_CSV_WRITTEN", {"path": str(csv_path), "rows": int(len(data))})

    # Get a secret signing key (from env if set, otherwise random) and compute an HMAC signature of the CSV
    key = load_or_generate_secret_key()
    sig_b64 = hmac_sha256_file(csv_path, key)
    # Store the signature in a separate file next to the CSV for later verification
    sig_path = Path("driving_data.sig")
    sig_path.write_text(sig_b64, encoding="utf-8")
    # Lock down the signature file for least-privilege access
    set_strict_perms(sig_path)
    # Tell the user where we saved the signature for transparency
    print("HMAC-SHA256 signature written to:", sig_path)
    # Log that the raw CSV was signed (authenticity)
    audit_event("RAW_CSV_SIGNED", {"sig_path": str(sig_path)})

    # Immediately verify the signature to demonstrate authenticity checking
    ok = verify_hmac_file(csv_path, sig_b64, key)
    # Print whether the signature matched so the user sees a quick integrity/auth result
    print("Signature verification:", "VALID ✅" if ok else "INVALID ❌")
    # Log the verification outcome so it’s captured in the audit trail
    audit_event("SIGNATURE_VERIFIED", {"ok": bool(ok)})

    # Create a privacy-safe CSV that hides exact timing and slightly blurs speeds for safe sharing
    public_path = Path("driving_data_public.csv")
    export_privacy_copy(data, public_path)
    # Lock down the privacy export too (still practice less privilege)
    set_strict_perms(public_path)
    # Log that the privacy export was created and where it lives
    audit_event("PRIVACY_EXPORT_WRITTEN", {"path": str(public_path)})

    # Turn the raw signals into useful per-trip KPIs and a simple 0-100 safety score
    summary = trip_kpis_and_score(data)
    # Save the trip summary so it can be viewed or shared internally
    summary_path = Path("driving_data_summary.csv")
    summary.to_csv(summary_path, index=False)
    # Lock down the summary file to prevent unwanted access
    set_strict_perms(summary_path)
    # Log that the KPIs file was written and how many trips it covers
    audit_event("KPIS_WRITTEN", {"path": str(summary_path), "trips": int(len(summary))})
    # Tell the user where the KPIs were saved
    print("Trip KPIs saved:", summary_path)

    # Show plots so we can visually sanity-check speeds, acceleration, and tilt
    plot_speed_dual_units(data)
    plot_series(data, "acceleration", "Acceleration (m/s²)", "Driving Acceleration Over Time")
    plot_series(data, "tilt", "Tilt (degrees)", "Phone Tilt During Driving")
    # Log that we displayed plots for traceability
    audit_event("PLOTS_SHOWN", {"count": 3})

    # Simulate the “ready to send over HTTPS” step to reflect a real secure pipeline
    print("\nSimulating secure transmission over HTTPS...")
    print("Data ready to send securely!")
    # Log that the data is ready for secure transmission
    audit_event("READY_TO_TRANSMIT", {})

    # Recompute the entire hash chain to prove the audit log wasn’t edited
    verify_audit_log()

# Only run main() when this file is executed directly (not when it’s imported by another script)
if __name__ == "__main__":
    main()

