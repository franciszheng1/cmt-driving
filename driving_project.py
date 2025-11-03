import sys                      # for detecting operating system and exit
import pandas as pd             # for handling tabular data
import numpy as np              # for random number generation
import hashlib                  # for cybersecurity (hashing)
import matplotlib               # for graphs and plots
from pathlib import Path        # for path files
from getpass import getpass     # for hidden password input (no echo)

# Choose a Matplotlib backend that works for all systems
# "MacOSX" -> macOS pop-up, "TkAgg" -> Windows/Linux
matplotlib.use("MacOSX" if sys.platform == "darwin" else "TkAgg")

# Import pyplot after choosing the backend
import matplotlib.pyplot as plt

# Constants for unit conversions and thresholds
KMH_TO_MPH = 0.621371
HIGH_KMH = 120 # km/h threshold
HIGH_MPH = 75 # mph threshold (approximately 120 km/h)

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
def simulate_trip(trip_type = 'city', min_seconds=30, max_seconds=180):
    # Chooses a random trip length (between 30-180 seconds)
    duration = np.random.randint(min_seconds, max_seconds)

    # Create a time column: 0, 1, 2, ... up to duration
    time = np.arange(duration)

    # Depending on the type of trip, generate different driving patterns
    if trip_type == 'city': # use == for comparison
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
        'time': time,                   # seconds within this trip
        'trip_type': trip_type,         # 'city' or 'highway'
        'speed_kmh': speed_kmh,         # speed in km/h
        'speed_mph': speed_mph,         # speed in mph
        'acceleration': acceleration,
        'tilt': tilt,
    })

# Build a dataset of random trips
def simulate_dataset():
    # New randomness for every run
    np.random.seed(None)

    # Pick a random number of trips: 2..5
    n_trips = int(np.random.randint(2, 6))

    trips = []
    for trip_id in range(1, n_trips + 1):
        # Choose trip type randomly each time (50/50 city vs highway)
        trip_type = np.random.choice(['city', 'highway'])

        # Make one trip
        trip = simulate_trip(trip_type)

        # Tap which trip each row belongs to (1..n_trips)
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
    data['global_time'] = data['time'] + data['trip_id'].map(offset_map)

    return data


# Calculates and returns the SHA_256 hash (fingerprint) of a file for integrity verification
def sha256_file(path: Path) -> str:
    # Create a new SHA-256 hashing object
    h = hashlib.sha256()

    # Open the file in binary mode, so we can read raw bytes
    with open(path, 'rb') as f:
        # Read the file in chunks of 8 KB (8192 bytes)
        # This prevents memory issues for large files
        for chunk in iter(lambda: f.read(8192), b''):
            # Update the hash with each chunk of data
            h.update(chunk)

    # Return the final hash as a 64-character hexadecimal string
    return h.hexdigest()

