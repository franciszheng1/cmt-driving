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
    if trip_type = 'city':
        # This is because city driving is slower and more variable
        # np.random.normal(mean, std, size) creates random numbers around a mean


