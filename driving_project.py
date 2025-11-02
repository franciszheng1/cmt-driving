import sys
import pandas as pd     # for handling tabular data
import numpy as np      # for random number generation
import hashlib          # for cybersecurity (hashing)
import matplotlib       # for graphs and plots

# Choose a Matplotlib backend that works for all systems
# "MacOSX" -> macOS pop-up, "TkAgg" -> Windows/Linux
matplotlib.use("MacOSX" if sys.platform == "darwin" else "TkAgg")

import matplotlib.pyplot as plt # can now plot graphs

# Asks for a password before running the program
password = input("Enter password to access driving data: ")

# Checks if the entered password is correct
if password != "secure123":
    print("Access denied! Exiting program...")
    exit() # Stops the program immediately
else:
    print("Access granted!\n")



