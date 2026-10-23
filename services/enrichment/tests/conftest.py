import os
import sys

# enrich.py sits one folder up; pytest.ini adds it to the path, this is the
# belt-and-braces version for running a single file from another directory.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
