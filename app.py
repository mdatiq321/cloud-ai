import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from report_generator import generate_report

if __name__ == "__main__":
    print("Cloud Security System Running...\n")
    generate_report()