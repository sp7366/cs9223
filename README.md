# Python Rekor Transparency Log Monitor

A command-line tool designed to query, monitor, and verify entries against the Rekor transparency log, providing cryptographic verification of inclusion proofs, consistency proofs, and artifact signatures.

---

## Features

- **Log Entry Retrieval & Verification**: Fetch and inspect log entries by index from Rekor.
- **Merkle Proof Verification**: Verify inclusion and consistency proofs using local cryptographic hash helpers.
- **Artifact Signature Verification**: Extract public keys from certificates and validate digital signatures against signed artifacts.
- **Automated Testing & Coverage**: Fully tested using `pytest` and `pytest-cov` exceeding 75% test coverage.

---

## Installation & Setup

This project uses [Poetry](https://python-poetry.org/) for dependency management and packaging[cite: 2, 3].

1. **Clone the repository**:
   ```bash
   git clone [https://github.com/sp7366/cs9223.git](https://github.com/sp7366/cs9223.git)
   cd cs9223
Install dependencies using Poetry:Bash poetry install
Activate the virtual environment:Bash poetry shell
Usage
You can run the application directly via Python or through Poetry using CLI flags.
1. Fetching a Checkpoint Bash python main.py --checkpoint
2. Verifying Inclusion Proofs Bash python main.py --inclusion <LOG_INDEX> --artifact <PATH_TO_ARTIFACT>
3. Checking Consistency Bash python main.py --consistency --tree-id <TREE_ID> --tree-size <TREE_SIZE> --root-hash <ROOT_HASH>
Development & Testing
Running Tests
To run the test suite and generate a terminal coverage report:
4. Bash PYTHONPATH=. poetry run pytest --cov=. --cov-report=term
Static Analysis
5. Linter (ruff):Bash ruff check -o ruff.initial.txt
6. Type Checker (mypy):Bash mypy main.py merkle_proof.py util.py > mypy.final.txt
7. Security Scanner (bandit):Bash bandit -r -o bandit-final.txt -f txt
Contributing
Please read CONTRIBUTING.md for details on our code of conduct, and the process for submitting pull requests.   
License
This project is licensed under the terms of the MIT License. See the LICENSE file for details.