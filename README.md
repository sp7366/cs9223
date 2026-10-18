# Python Rekor Transparency Log Monitor

A command-line tool designed to query, monitor, and verify entries against the Rekor transparency log, providing cryptographic verification of inclusion proofs, consistency proofs, and artifact signatures.

---

## Features

- **Log Entry Retrieval & Verification**: Fetch and inspect log entries by index from Rekor[cite: 1].
- **Merkle Proof Verification**: Verify inclusion and consistency proofs using local cryptographic hash helpers[cite: 1].
- **Artifact Signature Verification**: Extract public keys from certificates and validate digital signatures against signed artifacts[cite: 1].
- **Automated Testing & Coverage**: Fully tested using `pytest` and `pytest-cov` exceeding 75% test coverage.

---

## Installation & Setup

This project uses [Poetry](https://python-poetry.org/) for dependency management and packaging[cite: 2, 3].

1. **Clone the repository**:
   ```bash
   git clone [https://github.com/sp7366/cs9223.git](https://github.com/sp7366/cs9223.git)
   cd cs9223
2. Install dependencies: poetry install
4. Activate the virtual environment: poetry shell
5. Fetch Checkpoints: python main.py --checkpoint
6. Verify Inclusion Proofs: python main.py --inclusion <LOG_INDEX> --artifact <PATH_TO_ARTIFACT>
7. Check Consistency: python main.py --consistency --tree-id <TREE_ID> --tree-size <TREE_SIZE> --root-hash <ROOT_HASH>

**Development & Testing
Running Tests & Coverage**

1. To run the test suite and verify that test coverage meets or exceeds the required threshold ($\ge 75\%$): PYTHONPATH=. poetry run pytest --cov=. --cov-report=term

**Static Analysis Tools**
1. Linter (ruff): ruff check -o ruff.final.txt
2. Type Checker (mypy): mypy --install-types; mypy main.py merkle_proof.py util.py > mypy.final.txt;
3. Security Scanner (Bandit): bandit -r -o bandit-final.txt -f txt

License
Licensed under the MIT License. See the LICENSE file for details.
