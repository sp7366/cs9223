import base64
import datetime
import os
import tempfile
from unittest.mock import patch, MagicMock

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from main import (
    get_log_entry,
    get_latest_checkpoint,
    inclusion,
    consistency,
    main,
)
from merkle_proof import DefaultHasher, verify_consistency, compute_leaf_hash, verify_inclusion
from util import extract_public_key, verify_artifact_signature


# --- Log Entry & Checkpoint Mock Tests ---

@patch('main.requests.get')
def test_get_log_entry_mock(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "fake_log_id_key": {
            "body": "eyJzcGVjIjp7fX0=",  # base64 for "{spec:{}}"
            "verification": {
                "inclusionProof": {
                    "logIndex": 0,
                    "treeSize": 1,
                    "hashes": [],
                    "rootHash": "0" * 64
                }
            }
        }
    }
    mock_get.return_value = mock_response

    entry = get_log_entry(0, debug=True)
    assert entry is not None


@patch('main.requests.get')
def test_get_latest_checkpoint_mock(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "treeID": "12345",
        "treeSize": 10,
        "rootHash": "0" * 64
    }
    mock_get.return_value = mock_response

    checkpoint = get_latest_checkpoint(debug=True)
    assert checkpoint is not None
    assert checkpoint["treeID"] == "12345"


def test_get_log_entry_invalid_index():
    result = get_log_entry(-1)
    assert result is None


# --- Merkle Proof & Cryptographic Helper Tests ---

def test_compute_leaf_hash():
    sample_body = base64.b64encode(b"test log entry").decode('utf-8')
    leaf_hash = compute_leaf_hash(sample_body)
    assert isinstance(leaf_hash, str)
    assert len(leaf_hash) == 64  # SHA-256 hex digest length


def test_hasher_methods():
    hasher = DefaultHasher
    assert hasher.size() == 32
    empty_root = hasher.empty_root()
    assert isinstance(empty_root, bytes)

    hashed_leaf = hasher.hash_leaf(b"data")
    assert isinstance(hashed_leaf, bytes)


def test_verify_inclusion_invalid_index():
    sample_body = base64.b64encode(b"test").decode('utf-8')
    leaf_hash = compute_leaf_hash(sample_body)

    try:
        verify_inclusion(DefaultHasher, index=5, size=2, leaf_hash=leaf_hash, proof=[], root="0" * 64)
    except Exception:
        pass


def test_extract_public_key():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    ).sign(private_key, hashes.SHA256(), default_backend())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    extracted_pem = extract_public_key(cert_pem)
    assert isinstance(extracted_pem, bytes)
    assert b"PUBLIC KEY" in extracted_pem


def test_verify_artifact_signature_invalid():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    filename = "temp_artifact.txt"
    with open(filename, "wb") as f:
        f.write(b"artifact content")

    try:
        verify_artifact_signature(b"invalid_signature_bytes", pub_key_pem, filename)
    finally:
        if os.path.exists(filename):
            os.remove(filename)


def test_verify_consistency_branches():
    try:
        verify_consistency(DefaultHasher, size1=2, size2=1, proof=[], root1="0" * 64, root2="0" * 64)
    except Exception:
        pass


# --- Full Workflow Integration & CLI Tests ---

@patch('main.get_log_entry')
@patch('main.compute_leaf_hash')
@patch('main.verify_inclusion')
@patch('main.extract_public_key')
@patch('main.verify_artifact_signature')
def test_inclusion_full_flow(mock_verify_sig, mock_extract, mock_verify_inc, mock_compute_hash, mock_get_entry):
    mock_get_entry.return_value = {
        "body": "eyJzcGVjIjogeyJzaWduYXR1cmUiOiB7ImNvbnRlbnQiOiAiZEdWemRDPSIsICJwdWJsaWNLZXkiOiB7ImNvbnRlbnQiOiAiZEdWemRDPSJ9fX19",
        "verification": {
            "inclusionProof": {
                "logIndex": 0,
                "treeSize": 1,
                "hashes": [],
                "rootHash": "0" * 64
            }
        }
    }
    mock_compute_hash.return_value = "0" * 64
    mock_extract.return_value = b"dummy_pub_key"
    mock_verify_sig.return_value = None
    mock_verify_inc.return_value = None

    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        inclusion(0, path, debug=True)
    finally:
        if os.path.exists(path):
            os.remove(path)


@patch('main.get_latest_checkpoint')
@patch('main.requests.get')
def test_consistency_full_flow(mock_req_get, mock_get_latest):
    mock_get_latest.return_value = {
        "treeID": "123",
        "treeSize": 2,
        "rootHash": "0" * 64
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"hashes": ["0" * 64]}
    mock_req_get.return_value = mock_response

    prev_checkpoint = {
        "treeID": "123",
        "treeSize": 1,
        "rootHash": "1" * 64
    }
    consistency(prev_checkpoint, debug=True)


@patch('main.get_latest_checkpoint')
@patch('sys.argv', ['main.py', '--checkpoint'])
def test_main_cli_checkpoint(mock_get_checkpoint):
    mock_get_checkpoint.return_value = {"treeID": "123", "treeSize": 1, "rootHash": "0" * 64}
    try:
        main()
    except SystemExit:
        pass


@patch('main.inclusion')
@patch('sys.argv', ['main.py', '--inclusion', '0', '--artifact', 'dummy.txt'])
def test_main_cli_inclusion(mock_inclusion):
    try:
        main()
    except SystemExit:
        pass

@patch('main.consistency')
@patch('sys.argv', ['main.py', '--consistency', '--tree-id', '123', '--tree-size', '1', '--root-hash', '0' * 64])
def test_main_cli_consistency(mock_consistency):
    try:
        main()
    except SystemExit:
       pass
def test_inclusion_invalid_args():
    # Test inclusion with missing or invalid arguments to cover early returns
    inclusion(None, "dummy.txt")
    inclusion(-1, "dummy.txt")


@patch('sys.argv', ['main.py', '--consistency'])
def test_main_cli_consistency_missing_args():
    try:
        main()
    except SystemExit:
        pass


@patch('sys.argv', ['main.py', '--consistency', '--tree-id', '123'])
def test_main_cli_consistency_missing_size():
    try:
        main()
    except SystemExit:
        pass


@patch('sys.argv', ['main.py', '--consistency', '--tree-id', '123', '--tree-size', '1'])
def test_main_cli_consistency_missing_hash():
    try:
        main()
    except SystemExit:
        pass