import argparse  # ADDED: The template forgot this import!
import requests
import json
import base64
import util
import merkle_proof

from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash
REKOR_SERVER = "https://rekor.sigstore.dev"

def get_log_entry(log_index, debug=False):
    # verify that log index value is sane
    if not log_index or log_index < 0:
        return None

    url = f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}"
    response = requests.get(url)
    entry_data = response.json()

    # Extract the entry using the dynamic log ID key
    log_id = list(entry_data.keys())[0]
    return entry_data[log_id]


def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    if not log_index or log_index < 0:
        return None

    log_entry = get_log_entry(log_index, debug)
    return log_entry['verification']['inclusionProof']


def inclusion(log_index, artifact_filepath, debug=False):
    if not log_index or not artifact_filepath:
        print("Invalid log index or artifact filepath")
        return

    try:
        log_entry = get_log_entry(log_index, debug)

        decoded_body = base64.b64decode(log_entry['body']).decode('utf-8')
        body_json = json.loads(decoded_body)

        spec = body_json.get('spec', {})
        if 'signature' in spec:
            b64_signature = spec['signature']['content']
            b64_certificate = spec['signature']['publicKey']['content']
        elif 'signatures' in spec:
            b64_signature = spec['signatures'][0]['signature']
            b64_certificate = spec['signatures'][0]['verifier']
        else:
            raise KeyError("Could not find signature in log entry spec.")

        signature = base64.b64decode(b64_signature)
        certificate = base64.b64decode(b64_certificate)

        public_key = extract_public_key(certificate)

        # 1. Safely verify signature (catch exceptions since util.py doesn't return bool)
        is_valid_sig = False
        try:
            verify_artifact_signature(signature, public_key, artifact_filepath)
            is_valid_sig = True
        except Exception:
            is_valid_sig = False

        proof = get_verification_proof(log_index, debug)
        leaf_hash = compute_leaf_hash(log_entry['body'])

        # 2. Safely verify inclusion (catch exceptions since merkle_proof.py doesn't return bool)
        is_included = False
        try:
            verify_inclusion(
                DefaultHasher,
                proof['logIndex'],
                proof['treeSize'],
                leaf_hash,
                proof['hashes'],
                proof['rootHash']
            )
            is_included = True
        except Exception:
            is_included = False

        if is_valid_sig and is_included:
            print("Offline verification successful")
        else:
            print("Offline verification failed")

    except Exception as e:
        import traceback
        traceback.print_exc()


def get_latest_checkpoint(debug=False):
    """
    Fetches the latest checkpoint (Signed Tree Head) from the Rekor transparency log.
    """
    url = f"{REKOR_SERVER}/api/v1/log"
    try:
        response = requests.get(url)
        response.raise_for_status()
        checkpoint_data = response.json()

        if debug:
            print("[DEBUG] Fetched latest checkpoint successfully:")
            print(json.dumps(checkpoint_data, indent=2))
            with open("checkpoint.json", "w") as f:
                json.dump(checkpoint_data, f, indent=2)

        return checkpoint_data
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch latest checkpoint: {e}")
        return None


def consistency(prev_checkpoint, debug=False):
    tree_id = prev_checkpoint.get("treeID")
    prev_size = prev_checkpoint.get("treeSize")
    prev_hash = prev_checkpoint.get("rootHash")

    print("[INFO] Fetching latest checkpoint for consistency check...")
    latest_checkpoint = get_latest_checkpoint(debug=debug)

    if not latest_checkpoint:
        print("[ERROR] Could not retrieve the latest checkpoint.")
        return

    curr_size = latest_checkpoint.get("treeSize")
    curr_hash = latest_checkpoint.get("rootHash")

    print(f"[INFO] Verifying consistency from tree size {prev_size} to {curr_size}...")

    proof_url = f"{REKOR_SERVER}/api/v1/log/proof?firstSize={prev_size}&lastSize={curr_size}&treeID={tree_id}"

    try:
        response = requests.get(proof_url)
        response.raise_for_status()
        proof_data = response.json()

        proof_hashes = proof_data.get('hashes', [])

        is_consistent = False
        try:
            # EXPLICITLY matching the template's required order:
            # hasher, size1, size2, proof, root1, root2
            verify_consistency(
                DefaultHasher,
                prev_size,
                curr_size,
                proof_hashes,
                prev_hash,
                curr_hash
            )
            is_consistent = True
        except Exception as e:
            is_consistent = False
            if debug:
                print(f"[DEBUG] Exception in verify_consistency: {e}")

        if is_consistent:
            print("Consistency verification successful")
        else:
            print("Consistency verification failed")

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch consistency proof: {e}")

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
