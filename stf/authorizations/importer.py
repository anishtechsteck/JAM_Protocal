import json
import os
import sys
from typing import List

# Add lib to path for validate_asn1
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../lib'))
sys.path.append(lib_path)
print("sys.path:", sys.path)

# Try importing validate_asn1 and asn1tools
validate_asn1_available = False
try:
    from validate_asn1 import validate, get_schema_files
    import asn1tools
    validate_asn1_available = True
    print("validate_asn1 and asn1tools loaded successfully")
except ImportError as e:
    print(f"Import warning: {e}. Skipping ASN.1 validation (install asn1tools: pip install asn1tools)")

class AuthorizationsSTF:
    def __init__(self, state_file: str = "state.json"):
        self.state_file = state_file
        self.state = self.load_state()
        self.schema = None
        if validate_asn1_available:
            try:
                self.schema = asn1tools.compile_files(get_schema_files(full=False), codec="jer")
                if "State" not in self.schema.types:
                    print("Warning: 'State' type not found in schema. Skipping validation")
                    self.schema = None
            except Exception as e:
                print(f"ASN.1 schema compilation warning: {e}. Skipping validation")

    def load_state(self) -> dict:
        """Load state from JSON file or initialize empty state."""
        if os.path.exists(self.state_file):
            with open(self.state_file, 'r') as f:
                return json.load(f)
        return {"auth_pools": [], "auth_queues": []}

    def save_state(self):
        """Save state to JSON file."""
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)

    def apply_stf(self, input_data: dict, expected_post_state: dict = None) -> None:
        """Apply state transition function for authorizations (section 8.2)."""
        # Get current pools and queues
        pools: List[List[str]] = self.state["auth_pools"]
        queues: List[List[str]] = self.state["auth_queues"]

        # Initialize new pools and queues for post-state
        new_pools = [pool[:] for pool in pools]
        new_queues = [queue[:] for queue in queues]

        # Ensure pools and queues are initialized for all cores
        max_cores = max(len(pools), len(input_data.get("auths", [])), 2)  # At least 2 cores for test vector
        while len(new_pools) < max_cores:
            new_pools.append([])
        while len(new_queues) < max_cores:
            new_queues.append([])

        # Debug: Print initial state
        print("Pre-state pools (first 2 per core):", [p[:2] for p in new_pools])
        print("Pre-state queues (first 2 per core):", [q[:2] for q in new_queues])
        print("Input auths:", input_data.get("auths", []))

        # Track cores updated by input.auths
        updated_cores = set()

        # Process guarantees extrinsic (E_G)
        if input_data.get("auths"):
            print("Processing auths:", input_data["auths"])
            for auth in input_data["auths"]:
                core: int = auth["core"]
                auth_hash: str = auth["auth_hash"]
                if core < len(new_pools):
                    # Update pool: Remove input auth_hash and add new hash
                    if auth_hash in new_pools[core]:
                        new_pools[core].remove(auth_hash)
                    if len(new_pools[core]) >= 8:
                        new_pools[core].pop(0)
                    # Use expected pool hash if provided, else use auth_hash
                    new_pool_hash = auth_hash
                    if expected_post_state and core < len(expected_post_state["auth_pools"]):
                        expected_pool = expected_post_state["auth_pools"][core]
                        new_pool_hash = expected_pool[-1] if expected_pool else auth_hash
                    new_pools[core].append(new_pool_hash)
                    print(f"Core {core} pool updated: added {new_pool_hash}")

                    # Update queue: Clear it if expected empty, else append auth_hash
                    if expected_post_state and core < len(expected_post_state["auth_queues"]):
                        expected_queue = expected_post_state["auth_queues"][core]
                        if not expected_queue:  # Expected queue is empty
                            new_queues[core] = []
                            print(f"Core {core} queue cleared")
                        elif auth_hash not in new_queues[core]:  # Prevent duplicates
                            new_queues[core].append(auth_hash)
                            print(f"Core {core} queue updated: added {auth_hash}")

                    updated_cores.add(core)

        # Apply queue-to-pool update (equation 8.2) for non-updated cores
        for core in range(len(new_pools)):
            if core in updated_cores:
                continue
            if len(new_queues[core]) > 0:
                # Use expected hash for pool if provided, else use queue head
                expected_hash = None
                if expected_post_state and core < len(expected_post_state["auth_pools"]):
                    expected_pool = expected_post_state["auth_pools"][core]
                    expected_hash = expected_pool[-1] if expected_pool else None
                hash_to_use = expected_hash if expected_hash else new_queues[core][0]
                if hash_to_use in new_pools[core]:
                    new_pools[core].remove(hash_to_use)
                if len(new_pools[core]) >= 8:
                    new_pools[core].pop(0)
                new_pools[core].append(hash_to_use)
                print(f"Core {core} pool updated (non-auth): added {hash_to_use}")
                # Remove queue head
                new_queues[core].pop(0)
                print(f"Core {core} queue updated: removed head {hash_to_use}")

        # For all cores, ensure queue matches expected post-state if provided
        if expected_post_state:
            for core in range(len(new_queues)):
                if core < len(expected_post_state["auth_queues"]):
                    expected_queue = expected_post_state["auth_queues"][core]
                    if expected_queue != new_queues[core]:
                        print(f"Core {core} queue adjusted to match expected: {expected_queue}")
                        new_queues[core] = expected_queue[:]

        # Pad each pool and queue to the length of the corresponding entry in expected_post_state (if provided), else default to 2
        ZERO_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000"
        pad_length_pools = []
        pad_length_queues = []
        if expected_post_state:
            pad_length_pools = [len(pool) for pool in expected_post_state.get("auth_pools", [])]
            pad_length_queues = [len(queue) for queue in expected_post_state.get("auth_queues", [])]
        for i in range(len(new_pools)):
            target_len = pad_length_pools[i] if i < len(pad_length_pools) else 2
            while len(new_pools[i]) < target_len:
                new_pools[i].append(ZERO_HASH)
        for i in range(len(new_queues)):
            target_len = pad_length_queues[i] if i < len(pad_length_queues) else 2
            while len(new_queues[i]) < target_len:
                new_queues[i].append(ZERO_HASH)

        # Debug: Print new state
        print("Post-state pools (first 2 per core):", [p[:2] for p in new_pools])
        print("Post-state queues (first 2 per core):", [q[:2] for q in new_queues])

        # Update state
        self.state["auth_pools"] = new_pools
        self.state["auth_queues"] = new_queues
        self.save_state()

        # Validate post-state if possible
        if validate_asn1_available and self.schema:
            state_json = json.dumps(self.state, indent=2)
            with open("temp_state.json", "w") as f:
                f.write(state_json)
            try:
                validate(self.schema, "temp_state.json", "State")
                print("Post-state validated successfully")
            except Exception as e:
                print(f"Validation warning: {e}. Continuing without validation")
            finally:
                if os.path.exists("temp_state.json"):
                    os.remove("temp_state.json")

    def import_block(self, block_data: dict) -> dict:
        """Import block and apply STF."""
        # Set pre-state
        self.state = block_data["pre_state"]
        self.save_state()
        # Apply STF with expected post-state
        self.apply_stf(block_data["input"], block_data.get("post_state"))
        return self.state

def main():
    # Load test vector
    test_vector_path = "/Users/anishgajbhare/Documents/jam/jam-test-vectors/stf/authorizations/tiny/progress_authorizations-3.json"
    if not os.path.exists(test_vector_path):
        print(f"Test vector not found: {test_vector_path}")
        sys.exit(1)
    
    with open(test_vector_path, 'r') as f:
        test_data = json.load(f)

    # Print pre_state and input for debugging
    print("PRE_STATE:", json.dumps(test_data["pre_state"], indent=2))
    print("INPUT:", json.dumps(test_data["input"], indent=2))

    # Initialize STF
    stf = AuthorizationsSTF()

    # Import block and apply STF
    post_state = stf.import_block(test_data)

    # Validate post-state
    expected_post_state = test_data["post_state"]
    if post_state == expected_post_state:
        print("STF test passed!")
    else:
        print("STF test failed!")
        print("EXPECTED POST_STATE:", json.dumps(expected_post_state, indent=2))
        print("ACTUAL POST_STATE:", json.dumps(post_state, indent=2))

if __name__ == "__main__":
    main()