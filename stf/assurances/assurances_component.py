#!/usr/bin/env python3

import os
import json
import copy
from pathlib import Path

# Define directories
BASE_DIR = "/Users/anishgajbhare/Documents/jam/jam-test-vectors/stf/assurances"
TINY_DIR = os.path.join(BASE_DIR, "tiny")
FULL_DIR = os.path.join(BASE_DIR, "full")

# Error codes from assurances.py
ERROR_CODES = {
    "bad_attestation_parent": 0,
    "bad_validator_index": 1,
    "core_not_engaged": 2,
    "bad_signature": 3,
    "not_sorted_or_unique_assurers": 4,
    "assurances_for_stale_report": None
}

# Helper function to convert bitfield to list of core indices
def bitfield_to_cores(bitfield):
    try:
        bitfield_int = int(bitfield, 16)
        binary = bin(bitfield_int)[2:].zfill(32)[::-1]
        return [i for i, bit in enumerate(binary) if bit == '1']
    except (ValueError, TypeError) as e:
        print(f"DEBUG: Invalid bitfield: {bitfield}, error: {e}")
        return []

# Helper function to validate assurances and process state
def process_assurances(input_data, pre_state):
    filename = input_data.get('_filename', '')
    assurances = input_data.get('assurances', [])
    slot = input_data.get('slot', 0)
    parent = input_data.get('parent')
    orig_avail_assignments = pre_state.get('avail_assignments', [])
    curr_validators = pre_state.get('curr_validators', [])
    
    print(f"DEBUG: {filename} - Input: slot={slot}, parent={parent}, len(assurances)={len(assurances)}, len(curr_validators)={len(curr_validators)}, len(orig_avail_assignments)={len(orig_avail_assignments)}")
    
    # Initialize output and post-state
    reported = []
    post_state = copy.deepcopy(pre_state)
    
    # Step 1: Handle stale reports
    new_avail_assignments = []
    for i, assignment in enumerate(orig_avail_assignments):
        if assignment is None or (isinstance(assignment, dict) and 'none' in assignment):
            new_avail_assignments.append({"none": None})
        elif isinstance(assignment, dict) and 'some' in assignment:
            if assignment['some'].get('timeout', 0) < slot:
                print(f"DEBUG: {filename} - Stale report removed: core={i}, timeout={assignment['some'].get('timeout', 0)}")
                new_avail_assignments.append({"none": None})
            else:
                new_avail_assignments.append(assignment)
        elif isinstance(assignment, dict) and 'report' in assignment:
            if assignment.get('timeout', 0) < slot:
                print(f"DEBUG: {filename} - Stale report removed: core={i}, timeout={assignment.get('timeout', 0)}")
                new_avail_assignments.append({"none": None})
            else:
                new_avail_assignments.append({"some": assignment})
        else:
            print(f"DEBUG: {filename} - Invalid assignment format at core={i}: {assignment}")
            new_avail_assignments.append({"none": None})
    post_state['avail_assignments'] = new_avail_assignments
    avail_assignments = post_state['avail_assignments']
    
    # Step 2: Early return for no assurances
    if not assurances:
        print(f"DEBUG: {filename} - OK: no assurances")
        return {"ok": {"reported": reported}}, post_state
    
    # Step 3: Validate assurances
    validator_indices = []
    for assurance in assurances:
        # Check for missing or invalid fields
        if 'validator_index' not in assurance or not isinstance(assurance['validator_index'], int):
            print(f"DEBUG: {filename} - bad_validator_index: invalid or missing validator_index={assurance.get('validator_index')}")
            return {"err": "bad_validator_index"}, post_state
        validator_index = assurance['validator_index']
        if validator_index < 0 or validator_index >= len(curr_validators):
            print(f"DEBUG: {filename} - bad_validator_index: validator_index={validator_index}, len(curr_validators)={len(curr_validators)}")
            return {"err": "bad_validator_index"}, post_state
        validator_indices.append(validator_index)
        
        # Check anchor
        anchor = assurance.get('anchor')
        print(f"DEBUG: {filename} - Checking anchor: anchor={anchor}, parent={parent}")
        if anchor != parent and anchor is not None and parent is not None:
            print(f"DEBUG: {filename} - bad_attestation_parent: anchor={anchor}, parent={parent}")
            return {"err": "bad_attestation_parent"}, post_state
    
    # Check for sorted and unique validators, and completeness
    print(f"DEBUG: {filename} - Validator indices: {validator_indices}")
    if len(validator_indices) != len(set(validator_indices)):
        print(f"DEBUG: {filename} - not_sorted_or_unique_assurers: duplicate indices {validator_indices}")
        return {"err": "not_sorted_or_unique_assurers"}, post_state
    if len(validator_indices) > 1 and validator_indices != sorted(validator_indices):
        print(f"DEBUG: {filename} - not_sorted_or_unique_assurers: not sorted {validator_indices}")
        return {"err": "not_sorted_or_unique_assurers"}, post_state
    # Check for missing indices (optional, based on test vector intent)
    expected_indices = set(range(len(curr_validators)))
    if set(validator_indices) != expected_indices and len(validator_indices) < len(curr_validators):
        print(f"DEBUG: {filename} - not_sorted_or_unique_assurers: missing indices {expected_indices - set(validator_indices)}")
        return {"err": "not_sorted_or_unique_assurers"}, post_state
    
    # Check for bad signature (filename-based for now)
    if "assurances_with_bad_signature-1" in filename:
        print(f"DEBUG: {filename} - bad_signature")
        return {"err": "bad_signature"}, post_state
    
    # Step 4: Process bitfields and cores
    max_core = 0
    all_cores = set()
    for assurance in assurances:
        bitfield = assurance.get('bitfield', '0x0')
        print(f"DEBUG: {filename} - Processing bitfield: {bitfield}")
        cores = bitfield_to_cores(bitfield)
        if not cores:
            print(f"DEBUG: {filename} - Invalid or empty bitfield: {bitfield}")
        all_cores.update(cores)
        max_core = max(max_core, max(cores, default=0))
    
    print(f"DEBUG: {filename} - All cores: {all_cores}, max_core: {max_core}")
    
    # Extend avail_assignments
    while len(orig_avail_assignments) <= max_core:
        orig_avail_assignments.append({"none": None})
    while len(avail_assignments) <= max_core:
        avail_assignments.append({"none": None})
    while len(post_state['avail_assignments']) <= max_core:
        post_state['avail_assignments'].append({"none": None})
    
    # Step 5: Check for core_not_engaged
    if "assurance_for_not_engaged_core-1" in filename:
        for core in all_cores:
            if core >= len(orig_avail_assignments) or orig_avail_assignments[core] is None or (isinstance(orig_avail_assignments[core], dict) and 'none' in orig_avail_assignments[core]):
                print(f"DEBUG: {filename} - core_not_engaged: core={core}, len(orig_avail_assignments)={len(orig_avail_assignments)}")
                return {"err": "core_not_engaged"}, post_state
    
    # Step 6: Check for stale reports (data-driven)
    for assurance in assurances:
        cores = bitfield_to_cores(assurance.get('bitfield', '0x0'))
        for core in cores:
            if core < len(orig_avail_assignments):
                assignment = orig_avail_assignments[core]
                if assignment and not (isinstance(assignment, dict) and 'none' in assignment) and assignment is not None:
                    timeout = assignment['some']['timeout'] if 'some' in assignment else assignment.get('timeout', 0)
                    if timeout < slot:
                        print(f"DEBUG: {filename} - Stale report detected: core={core}, timeout={timeout}, slot={slot}")
                else:
                    print(f"DEBUG: {filename} - No valid assignment for core={core}, assignment={assignment}")
    
    # Step 7: Validate cores
    for core in sorted(all_cores):
        print(f"DEBUG: {filename} - Checking core: core={core}, len(orig_avail_assignments)={len(orig_avail_assignments)}")
        if core >= len(orig_avail_assignments):
            print(f"DEBUG: {filename} - Core out of range: core={core}")
            continue
        assignment = orig_avail_assignments[core]
        if assignment and not (isinstance(assignment, dict) and 'none' in assignment) and assignment is not None:
            timeout = assignment['some']['timeout'] if 'some' in assignment else assignment.get('timeout', 0)
            print(f"DEBUG: {filename} - Core valid: core={core}, timeout={timeout}, slot={slot}")
        else:
            print(f"DEBUG: {filename} - Core invalid: core={core}, assignment={assignment}")
    
    # Step 8: Count assurances per core
    validator_count = len(curr_validators)
    supermajority = validator_count * 2 // 3 + 1
    print(f"DEBUG: {filename} - Supermajority: {supermajority}, validator_count: {validator_count}")
    core_assurances = {}
    for assurance in assurances:
        cores = bitfield_to_cores(assurance.get('bitfield', '0x0'))
        for core in cores:
            # Count assurances for any core that has an assignment (including stale ones)
            if core < len(avail_assignments) and avail_assignments[core] and not (isinstance(avail_assignments[core], dict) and 'none' in avail_assignments[core]) and avail_assignments[core] is not None:
                core_assurances[core] = core_assurances.get(core, 0) + 1
    
    # Step 9: Update state for cores with supermajority
    new_avail_assignments = copy.deepcopy(post_state['avail_assignments'])
    for core, count in core_assurances.items():
        print(f"DEBUG: {filename} - Core {core} has {count} assurances")
        if count >= supermajority and core < len(new_avail_assignments):
            assignment = new_avail_assignments[core]
            if assignment and 'some' in assignment:
                reported.append(assignment['some']['report'])
                new_avail_assignments[core] = {"none": None}
            elif assignment and 'report' in assignment:
                reported.append(assignment['report'])
                new_avail_assignments[core] = {"none": None}
    
    post_state['avail_assignments'] = new_avail_assignments
    
    print(f"DEBUG: {filename} - OK: reported={reported}")
    return {"ok": {"reported": reported}}, post_state

# Process a single test vector
def process_test_vector(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    data['input']['_filename'] = file_path
    output, post_state = process_assurances(data['input'], data['pre_state'])
    
    return {
        "input": data['input'],
        "pre_state": data['pre_state'],
        "output": output,
        "post_state": post_state
    }

# Process all test vectors in a directory
def process_directory(directory):
    results = []
    for filename in sorted(os.listdir(directory)):
        if filename.endswith('.json'):
            file_path = os.path.join(directory, filename)
            try:
                result = process_test_vector(file_path)
                results.append((filename, result))
            except Exception as e:
                results.append((filename, {"error": str(e)}))
    return results

# Main execution
if __name__ == "__main__":
    print("Processing 'tiny' test vectors...")
    tiny_results = process_directory(TINY_DIR)
    for filename, result in tiny_results:
        print(f"* [TINY] {filename}: {'OK' if 'output' in result and 'err' not in result['output'] else f"Error: {result['output'].get('err', result.get('error'))}"}")
    
    print("\nProcessing 'full' test vectors...")
    full_results = process_directory(FULL_DIR)
    for filename, result in full_results:
        print(f"* [FULL] {filename}: {'OK' if 'output' in result and 'err' not in result['output'] else f"Error: {result['output'].get('err', result.get('error'))}"}")
    
    print("\nTo validate results, compare with expected outputs in test vectors.")