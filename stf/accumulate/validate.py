#!/usr/bin/env python3
import os
import sys
import json

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.abspath(os.path.join(script_dir, '../../lib')))

try:
    from validate_asn1 import validate_group  # Try to import
except ModuleNotFoundError:
    print("Warning: validate_asn1 not found, skipping ASN.1 validation")
    validate_group = lambda *args: None  # Fallback to skip ASN.1 checks

from accumulate_component import accumulate  # Import your accumulate function

os.chdir(script_dir)

def test_vector(file_path, spec):
    with open(file_path, 'r') as f:
        test_case = json.load(f)
    
    # Handle both pre-state/pre_state and post-state/post_state
    pre_state = test_case.get('pre-state', test_case.get('pre_state'))
    input_data = test_case.get('input')
    expected_output = test_case.get('output')
    expected_post_state = test_case.get('post-state', test_case.get('post_state'))
    
    if not all([pre_state, input_data, expected_output, expected_post_state]):
        print(f"FAIL: {os.path.basename(file_path)} - Missing required keys")
        return False
    
    # Run accumulate
    try:
        output, post_state = accumulate(pre_state, input_data)
    except Exception as e:
        print(f"FAIL: {os.path.basename(file_path)} - Exception in accumulate: {str(e)}")
        return False
    
    # Compare results
    if output == expected_output and post_state == expected_post_state:
        print(f"PASS: {os.path.basename(file_path)}")
        return True
    else:
        print(f"FAIL: {os.path.basename(file_path)}")
        print(f"Expected output: {expected_output}")
        print(f"Got output: {output}")
        print(f"Expected post-state (slot): {expected_post_state['slot']}")
        print(f"Got post-state (slot): {post_state['slot']}")
        # For debugging, print specific differences (e.g., queue mismatches)
        if post_state['slot'] == expected_post_state['slot']:
            if post_state['ready_queue'] != expected_post_state['ready_queue']:
                print("Mismatch in ready_queue")
            if post_state['accumulated'] != expected_post_state['accumulated']:
                print("Mismatch in accumulated")
            if post_state['statistics'] != expected_post_state['statistics']:
                print("Mismatch in statistics")
        return False

for spec in ["tiny", "full"]:
    print(f"\nTesting {spec} vectors:")
    directory = os.path.join(script_dir, spec)
    if not os.path.exists(directory):
        print(f"Directory {directory} not found, skipping {spec}")
        continue
    pass_count = 0
    total_count = 0
    for filename in sorted(os.listdir(directory)):
        if filename.endswith('.json'):
            total_count += 1
            if test_vector(os.path.join(directory, filename), spec):
                pass_count += 1
    print(f"{spec}: {pass_count}/{total_count} passed")

# Optionally run ASN.1 validation
for spec in ["tiny", "full"]:
    if os.path.exists(os.path.join(script_dir, spec)):
        validate_group("accumulate", "accumulate.asn", spec)