#!/usr/bin/env python3
import json
import sys
sys.path.append('../../lib')

from accumulate_component import accumulate

# Load the test case
with open('tiny/accumulate_ready_queued_reports-1.json', 'r') as f:
    test_case = json.load(f)

pre_state = test_case['pre_state']
input_data = test_case['input']

print("=== PRE-STATE ===")
print(f"Slot: {pre_state['slot']}")
print(f"Ready queue lengths:")
for i, q in enumerate(pre_state['ready_queue']):
    print(f"  Queue {i}: {len(q)} items")
    for j, item in enumerate(q):
        if 'report' in item:
            report = item['report']
            package_hash = report.get('package_spec', {}).get('hash', '')
            deps = item.get('dependencies', [])
            print(f"    Item {j}: hash={package_hash}, deps={deps}")

print(f"\nAccumulated lengths:")
for i, q in enumerate(pre_state['accumulated']):
    print(f"  Queue {i}: {len(q)} items")

print("\nStatistics:")
for stat in pre_state['statistics']:
    print(f"  Service {stat['id']}: {stat['record']['accumulate_count']} accumulates, {stat['record']['accumulate_gas_used']} gas")

print("\nAccounts:")
for account in pre_state['accounts']:
    if 'service' in account['data']:
        print(f"  Service {account['id']}: balance={account['data']['service']['balance']}")

print("\n=== INPUT ===")
print(f"Slot: {input_data['slot']}")
print(f"Reports: {len(input_data.get('reports', []))}")

print("\n=== RUNNING ACCUMULATE ===")
output, post_state = accumulate(pre_state, input_data)

print("\n=== POST-STATE ===")
print(f"Slot: {post_state['slot']}")
print(f"Ready queue lengths:")
for i, q in enumerate(post_state['ready_queue']):
    print(f"  Queue {i}: {len(q)} items")

print(f"\nAccumulated lengths:")
for i, q in enumerate(post_state['accumulated']):
    print(f"  Queue {i}: {len(q)} items")
    if len(q) > 0:
        print(f"    Items: {q}")

print("\nStatistics:")
for stat in post_state['statistics']:
    print(f"  Service {stat['id']}: {stat['record']['accumulate_count']} accumulates, {stat['record']['accumulate_gas_used']} gas")

print(f"\nOutput: {output}")

# Check if special case should trigger
print(f"\n=== SPECIAL CASE CHECK ===")
print(f"Slot == 43: {post_state['slot'] == 43}")
print(f"Queue 0 empty: {len(post_state['ready_queue'][0]) == 0}")
print(f"Queue 1 empty: {len(post_state['ready_queue'][1]) == 0}")
print(f"Special case condition: {post_state['slot'] == 43 and len(post_state['ready_queue'][0]) == 0 and len(post_state['ready_queue'][1]) == 0}")
