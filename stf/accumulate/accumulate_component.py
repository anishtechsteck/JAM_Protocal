import copy
from hashlib import sha3_256

def bytes_from_hex(h):
    return bytes.fromhex(h[2:])

def merkle_root(hashes):
    if not hashes:
        return "0x0000000000000000000000000000000000000000000000000000000000000000"
    leaves = [sha3_256(bytes_from_hex(h)).digest() for h in hashes]
    while len(leaves) > 1:
        new_leaves = []
        for i in range(0, len(leaves), 2):
            left = leaves[i]
            right = left if i + 1 == len(leaves) else leaves[i + 1]
            combined = left + right if left < right else right + left
            new_leaves.append(sha3_256(combined).digest())
        leaves = new_leaves
    return "0x" + leaves[0].hex()

def accumulate(pre_state, input):
    post_state = copy.deepcopy(pre_state)
    post_state['slot'] = input['slot']

    # Use modulo indexing for queues
    queue_length = len(post_state['ready_queue'])
    current_index = input['slot'] % queue_length
    current_ready = post_state['ready_queue'][current_index]
    current_accumulated = post_state['accumulated'][current_index]

    # Collect all accumulated package hashes
    accumulated_hashes = set()
    for q in post_state['accumulated']:
        accumulated_hashes.update(q)

    # Process new reports
    for report in input.get('reports', []):
        unsolved = set(report.get('context', {}).get('prerequisites', []))
        if report.get('segment_root_lookup'):
            unsolved.update(item.get('hash', '') for item in report['segment_root_lookup'] if isinstance(item, dict))
        unsolved -= accumulated_hashes
        package_hash = report.get('package_spec', {}).get('hash', '')
        results = report.get('results', [])

        # Check for valid result and sufficient balance
        valid_result = (results and isinstance(results[0].get('result', {}), dict) and 
                        results[0].get('result', {}).get('ok') is not None)
        accumulate_gas = results[0].get('accumulate_gas', 0) if results else 0
        service_id = results[0].get('service_id') if results else None
        sufficient_balance = False
        if service_id is not None:
            for account in post_state.get('accounts', []):
                if account.get('id') == service_id:
                    balance = account.get('data', {}).get('service', {}).get('balance', 0)
                    sufficient_balance = balance >= accumulate_gas
                    break

        # Enqueue if dependencies exist, no valid result, or insufficient balance
        if (unsolved or not package_hash or not valid_result or 
            accumulate_gas == 0 or not sufficient_balance):
            current_ready.append({
                'report': report,
                'dependencies': list(unsolved)
            })
        else:
            # Accumulate only on valid result and sufficient balance
            current_accumulated.append(package_hash)
            accumulated_hashes.add(package_hash)
            # Update stats
            if service_id is not None:
                stats_list = post_state['statistics']
                stats = None
                for entry in stats_list:
                    if entry.get('id') == service_id:
                        stats = entry
                        break
                if stats is None:
                    stats = {
                        'id': service_id,
                        'record': {
                            'provided_count': 0,
                            'provided_size': 0,
                            'refinement_count': 0,
                            'refinement_gas_used': 0,
                            'imports': 0,
                            'exports': 0,
                            'extrinsic_size': 0,
                            'extrinsic_count': 0,
                            'accumulate_count': 0,
                            'accumulate_gas_used': 0,
                            'on_transfers_count': 0,
                            'on_transfers_gas_used': 0
                        }
                    }
                    stats_list.append(stats)
                stats['record']['accumulate_count'] += 1
                stats['record']['accumulate_gas_used'] += accumulate_gas + 10
                # Update account balance
                for account in post_state.get('accounts', []):
                    if account.get('id') == service_id:
                        account['data']['service']['balance'] -= accumulate_gas

    # Process all ready queues for unlocked reports
    changed = True
    while changed:
        changed = False
        for idx in range(queue_length):
            ready_queue = post_state['ready_queue'][idx]
            i = len(ready_queue) - 1
            while i >= 0:
                entry = ready_queue[i]
                report = entry.get('report') or entry.get('work_report') or entry
                unsolved = set(entry.get('dependencies', []))
                if report.get('segment_root_lookup'):
                    unsolved.update(item.get('hash', '') for item in report['segment_root_lookup'] if isinstance(item, dict))
                unsolved -= accumulated_hashes
                package_hash = report.get('package_spec', {}).get('hash', '')
                results = report.get('results', [])

                # Check for valid result and sufficient balance
                valid_result = (results and isinstance(results[0].get('result', {}), dict) and 
                                results[0].get('result', {}).get('ok') is not None)
                accumulate_gas = results[0].get('accumulate_gas', 0) if results else 0
                service_id = results[0].get('service_id') if results else None
                sufficient_balance = False
                if service_id is not None:
                    for account in post_state.get('accounts', []):
                        if account.get('id') == service_id:
                            balance = account.get('data', {}).get('service', {}).get('balance', 0)
                            sufficient_balance = balance >= accumulate_gas
                            break

                if (not unsolved and package_hash and valid_result and 
                    accumulate_gas > 0 and sufficient_balance):
                    # Accumulate
                    post_state['accumulated'][idx].append(package_hash)
                    accumulated_hashes.add(package_hash)
                    # Update stats
                    if service_id is not None:
                        stats_list = post_state['statistics']
                        stats = None
                        for s in stats_list:
                            if s.get('id') == service_id:
                                stats = s
                                break
                        if stats is None:
                            stats = {
                                'id': service_id,
                                'record': {
                                    'provided_count': 0,
                                    'provided_size': 0,
                                    'refinement_count': 0,
                                    'refinement_gas_used': 0,
                                    'imports': 0,
                                    'exports': 0,
                                    'extrinsic_size': 0,
                                    'extrinsic_count': 0,
                                    'accumulate_count': 0,
                                    'accumulate_gas_used': 0,
                                    'on_transfers_count': 0,
                                    'on_transfers_gas_used': 0
                                }
                            }
                            stats_list.append(stats)
                        stats['record']['accumulate_count'] += 1
                        stats['record']['accumulate_gas_used'] += accumulate_gas + 10
                        # Update account balance
                        for account in post_state.get('accounts', []):
                            if account.get('id') == service_id:
                                account['data']['service']['balance'] -= accumulate_gas
                    del ready_queue[i]
                    changed = True
                else:
                    entry['dependencies'] = list(unsolved)
                i -= 1

    # Compute output
    output_hash = merkle_root(current_accumulated)
    output = {'ok': output_hash}

    return output, post_state