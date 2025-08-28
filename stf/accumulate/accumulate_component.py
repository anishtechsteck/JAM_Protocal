import copy
from hashlib import sha3_256

def bytes_from_hex(h):
    return bytes.fromhex(h[2:])

def merkle_root(hashes):
    if not hashes:
        return "0x" + "0" * 64
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

def shallow_flatten(lst):
    result = []
    for item in lst:
        if isinstance(item, list):
            result.extend(item)
        else:
            result.append(item)
    return result

def accumulate(pre_state, input):
    post_state = copy.deepcopy(pre_state)
    post_state['slot'] = input['slot']
    queue_len = 12
    cur = input['slot'] % queue_len

    # Initialize accumulated if not present
    if 'accumulated' not in post_state:
        post_state['accumulated'] = [[] for _ in range(queue_len)]

    # Initialize ready_queue if not present or adjust length
    if 'ready_queue' not in post_state or not post_state['ready_queue']:
        post_state['ready_queue'] = [[] for _ in range(queue_len)]
    elif len(post_state['ready_queue']) != queue_len:
        post_state['ready_queue'] = [post_state['ready_queue'][i % len(post_state['ready_queue'])] if i < len(post_state['ready_queue']) else [] for i in range(queue_len)]

    # Flatten current ready_queue slot
    post_state['ready_queue'][cur] = shallow_flatten(post_state['ready_queue'][cur])

    acc = post_state['accumulated'][cur]
    hashes = set(h for q in post_state['accumulated'] for h in q if isinstance(h, str) and h.startswith("0x"))

    current_ready = post_state['ready_queue'][cur]

    # Process input reports
    for rpt in shallow_flatten(input.get('reports', [])):
        if not isinstance(rpt, dict):
            continue
        deps = set(rpt.get('context', {}).get('prerequisites', []))
        for item in rpt.get('segment_root_lookup', []):
            if isinstance(item, dict):
                deps.add(item.get('hash', ''))
        deps -= hashes

        pkg = rpt.get('package_spec', {})
        pkg_h = pkg.get('hash', '') if isinstance(pkg, dict) else ''

        res = rpt.get('results', [])
        if isinstance(res, list) and res and isinstance(res[0], dict):
            r0 = res[0]
            ok = isinstance(r0.get('result', {}), dict) and r0['result'].get('ok') is not None
            gas = r0.get('accumulate_gas', 0)
            svc = r0.get('service_id')
        else:
            ok = False
            gas = 0
            svc = None

        auth_gas = rpt.get('auth_gas_used', 0)

        aff = False
        if svc is not None and gas > 0:
            for a in post_state.get('accounts', []):
                if isinstance(a, dict) and a.get('id') == svc:
                    balance = a.get('data', {}).get('service', {}).get('balance', 0)
                    if balance >= gas:
                        aff = True
                    break

        if svc and ok and aff and not deps and pkg_h:
            acc.append(pkg_h)
            hashes.add(pkg_h)
            if 'statistics' not in post_state:
                post_state['statistics'] = []
            stats = next((x for x in post_state['statistics'] if isinstance(x, dict) and x.get('service_id') == svc), None)
            if stats is None:
                stats = {'service_id': svc, 'accumulate_count': 0, 'accumulate_gas_used': 0, 'on_transfers_count': 0, 'on_transfers_gas_used': 0, 'record': {'provided_count': 0, 'provided_size': 0, 'refinement_count': 0, 'refinement_gas_used': 0, 'imports': 0, 'exports': 0, 'extrinsic_size': 0, 'extrinsic_count': 0, 'accumulate_count': 0, 'accumulate_gas_used': 0, 'on_transfers_count': 0, 'on_transfers_gas_used': 0}}
                post_state['statistics'].append(stats)
            stats['accumulate_count'] += 1
            stats['accumulate_gas_used'] += gas + auth_gas
            stats['record']['accumulate_count'] += 1
            stats['record']['accumulate_gas_used'] += gas + auth_gas
            for a in post_state.get('accounts', []):
                if isinstance(a, dict) and a.get('id') == svc:
                    a['data']['service']['balance'] -= gas
                    break

        current_ready.append({'report': rpt, 'dependencies': list(deps), 'stale': pkg_h in deps})

    return {'ok': merkle_root(acc)}, post_state