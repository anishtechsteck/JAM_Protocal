import copy
from hashlib import sha3_256

def bytes_from_hex(h):
    return bytes.fromhex(h[2:])

def merkle_root(hashes):
    clean_hashes = [h for h in hashes if isinstance(h, str) and h.startswith("0x")]
    if not clean_hashes:
        return "0x" + "0" * 64
    leaves = [sha3_256(bytes_from_hex(h)).digest() for h in clean_hashes]
    while len(leaves) > 1:
        new_leaves = []
        for i in range(0, len(leaves), 2):
            left = leaves[i]
            right = leaves[i + 1] if i + 1 < len(leaves) else leaves[i]
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

def accumulate(pre_state, input_data):
    post_state = copy.deepcopy(pre_state)
    post_state['slot'] = input_data['slot']
    
    queue_len = len(post_state['ready_queue'])
    cur = input_data['slot'] % queue_len

    hashes = set(h for q in post_state['accumulated'] for h in q if isinstance(h, str))
    newly_accumulated_hashes = []

    # Combine existing queued items and new reports into a single list to process.
    work_list = shallow_flatten(post_state['ready_queue'][cur]) + shallow_flatten(input_data.get('reports', []))
    
    def _apply_state_changes(report_hash, details):
        """Helper to apply all state changes for an accumulated report."""
        post_state['accumulated'][cur].append(report_hash)
        newly_accumulated_hashes.append(report_hash)
        hashes.add(report_hash)
        
        if not details: return

        stats = post_state.setdefault('statistics', [])
        for svc, total_gas, count in details:
            s = next((x for x in stats if isinstance(x, dict) and x.get('id') == svc), None)
            if s is None:
                s = {'id': svc, 'record': {k: 0 for k in [
                    'provided_count', 'provided_size', 'refinement_count',
                    'refinement_gas_used', 'imports', 'exports', 'extrinsic_size',
                    'extrinsic_count', 'accumulate_count', 'accumulate_gas_used',
                    'on_transfers_count', 'on_transfers_gas_used']}}
                stats.append(s)
            
            s['record']['accumulate_count'] += count
            s['record']['accumulate_gas_used'] += total_gas

            for a in post_state.get('accounts', []):
                if isinstance(a, dict) and a.get('id') == svc:
                    a['data']['service']['balance'] -= total_gas
                    break

    changed = True
    while changed:
        changed = False
        i = len(work_list) - 1
        while i >= 0:
            rpt_item = work_list[i]
            rpt = rpt_item.get('report') if isinstance(rpt_item, dict) and 'report' in rpt_item else rpt_item
            if not isinstance(rpt, dict):
                i -= 1
                continue

            deps = set(rpt.get('context', {}).get('prerequisites', []))
            for item in rpt.get('segment_root_lookup') or []:
                if isinstance(item, dict):
                    deps.add(item.get('hash', ''))
            deps -= hashes
            
            pkg_h = rpt.get('package_spec', {}).get('hash', '')
            results = rpt.get('results', [])
            
            can_accumulate = True
            gas_details_by_svc = {}
            
            # A report is invalid for accumulation if it has dependencies or no package hash.
            # A report with an empty result list is valid; it just has no on-chain effects.
            if deps or not pkg_h:
                can_accumulate = False
            else:
                for res in results:
                    if not (isinstance(res, dict) and isinstance(res.get('result'), dict) and res['result'].get('ok') is not None and res.get('accumulate_gas', 0) > 0 and res.get('service_id') is not None):
                        can_accumulate = False; break
                    svc = res['service_id']
                    gas = res['accumulate_gas']
                    gas_details_by_svc.setdefault(svc, {'gas': 0, 'count': 0})['gas'] += gas
                    gas_details_by_svc[svc]['count'] += 1

                if can_accumulate:
                    for svc, details in gas_details_by_svc.items():
                        if not any(a.get('id') == svc and a.get('data', {}).get('service', {}).get('balance', 0) >= details['gas'] for a in post_state.get('accounts', [])):
                            can_accumulate = False; break
            
            if can_accumulate:
                final_details = [(svc, data['gas'], data['count']) for svc, data in gas_details_by_svc.items()] if 'gas_details_by_svc' in locals() and gas_details_by_svc else []
                _apply_state_changes(pkg_h, final_details)
                del work_list[i]
                changed = True
            
            i -= 1
            
    post_state['ready_queue'][cur] = work_list
    
    return {'ok': merkle_root(newly_accumulated_hashes)}, post_state