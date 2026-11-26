"""Local regression checks using the existing trained model and saved sample."""
import json
import math
from pathlib import Path
from unittest.mock import patch
from backend.app import context_comparison_service as service
from backend.app.context_risk_service import assess_traffic_risk


def main():
    root = Path(__file__).resolve().parent
    features = json.loads((root / 'results/multiclass/frontend_detection_samples/mirai.json').read_text(encoding='utf-8-sig'))
    with patch.object(service, 'predict_traffic', wraps=service.predict_traffic) as inference:
        result = service.compare_traffic_contexts(features)
        assert inference.call_count == 1
    print('PASS: one inference')
    rows = result['comparisons']
    assert result['total_contexts'] == len(rows) == 6
    assert {r['device_id'] for r in rows} == {'sensor-001','camera-001','gateway-001','medical-001','industrial-001',None}
    scores = [r['risk_score'] for r in rows]
    assert scores == sorted(scores, reverse=True)
    for row in rows:
        individual = assess_traffic_risk(features, row['device_id'])
        assert individual['prediction'] == result['prediction']
        assert math.isclose(row['risk_score'], individual['risk_assessment']['risk_score'], abs_tol=1e-8)
        assert row['risk_reconstruction']['passed']
        assert row['containment_authorized'] is False and row['response_executed'] is False
        assert row['device_context']['identity_verified'] is False
        print(f"PASS: {row['device_name']}: {row['risk_score']:.6f} ({row['risk_level']})")
    summary = result['summary']
    assert summary['highest_risk_score'] == max(scores)
    assert summary['lowest_risk_score'] == min(scores)
    assert summary['risk_score_difference'] == max(scores)-min(scores)
    assert summary['highest_risk_device_ids'] == ['gateway-001']
    assert summary['lowest_risk_device_ids'] == ['sensor-001']
    assert result['simulation_only'] is True
    for key in ('containment_authorized','incident_created','response_executed'):
        assert result[key] is False
    print('PASS: ranking, summary and safety')
    # Synthetic prediction tests exercise risk policy edge cases, not model accuracy.
    synthetic = dict(result['prediction'], calibrated_attack_probability=0.0, attack_probability=0.0, detection_status='low_probability')
    zero = service.compare_prediction_contexts(synthetic)
    assert all(r['risk_score'] == 0 for r in zero['comparisons'])
    assert len(zero['summary']['highest_risk_device_ids']) == 6
    assert len(zero['summary']['lowest_risk_device_ids']) == 6
    assert zero['summary']['risk_score_difference'] == 0
    print('PASS: synthetic zero risk and ties')
    try:
        service.compare_traffic_contexts({})
    except ValueError:
        print('PASS: invalid features rejected')
    else:
        raise AssertionError('Invalid features accepted')
    print('ALL COMPARISON SERVICE TESTS PASSED')

if __name__ == '__main__':
    main()
