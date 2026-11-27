"""Assessment-only comparison of identical traffic across device contexts."""
import math

from .multiclass_ml_service import predict_traffic
from .context_risk_service import assess_prediction_risk, RISK_POLICY_VERSION
from .device_context_service import list_device_profiles

COMPARISON_VERSION = "context_comparison_v1"


def compare_prediction_contexts(prediction: dict) -> dict:
    """Reuse an existing prediction; never perform inference or network actions."""
    device_ids = [profile['device_id'] for profile in list_device_profiles()]
    device_ids.append(None)
    comparisons = []
    for device_id in device_ids:
        risk = assess_prediction_risk(prediction=prediction, device_id=device_id)
        context = risk['device_context']
        comparisons.append({
            'device_id': context['device_id'],
            'device_name': context['device_name'],
            **risk,
        })
    comparisons.sort(key=lambda row: (-row['risk_score'], row['device_id'] or ''))
    highest = comparisons[0]['risk_score']
    lowest = comparisons[-1]['risk_score']
    def tied(score):
        return [row['device_id'] for row in comparisons
                if math.isclose(row['risk_score'], score, rel_tol=0, abs_tol=1e-8)]
    return {
        'comparison_version': COMPARISON_VERSION,
        'risk_policy_version': RISK_POLICY_VERSION,
        'mode': 'context_comparison_only',
        'prediction': prediction,
        'total_contexts': len(comparisons),
        'comparisons': comparisons,
        'summary': {
            'highest_risk_score': highest,
            'lowest_risk_score': lowest,
            'risk_score_difference': highest - lowest,
            'highest_risk_device_ids': tied(highest),
            'lowest_risk_device_ids': tied(lowest),
        },
        'simulation_only': True,
        'containment_authorized': False,
        'incident_created': False,
        'response_executed': False,
    }


def compare_traffic_contexts(features: dict) -> dict:
    return compare_prediction_contexts(predict_traffic(features))
