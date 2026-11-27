
import { Injectable, inject } from '@angular/core';
import { Observable, of, map } from 'rxjs';

import {
  MonitoringApiService,
} from './monitoring-api.service';

@Injectable({ providedIn: 'root' })
export class SecurityAssistantService {

  private readonly monitoring = inject(MonitoringApiService);

  answer(question: string): Observable<string> {

    const q = question.toLowerCase().trim();

    // Current incident statistics
    if (
      /\b(how many|count|statistics|summary|total|current|active)\b/.test(q)
      && /\b(incidents?)\b/.test(q)
    ) {

      return this.monitoring.getIncidentSummary().pipe(
        map(summary => [
          'Current multiclass incident statistics:',
          '',
          `Total incidents: ${summary.total_incidents}`,
          `Active incidents: ${summary.active_incidents}`,
          `Active critical incidents: ${summary.active_critical_incidents}`,
          `Resolved incidents: ${summary.resolved_incidents}`,
          '',
          'Source: PostgreSQL-backed incident summary API.',
        ].join('\n'))
      );
    }

    // Explainable AI
    if (/\b(shap|explainable|explainability)\b/.test(q)) {

      return of([
        'IoT Sentinel uses SHAP to explain model predictions.',
        '',
        'Positive SHAP values increase the explained probability.',
        'Negative SHAP values decrease the explained probability.',
        '',
        'Family SHAP explains the selected attack family.',
        'Attack SHAP explains the uncalibrated attack probability.',
        '',
        'The additivity check verifies numerical reconstruction.',
        'SHAP explanations are not proof of causality.',
      ].join('\n'));
    }

    // Context-aware risk
    if (/\b(risk|severity|criticality|exposure)\b/.test(q)) {

      return of([
        'IoT Sentinel calculates context-aware risk using:',
        '',
        'Risk = 100 x P x (0.4C + 0.4I + 0.2E)',
        '',
        'P = Calibrated attack probability',
        'C = Device criticality',
        'I = Expected attack impact',
        'E = Device exposure',
        '',
        'Low: Below 25',
        'Medium: 25 to below 50',
        'High: 50 to below 75',
        'Critical: 75 or higher',
        '',
        'These weights are provisional academic policy settings.',
        'Device contexts are unverified demonstration profiles.',
      ].join('\n'));
    }

    // Mirai
    if (/\b(mirai|botnet)\b/.test(q)) {

      return of([
        'Mirai is an IoT botnet malware family.',
        '',
        'It commonly targets vulnerable IoT devices.',
        '',
        'Recommended investigation:',
        '1. Review suspicious network traffic.',
        '2. Inspect prediction probabilities and SHAP features.',
        '3. Verify the affected device identity.',
        '4. Review credentials and unusual connections.',
        '',
        'The response policy may recommend simulated isolation.',
        'Real network containment is disabled.',
      ].join('\n'));
    }

    // DDoS and DoS
    if (/\b(ddos|dos|flood)\b/.test(q)) {

      return of([
        'DoS and DDoS attacks disrupt service availability.',
        '',
        'DoS: Denial of Service.',
        'DDoS: Distributed Denial of Service.',
        '',
        'Recommended investigation:',
        '1. Review packet rates and traffic volume.',
        '2. Identify affected devices and services.',
        '3. Check prediction confidence and SHAP explanations.',
        '4. Distinguish attacks from legitimate high-volume traffic.',
        '',
        'The prototype may recommend simulated rate limiting.',
      ].join('\n'));
    }

    // Reconnaissance
    if (/\b(reconnaissance|scan|scanning)\b/.test(q)) {

      return of([
        'Reconnaissance involves discovering network devices,',
        'services and exposed resources.',
        '',
        'Review repeated connection attempts, destination ports',
        'and unusual discovery activity.',
        '',
        'Verify whether the activity is authorized.',
        'Monitoring and investigation are recommended.',
      ].join('\n'));
    }

    // Spoofing
    if (/\b(spoofing|spoof)\b/.test(q)) {

      return of([
        'Spoofing involves impersonating a trusted identity',
        'or network address.',
        '',
        'Review ARP, DNS and source identity inconsistencies.',
        'Compare activity with trusted device records.',
        '',
        'Spoofing is a weak class in the current model.',
        'A benign prediction does not conclusively exclude spoofing.',
      ].join('\n'));
    }

    // Brute force
    if (/\b(bruteforce|brute.force|password)\b/.test(q)) {

      return of([
        'Brute-force attacks involve repeated credential guessing.',
        '',
        'Review failed authentication events and login patterns.',
        'Investigate account security and access controls.',
        '',
        'BruteForce is supported as a model output class,',
        'but lacks held-out validation and test support.',
        'Its predictions must be treated as unverified.',
      ].join('\n'));
    }

    // Web-based attacks
    if (/\b(webbased|web.based|xss|injection)\b/.test(q)) {

      return of([
        'WebBased attacks target web applications and services.',
        '',
        'Review application logs and suspicious request patterns.',
        'Use application-level evidence to verify the attack.',
        '',
        'The prototype may recommend simulated traffic filtering.',
        'No real filtering is executed.',
      ].join('\n'));
    }

    // Response policy
    if (
      /\b(response|containment|isolate|isolation|blocking|approval)\b/.test(q)
    ) {

      return of([
        'IoT Sentinel uses a risk-aware response policy.',
        '',
        'Provisional containment thresholds:',
        'Attack probability: At least 90%',
        'Family confidence: At least 70%',
        'Risk score: At least 75',
        '',
        'Device verification and additional safety checks are required.',
        '',
        'Persistent approval and real execution are disabled.',
        'Use the Response Center to inspect restriction reasons.',
      ].join('\n'));
    }

    // Incident management
    if (
      /\b(incident|incidents|investigate|investigation|resolve|audit|lifecycle)\b/.test(q)
    ) {

      return of([
        'Incident management follows a controlled lifecycle:',
        '',
        'Open -> Acknowledged -> Investigating',
        'Investigating -> Resolved or False Positive',
        '',
        'Review the prediction, risk assessment and response plan.',
        'Every permitted transition creates an audit event.',
        '',
        'Analyst names are unauthenticated demonstration identifiers.',
      ].join('\n'));
    }

    // Probability calibration
    if (
      /\b(calibration|calibrated|probability|confidence)\b/.test(q)
    ) {

      return of([
        'The Random Forest model produces eight family probabilities.',
        '',
        'Raw attack probability = 1 - Benign probability.',
        '',
        'Logistic calibration adjusts the binary attack probability.',
        'A probability of at least 90% triggers a high confidence alert.',
        '',
        'Family probabilities are not calibrated.',
        'Independent calibration evaluation is still required.',
      ].join('\n'));
    }

    // Reports
    if (/\b(report|reports|batch|csv|export)\b/.test(q)) {

      return of([
        'Reports and Batch Analysis supports CSV datasets.',
        '',
        '1. Upload a CSV containing all 36 required features.',
        '2. Run multiclass batch prediction.',
        '3. Review the prediction distribution.',
        '4. Download CSV or JSON reports.',
        '',
        'Maximum supported upload: 10,000 records and 10 MB.',
        'Batch analysis does not automatically create incidents.',
      ].join('\n'));
    }

    // Default response
    return of([
      'I am the IoT Sentinel rule-based Security Assistant.',
      '',
      'I can help you with:',
      '- Multiclass attack families',
      '- SHAP explanations',
      '- Context-aware risk assessment',
      '- Current incident statistics',
      '- Incident investigation',
      '- Automated response policies',
      '- Batch analysis and reports',
      '',
      'Please ask a question about one of these topics.',
      'I cannot independently execute network actions.',
    ].join('\n'));
  }
}
