import { Component, input, computed } from '@angular/core';
import { CommonModule } from '@angular/common';

import type {
  ResponsePlan,
} from '../../../core/services/security-operations-api.service';

@Component({
  selector: 'app-response-policy',
  standalone: true,
  imports: [CommonModule],

  template: `
    <section class="panel">

      <h3>Response Policy Evaluation</h3>

      <div class="metrics">

        <article>
          <small>Predicted family</small>
          <strong>{{ plan().predicted_family }}</strong>
        </article>

        <article>
          <small>Risk score</small>
          <strong>
            {{ plan().risk_score | number:'1.2-2' }}/100
          </strong>
        </article>

        <article>
          <small>Risk level</small>
          <strong>{{ plan().risk_level | titlecase }}</strong>
        </article>

        <article>
          <small>Response status</small>
          <strong>{{ readable(plan().response_status) }}</strong>
        </article>

      </div>

      <h4>Recommended response</h4>

      <div class="recommendation">
        {{ readable(plan().primary_action) }}
      </div>

      <p>
        {{ readable(plan().attack_specific_recommendation) }}
      </p>

      <div class="line">
        <span>Device context</span>
        <strong>{{ plan().device_name }}</strong>
      </div>

      <div class="line">
        <span>Incident required</span>
        <strong>{{ plan().incident_required ? 'Yes' : 'No' }}</strong>
      </div>

      <div class="line">
        <span>Proposed containment</span>
        <strong>
          {{ readable(plan().proposed_containment_action || 'None') }}
        </strong>
      </div>

      <div class="line">
        <span>Containment eligible</span>
        <strong>{{ plan().containment_eligible ? 'Yes' : 'No' }}</strong>
      </div>

      <h4>Safety policy checks</h4>

      @for (check of checks(); track check.key) {

        <div class="line">

          <span>{{ readable(check.key) }}</span>

          <strong
            [class.passed]="check.value === true"
            [class.restricted]="check.value === false">

            {{ check.value === true
              ? 'Passed'
              : check.value === false
                ? 'Not satisfied'
                : (check.value | json) }}

          </strong>

        </div>

      }

      @if (plan().restriction_reasons.length) {

        <h4>Restriction reasons</h4>

        <div class="warning">

          @for (reason of plan().restriction_reasons; track $index) {
            <p>{{ readable(reason) }}</p>
          }

        </div>

      }

      @for (warning of plan().warnings; track $index) {
        <p class="muted">{{ warning }}</p>
      }

      <div class="safety">

        <div>
          Simulation only:
          {{ plan().simulation_only ? 'Yes' : 'No' }}
        </div>

        <div>
          Containment authorized:
          {{ plan().containment_authorized ? 'Yes' : 'No' }}
        </div>

        <div>
          Real network action executed:
          {{ plan().real_network_action_executed ? 'Yes' : 'No' }}
        </div>

        <p>
          Response recommendations do not authorize real
          network containment.
        </p>

      </div>

    </section>
  `,

  styles: [`
    :host { display:block; min-width:0; }

    .panel {
      background:#152134;
      border:1px solid #29374d;
      border-radius:14px;
      padding:20px;
      color:#e2e8f0;
    }

    h3 { margin:0; }
    h4 { margin:22px 0 12px; }

    .metrics {
      display:grid;
      grid-template-columns:repeat(4,minmax(0,1fr));
      gap:12px;
      margin:20px 0;
    }

    article {
      display:grid;
      gap:10px;
      background:#0e1929;
      padding:14px;
      border-radius:9px;
      overflow-wrap:anywhere;
    }

    small,.muted {
      color:#94a3b8;
      font-size:12px;
    }

    article strong { color:#60a5fa; font-size:18px; }

    .line {
      display:flex;
      justify-content:space-between;
      gap:16px;
      padding:12px 0;
      border-bottom:1px solid #29374d;
      font-size:13px;
      overflow-wrap:anywhere;
    }

    .line strong { text-align:right; }

    .passed { color:#4ade80; }
    .restricted { color:#fbbf24; }

    .recommendation,.warning,.safety {
      padding:14px;
      border-radius:9px;
      font-size:13px;
      line-height:1.7;
    }

    .recommendation {
      background:#142d43;
      color:#bfdbfe;
    }

    .warning {
      background:#392c17;
      border:1px solid #854d0e;
      color:#fde68a;
    }

    .safety {
      margin-top:20px;
      background:#123126;
      border:1px solid #166534;
      color:#bbf7d0;
    }

    p { font-size:13px; line-height:1.7; }

    @media(max-width:900px) {
      .metrics {
        grid-template-columns:repeat(2,minmax(0,1fr));
      }
    }

    @media(max-width:450px) {
      .metrics { grid-template-columns:1fr; }
      .panel { padding:14px; }
      .line { flex-direction:column; gap:6px; }
      .line strong { text-align:left; }
    }
  `],
})
export class ResponsePolicy {

  readonly plan = input.required<ResponsePlan>();

  protected readonly checks = computed(
    () => Object.entries(this.plan().safety_checks).map(
      ([key, value]) => ({ key, value })
    )
  );

  protected readable(value: string): string {
    return value.replace(/_/g, ' ');
  }
}
