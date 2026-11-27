import { Component, input } from '@angular/core';
import { DecimalPipe } from '@angular/common';

import type { ContextComparisonResponse } from '../../../core/models/context-comparison.model';

@Component({
  selector: 'app-context-comparison',
  standalone: true,
  imports: [DecimalPipe],
  template: `
    <section class="comparison-panel">
      <h2>Device Context Comparison</h2>

      <p class="muted">Same network traffic evaluated across device contexts.</p>

      <div class="summary-grid">
        <article>
          <small>Highest risk</small>
          <strong>
            {{ result().summary.highest_risk_score | number: '1.2-2' }}
          </strong>
        </article>

        <article>
          <small>Lowest risk</small>
          <strong>
            {{ result().summary.lowest_risk_score | number: '1.2-2' }}
          </strong>
        </article>

        <article>
          <small>Risk difference</small>
          <strong>
            {{ result().summary.risk_score_difference | number: '1.2-2' }}
          </strong>
        </article>

        <article>
          <small>Device contexts</small>
          <strong>{{ result().total_contexts }}</strong>
        </article>
      </div>

      <p>
        Predicted family:
        <b>{{ result().prediction.predicted_family }}</b>
        | Attack probability:
        <b> {{ result().prediction.attack_probability * 100 | number: '1.2-4' }}% </b>
      </p>

      @for (row of result().comparisons; track row.device_id ?? 'unknown') {
        <article class="device-row" [attr.data-level]="row.risk_level">
          <div class="device-header">
            <div>
              <h3>{{ row.device_name }}</h3>
              <small>{{ row.device_id ?? 'Unknown context' }}</small>
            </div>

            <strong class="score">
              {{ row.risk_score | number: '1.2-2' }}
              / {{ row.risk_level }}
            </strong>
          </div>

          <div
            class="risk-track"
            role="meter"
            [attr.aria-label]="row.device_name + ' risk score'"
            aria-valuemin="0"
            aria-valuemax="100"
            [attr.aria-valuenow]="row.risk_score"
          >
            <div class="risk-fill" [style.width.%]="row.risk_score"></div>
          </div>

          <div class="device-header muted">
            <span>
              Criticality:
              {{ row.device_context.criticality * 100 | number: '1.0-0' }}%
            </span>
            <span>
              Exposure:
              {{ row.device_context.exposure * 100 | number: '1.0-0' }}%
            </span>
            <span>Identity: Unverified</span>
          </div>
        </article>
      }

      <footer>
        Simulation only. Device profiles are unverified and risk weights are provisional. No
        incident creation, containment authorization or response execution.
      </footer>
    </section>
  `,
  styles: [
    `
      :host {
        display: block;
        min-width: 0;
      }

      .comparison-panel {
        background: #111c2e;
        border: 1px solid #29364b;
        border-radius: 16px;
        padding: 24px;
        margin-top: 24px;
        color: #e2e8f0;
      }

      h2,
      h3 {
        margin: 0;
      }

      h2 {
        font-size: 20px;
      }

      h3 {
        font-size: 15px;
      }

      .muted,
      small,
      footer {
        color: #94a3b8;
        font-size: 12px;
      }

      .summary-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 12px;
        margin: 20px 0;
      }

      .summary-grid article,
      .device-row {
        background: #172438;
        border: 1px solid #29364b;
        border-radius: 12px;
        padding: 16px;
      }

      .summary-grid article {
        display: flex;
        flex-direction: column;
        gap: 8px;
      }

      .summary-grid strong {
        font-size: 26px;
      }

      .device-row {
        --risk-color: #22c55e;
        margin-top: 12px;
      }

      .device-row[data-level='medium'] {
        --risk-color: #eab308;
      }

      .device-row[data-level='high'] {
        --risk-color: #f97316;
      }

      .device-row[data-level='critical'] {
        --risk-color: #ef4444;
      }

      .device-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 12px;
      }

      .score {
        color: var(--risk-color);
        text-transform: uppercase;
        font-size: 14px;
      }

      .risk-track {
        height: 10px;
        background: #29364b;
        border-radius: 20px;
        overflow: hidden;
        margin: 14px 0;
      }

      .risk-fill {
        height: 100%;
        background: var(--risk-color);
        border-radius: 20px;
      }

      footer {
        border-top: 1px solid #29364b;
        margin-top: 20px;
        padding-top: 16px;
        line-height: 1.6;
      }

      @media (max-width: 900px) {
        .summary-grid {
          grid-template-columns: repeat(2, minmax(0, 1fr));
        }
      }

      @media (max-width: 480px) {
        .comparison-panel {
          padding: 14px;
        }

        .summary-grid {
          grid-template-columns: 1fr;
        }
      }
    `,
  ],
})
export class ContextComparison {
  readonly result = input.required<ContextComparisonResponse>();
}
