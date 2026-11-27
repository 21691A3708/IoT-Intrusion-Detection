import { Component, input, computed } from '@angular/core';
import { CommonModule } from '@angular/common';

import type {
  ShapExplanation,
} from '../../../core/services/multiclass-explainability-api.service';

@Component({
  selector: 'app-shap-contributions',
  standalone: true,
  imports: [CommonModule],

  template: `
    <section class="panel">

      <h3>{{ heading() }}</h3>

      <p class="muted">{{ description() }}</p>

      <div class="metrics">

        <article>
          <small>Base value</small>
          <strong>{{ result().base_value | number:'1.4-4' }}</strong>
        </article>

        <article>
          <small>SHAP contribution sum</small>
          <strong>
            {{ result().shap_values_sum | number:'1.4-4' }}
          </strong>
        </article>

        <article>
          <small>Reconstructed probability</small>
          <strong>
            {{ result().reconstructed_probability * 100
               | number:'1.2-2' }}%
          </strong>
        </article>

      </div>

      <div class="legend">
        <span class="positive-text">
          + Increases target probability
        </span>
        <span class="negative-text">
          - Decreases target probability
        </span>
      </div>

      @for (row of rows(); track row.feature) {

        <div class="feature-row">

          <div class="feature-header">
            <strong>{{ row.feature }}</strong>

            <span [class.positive-text]="row.shap_value > 0"
                  [class.negative-text]="row.shap_value < 0">

              {{ row.shap_value > 0 ? '+' : '' }}
              {{ row.shap_value | number:'1.6-6' }}

            </span>
          </div>

          <small>
            Feature value:
            {{ row.feature_value | number:'1.0-6' }}
          </small>

          <div class="diverging-bar">

            <div class="negative-half">
              <div class="negative-fill"
                   [style.width.%]="row.shap_value < 0
                     ? magnitude(row.shap_value) : 0">
              </div>
            </div>

            <div class="positive-half">
              <div class="positive-fill"
                   [style.width.%]="row.shap_value > 0
                     ? magnitude(row.shap_value) : 0">
              </div>
            </div>

          </div>

        </div>

      }

      <div class="verification">

        <strong>
          {{ result().additivity_passed
             ? 'Additivity verified'
             : 'Additivity verification failed' }}
        </strong>

        <p>
          Base value + all SHAP contributions =
          reconstructed probability.
        </p>

        <div>
          Reconstruction error:
          {{ result().additivity_error.toExponential(3) }}
        </div>

        <div>
          Remaining feature contribution:
          {{ result().remaining_features_sum | number:'1.6-6' }}
        </div>

        <div>
          Displaying {{ rows().length }} of
          {{ result().feature_count }} features.
        </div>

      </div>

      <p class="muted">
        Contributions explain the model output.
        They do not establish causal relationships.
      </p>

    </section>
  `,

  styles: [`
    :host {
      display: block;
      min-width: 0;
    }

    .panel {
      padding: 20px;
      background: #152134;
      border: 1px solid #29374d;
      border-radius: 14px;
      color: #e2e8f0;
    }

    h3 { margin: 0; }

    .muted, small {
      color: #94a3b8;
      font-size: 12px;
      line-height: 1.6;
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin: 20px 0;
    }

    article {
      background: #0e1929;
      padding: 14px;
      border-radius: 9px;
      display: grid;
      gap: 8px;
    }

    article strong {
      color: #60a5fa;
      font-size: 20px;
      overflow-wrap: anywhere;
    }

    .legend {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      font-size: 12px;
      margin: 20px 0;
    }

    .positive-text { color: #f87171; }
    .negative-text { color: #60a5fa; }

    .feature-row {
      padding: 14px 0;
      border-bottom: 1px solid #29374d;
    }

    .feature-header {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      font-size: 13px;
      overflow-wrap: anywhere;
    }

    .diverging-bar {
      display: flex;
      height: 12px;
      margin-top: 10px;
      background: #0d1727;
      border-radius: 5px;
      overflow: hidden;
    }

    .negative-half, .positive-half {
      width: 50%;
      display: flex;
    }

    .negative-half {
      justify-content: flex-end;
      border-right: 1px solid #64748b;
    }

    .negative-fill { background: #3b82f6; }
    .positive-fill { background: #ef4444; }

    .verification {
      margin-top: 20px;
      padding: 15px;
      border: 1px solid #166534;
      background: #123126;
      border-radius: 10px;
      font-size: 12px;
      line-height: 1.8;
      color: #bbf7d0;
    }

    @media (max-width: 600px) {
      .metrics { grid-template-columns: 1fr; }
      .panel { padding: 14px; }
    }
  `],
})
export class ShapContributions {

  readonly heading = input.required<string>();

  readonly description = input('');

  readonly result = input.required<ShapExplanation>();

  protected readonly rows = computed(
    () => [...this.result().top_features].sort(
      (a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value)
    )
  );

  private readonly maxMagnitude = computed(
    () => Math.max(
      1e-12,
      ...this.rows().map(row => Math.abs(row.shap_value))
    )
  );

  protected magnitude(value: number): number {
    return Math.abs(value) / this.maxMagnitude() * 100;
  }
}
