import {
  Component,
  computed,
  input,
} from '@angular/core';

import { DecimalPipe } from '@angular/common';

import {
  RISK_LEVEL_LABELS,
  type RiskAssessmentResponse,
} from '../../../core/models/risk-assessment.model';


@Component({
  selector: 'app-risk-score',
  standalone: true,
  imports: [DecimalPipe],
  templateUrl: './risk-score.html',
  styleUrl: './risk-score.scss',
})
export class RiskScore {

  readonly result =
    input.required<RiskAssessmentResponse>();


  protected readonly assessment = computed(
    () => this.result().risk_assessment
  );


  protected readonly prediction = computed(
    () => this.result().prediction
  );


  protected readonly context = computed(
    () => this.assessment().device_context
  );


  protected readonly score = computed(
    () => this.assessment().risk_score
  );


  protected readonly level = computed(
    () => this.assessment().risk_level
  );


  protected readonly levelLabel = computed(
    () => RISK_LEVEL_LABELS[this.level()]
  );


  protected readonly circumference =
    2 * Math.PI * 54;


  protected readonly gaugeOffset = computed(
    () =>
      this.circumference *
      (1 - this.score() / 100)
  );


  protected readonly metrics = computed(() => {

    const risk = this.assessment();

    return [

      {
        label: 'Calibrated attack probability',
        value: risk.attack_probability * 100,
        precision: '1.2-4',
        description: 'Binary calibrated probability',
      },

      {
        label: 'Device criticality',
        value: risk.risk_factors.criticality * 100,
        precision: '1.0-2',
        description: 'Business importance of the device',
      },

      {
        label: 'Expected attack impact',
        value: risk.risk_factors.attack_impact * 100,
        precision: '1.0-2',
        description: 'Conditional weighted attack impact',
      },

      {
        label: 'Network exposure',
        value: risk.risk_factors.exposure * 100,
        precision: '1.0-2',
        description: 'Device exposure to network threats',
      },

    ];

  });


  protected readonly classificationMismatch =
    computed(() => {

      return (
        this.prediction().predicted_family === 'Benign' &&
        this.assessment().attack_probability >= 0.50
      );

    });


}
