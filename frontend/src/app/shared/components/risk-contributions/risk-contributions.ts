import {
  Component,
  computed,
  input,
} from '@angular/core';

import { DecimalPipe } from '@angular/common';

import type {
  RiskAssessmentResponse,
} from '../../../core/models/risk-assessment.model';


@Component({
  selector: 'app-risk-contributions',
  standalone: true,
  imports: [DecimalPipe],
  templateUrl: './risk-contributions.html',
  styleUrl: './risk-contributions.scss',
})
export class RiskContributions {

  readonly result =
    input.required<RiskAssessmentResponse>();


  protected readonly assessment = computed(
    () => this.result().risk_assessment
  );


  protected readonly prediction = computed(
    () => this.result().prediction
  );


  protected readonly score = computed(
    () => this.assessment().risk_score
  );


  protected readonly reconstruction = computed(
    () => this.assessment().risk_reconstruction
  );


  protected readonly contributions = computed(() => {

    const risk = this.assessment();

    const definitions = [

      {
        key: 'criticality',
        label: 'Device criticality',
        description:
          'Business importance of the selected device',
        color: '#60a5fa',
      },

      {
        key: 'attack_impact',
        label: 'Expected attack impact',
        description:
          'Conditional probability-weighted attack impact',
        color: '#a78bfa',
      },

      {
        key: 'exposure',
        label: 'Network exposure',
        description:
          'Exposure of the device to network threats',
        color: '#2dd4bf',
      },

    ] as const;

    return definitions.map(definition => {

      const key = definition.key;

      const factor = risk.risk_factors[key];

      const weight = risk.risk_weights[key];

      const points = risk.risk_contributions[key];

      const share = risk.risk_score > 0
        ? (points / risk.risk_score) * 100
        : 0;

      return {

        ...definition,

        factor,

        weight,

        points,

        share,

      };

    });

  });


  protected readonly contributionSum = computed(
    () => this.contributions().reduce(
      (sum, item) => sum + item.points,
      0,
    )
  );


  protected readonly dominantContribution = computed(() => {

    const rows = this.contributions();

    const maximum = Math.max(
      ...rows.map(row => row.points)
    );

    if (maximum <= 0) {
      return 'None';
    }

    return rows
      .filter(row =>
        Math.abs(row.points - maximum) <= 1e-6
      )
      .map(row => row.label)
      .join(' and ');

  });


  protected readonly reconstructionVerified = computed(
    () => {

      return (
        this.reconstruction().passed === true &&
        Math.abs(
          this.contributionSum() - this.score()
        ) <= 1e-6
      );

    }
  );


  protected readonly unusedRiskCapacity = computed(
    () => Math.max(0, 100 - this.contributionSum())
  );


}
