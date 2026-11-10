import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PredictionTrends } from './prediction-trends';

describe('PredictionTrends', () => {
  let component: PredictionTrends;
  let fixture: ComponentFixture<PredictionTrends>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PredictionTrends],
    }).compileComponents();

    fixture = TestBed.createComponent(PredictionTrends);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
