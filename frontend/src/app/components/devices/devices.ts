import { Component, input } from '@angular/core';
import { DatePipe } from '@angular/common';
import { Device } from '../../services/api';

@Component({
  selector: 'app-devices',
  standalone: true,
  imports: [DatePipe],
  templateUrl: './devices.html',
  styleUrl: './devices.scss',
})
export class Devices {
  readonly devices = input.required<Device[]>();
  readonly loading = input(false);
  readonly error = input('');
}
