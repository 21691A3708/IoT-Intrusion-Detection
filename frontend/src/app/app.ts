import {
  Component,
} from '@angular/core';

import {
  Dashboard,
} from './components/dashboard/dashboard';

import {
  GlobalLoader,
} from './shared/components/global-loader/global-loader';

import {
  NotificationContainer,
} from './shared/components/notification-container/notification-container';

@Component({

  selector: 'app-root',

  standalone: true,

  imports: [
    Dashboard,
    GlobalLoader,
    NotificationContainer,
  ],

  templateUrl: './app.html',

  styleUrl: './app.scss',

})
export class App {}
