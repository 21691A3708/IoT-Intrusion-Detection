import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { GlobalLoader } from './shared/components/global-loader/global-loader';
import { NotificationContainer } from './shared/components/notification-container/notification-container';

@Component({
  selector: 'app-root', standalone: true,
  imports: [RouterOutlet, GlobalLoader, NotificationContainer],
  templateUrl: './app.html', styleUrl: './app.scss',
})
export class App {}
