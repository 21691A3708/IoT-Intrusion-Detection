import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { App } from './app/app';

bootstrapApplication(App, appConfig)
  .then(() => document.getElementById('startup-loader')?.remove())
  .catch((err) => {
    console.error(err);
    document.querySelector('.startup-spinner')?.remove();
    const message = document.getElementById('startup-message');
    if (message) message.textContent = 'Startup failed. Refresh the page or check the browser console.';
  });
