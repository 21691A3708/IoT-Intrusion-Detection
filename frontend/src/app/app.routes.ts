import { Routes, UrlMatcher } from '@angular/router';
import { Dashboard } from './components/dashboard/dashboard';

const pages = new Set(['dashboard', 'detection', 'traffic-monitor', 'incidents', 'response-center', 'devices', 'explainability', 'reports', 'assistant']);
const pageMatcher: UrlMatcher = segments => segments.length === 1 && pages.has(segments[0].path)
  ? { consumed: segments, posParams: { page: segments[0] } } : null;

export const routes: Routes = [
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
  { path: 'alerts', redirectTo: 'incidents', pathMatch: 'full' },
  { path: 'traffic', redirectTo: 'traffic-monitor', pathMatch: 'full' },
  { path: 'analysis', redirectTo: 'explainability', pathMatch: 'full' },
  { matcher: pageMatcher, component: Dashboard },
  { path: '**', component: Dashboard },
];
