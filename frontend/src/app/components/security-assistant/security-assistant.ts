
import {
  Component,
  inject,
  signal,
  DestroyRef,
} from '@angular/core';

import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { finalize } from 'rxjs';

import {
  takeUntilDestroyed,
} from '@angular/core/rxjs-interop';

import {
  SecurityAssistantService,
} from '../../core/services/security-assistant.service';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

@Component({
  selector: 'app-security-assistant',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './security-assistant.html',
  styleUrl: './security-assistant.scss',
})
export class SecurityAssistant {

  private readonly service = inject(SecurityAssistantService);
  private readonly destroyRef = inject(DestroyRef);

  protected question = '';

  protected readonly busy = signal(false);

  protected readonly suggestions = [
    'What is Mirai?',
    'Explain DDoS attacks',
    'Explain SHAP',
    'Explain the risk score',
    'Current incident summary',
    'How does response approval work?',
    'Explain the incident lifecycle',
    'How can I export reports?',
  ];

  protected readonly messages = signal<ChatMessage[]>([
    {
      role: 'assistant',
      content:
        'Welcome to IoT Sentinel Security Assistant.\n\n' +
        'Ask me about network attacks, SHAP explanations, ' +
        'contextual risk, incidents or response recommendations.',
      timestamp: new Date().toISOString(),
    },
  ]);

  protected send(value = this.question): void {

    const question = value.trim();

    if (
      !question ||
      this.busy() ||
      question.length > 2000
    ) {
      return;
    }

    this.append('user', question);

    this.question = '';
    this.busy.set(true);

    this.service.answer(question).pipe(

      takeUntilDestroyed(this.destroyRef),

      finalize(() => this.busy.set(false))

    ).subscribe({

      next: answer => {
        this.append('assistant', answer);
      },

      error: () => {
        this.append(
          'assistant',
          'Unable to retrieve security information. ' +
          'Check the backend connection and try again.'
        );
      },
    });
  }

  protected clear(): void {

    if (this.busy()) return;

    this.messages.set([
      {
        role: 'assistant',
        content: 'Conversation cleared. How can I help?',
        timestamp: new Date().toISOString(),
      },
    ]);

    this.question = '';
  }

  private append(
    role: ChatMessage['role'],
    content: string
  ): void {

    this.messages.update(messages => [
      ...messages,
      {
        role,
        content,
        timestamp: new Date().toISOString(),
      },
    ].slice(-100));
  }
}
