import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';

interface ChatMessage {
  role: 'user' | 'assistant';
  text: string;
  timestamp: Date;
}

interface ChatResponse {
  success: boolean;
  intent: string;
  answer: string;
}

@Component({
  selector: 'app-assistant-chat',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './assistant-chat.html',
  styleUrl: './assistant-chat.scss',
})
export class AssistantChat {
  private readonly http = inject(HttpClient);
  private readonly destroyRef = inject(DestroyRef);

  private readonly apiUrl = 'http://127.0.0.1:8000/api/assistant/chat';

  protected readonly isOpen = signal(false);
  protected readonly isSending = signal(false);
  protected readonly errorMessage = signal('');

  protected readonly messages = signal<ChatMessage[]>([
    {
      role: 'assistant',
      text:
        "Hello! I'm your IoT Security Assistant. Ask me about network attacks, " +
        'risk levels, SHAP explanations, predictions, incidents, or registered devices.',
      timestamp: new Date(),
    },
  ]);

  protected question = '';

  protected toggleChat(): void {
    this.isOpen.update((open) => !open);
    this.errorMessage.set('');
  }

  protected closeChat(): void {
    this.isOpen.set(false);
    this.errorMessage.set('');
  }

  protected sendQuestion(): void {
    const question = this.question.trim();

    if (!question || this.isSending()) {
      return;
    }

    this.messages.update((current) => [
      ...current,
      { role: 'user', text: question, timestamp: new Date() },
    ]);

    this.question = '';
    this.isSending.set(true);
    this.errorMessage.set('');

    this.http
      .post<ChatResponse>(this.apiUrl, { question })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (response) => {
          this.messages.update((current) => [
            ...current,
            {
              role: 'assistant',
              text:
                response?.answer ||
                'The assistant returned an empty response. Please try again.',
              timestamp: new Date(),
            },
          ]);
          this.isSending.set(false);
        },
        error: (error) => {
          console.error('Assistant chat request failed:', error);

          this.errorMessage.set(
            'Could not connect to the assistant. Make sure the FastAPI backend is running.',
          );
          this.messages.update((current) => [
            ...current,
            {
              role: 'assistant',
              text:
                'I could not reach the backend. Please check that the FastAPI server is running and try again.',
              timestamp: new Date(),
            },
          ]);
          this.isSending.set(false);
        },
      });
  }

  protected onEnter(event: Event): void {
    const keyboardEvent = event as KeyboardEvent;

    if (!keyboardEvent.shiftKey) {
      keyboardEvent.preventDefault();
      this.sendQuestion();
    }
  }

  protected trackMessage(index: number, message: ChatMessage): string {
    return `${message.role}-${message.timestamp.getTime()}-${index}`;
  }
}
