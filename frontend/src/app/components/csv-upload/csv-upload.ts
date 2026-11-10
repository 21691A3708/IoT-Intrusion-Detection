import { Component, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api, CsvUploadResponse } from '../../services/api';

@Component({
  selector: 'app-csv-upload',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './csv-upload.html',
  styleUrl: './csv-upload.scss',
})
export class CsvUpload implements OnDestroy {
  selectedFile: File | null = null;
  uploading = false;

  errorMessage = '';
  successMessage = '';

  result: CsvUploadResponse | null = null;

  elapsedSeconds = 0;
  processingTimeSeconds = 0;

  private timer: ReturnType<typeof setInterval> | null = null;
  private startTime = 0;

  constructor(
    private api: Api,
    private cdr: ChangeDetectorRef,
  ) {}

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0] ?? null;

    this.errorMessage = '';
    this.successMessage = '';
    this.result = null;
    this.elapsedSeconds = 0;
    this.processingTimeSeconds = 0;

    if (!file) {
      this.selectedFile = null;
      return;
    }

    if (!file.name.toLowerCase().endsWith('.csv')) {
      this.selectedFile = null;
      this.errorMessage = 'Please select a valid CSV file.';
      input.value = '';
      return;
    }

    this.selectedFile = file;
  }

  uploadFile(): void {
    if (!this.selectedFile || this.uploading) {
      return;
    }

    this.uploading = true;
    this.errorMessage = '';
    this.successMessage = '';
    this.result = null;
    this.elapsedSeconds = 0;
    this.processingTimeSeconds = 0;

    this.startTime = Date.now();

    this.stopTimer();

    this.timer = setInterval(() => {
      this.elapsedSeconds = Math.floor((Date.now() - this.startTime) / 1000);

      this.cdr.detectChanges();
    }, 1000);

    this.api.uploadCsv(this.selectedFile).subscribe({
      next: (response: CsvUploadResponse) => {
        this.processingTimeSeconds = Math.floor((Date.now() - this.startTime) / 1000);

        this.stopTimer();

        this.result = response;
        this.successMessage = response.message;
        this.uploading = false;

        this.cdr.detectChanges();
      },

      error: (error) => {
        this.processingTimeSeconds = Math.floor((Date.now() - this.startTime) / 1000);

        this.stopTimer();

        this.errorMessage =
          error?.error?.detail ||
          error?.message ||
          'CSV upload failed. Please check the backend and try again.';

        this.uploading = false;

        this.cdr.detectChanges();
      },
    });
  }

  get elapsedTimeText(): string {
    const minutes = Math.floor(this.elapsedSeconds / 60);
    const seconds = this.elapsedSeconds % 60;

    return minutes > 0 ? `${minutes} min ${seconds} sec` : `${seconds} sec`;
  }

  get processingTimeText(): string {
    const minutes = Math.floor(this.processingTimeSeconds / 60);
    const seconds = this.processingTimeSeconds % 60;

    return minutes > 0 ? `${minutes} min ${seconds} sec` : `${seconds} sec`;
  }

  private stopTimer(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  resetUpload(): void {
    if (this.uploading) {
      return;
    }

    this.selectedFile = null;
    this.result = null;
    this.errorMessage = '';
    this.successMessage = '';
    this.elapsedSeconds = 0;
    this.processingTimeSeconds = 0;

    this.cdr.detectChanges();
  }

  ngOnDestroy(): void {
    this.stopTimer();
  }
}
