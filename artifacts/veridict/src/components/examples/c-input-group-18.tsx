import { useRef, useState, type FormEvent } from 'react';
import { FileText, Globe2, Plus, Send, X } from 'lucide-react';
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupTextarea } from '@/components/ui/input-group';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';

export type LumioAttachment =
  | { type: 'url'; value: string }
  | { type: 'email'; file: File };

type Props = {
  message: string;
  attachment: LumioAttachment | null;
  disabled?: boolean;
  onMessageChange: (message: string) => void;
  onAttachmentChange: (attachment: LumioAttachment | null) => void;
  onSubmit: (message: string, attachment: LumioAttachment) => void;
  onError: (message: string) => void;
};

const MAX_EMAIL_BYTES = 10 * 1024 * 1024;

function safeUrlLabel(value: string) {
  const trimmed = value.trim();
  try {
    const parsed = new URL(/^[a-z]+:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    return `${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}`;
  } catch {
    return trimmed.split(/[?#]/, 1)[0];
  }
}

export function CInputGroup18({
  message,
  attachment,
  disabled = false,
  onMessageChange,
  onAttachmentChange,
  onSubmit,
  onError,
}: Props) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [attachDialogOpen, setAttachDialogOpen] = useState(false);
  const [urlView, setUrlView] = useState(false);
  const [urlDraft, setUrlDraft] = useState('');
  const [urlError, setUrlError] = useState('');
  const [fileError, setFileError] = useState('');

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!attachment) {
      onError('Attach one public URL or one .eml file before sending.');
      return;
    }
    if (attachment.type === 'url') {
      const target = attachment.value.trim();
      if (!target || /[\r\n]/.test(target) || target.length > 2048) {
        onError('Attach one URL or public domain under 2,048 characters.');
        return;
      }
    }
    onError('');
    onSubmit(message, attachment);
  }

  function attachUrl(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = urlDraft.trim();
    if (!value) { setUrlError('Enter one public URL or domain.'); return; }
    if (value.length > 2048) { setUrlError('Use a URL or domain under 2,048 characters.'); return; }
    if (/[\r\n]/.test(value)) { setUrlError('Enter one URL or domain on a single line.'); return; }
    onAttachmentChange({ type: 'url', value });
    setUrlError('');
    setAttachDialogOpen(false);
    setUrlView(false);
    setUrlDraft('');
    onError('');
  }

  function chooseFile(file: File | undefined) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.eml')) {
      const message = 'This analyzer accepts .eml files only. Choose a file ending in .eml.';
      setFileError(message);
      onError(message);
      return;
    }
    if (file.size > MAX_EMAIL_BYTES) {
      const message = 'The selected .eml file is larger than the 10 MB limit.';
      setFileError(message);
      onError(message);
      return;
    }
    setFileError('');
    onAttachmentChange({ type: 'email', file });
    onError('');
    setAttachDialogOpen(false);
    setUrlView(false);
  }

  return (
    <>
      <form onSubmit={submit} className="mx-auto w-full max-w-3xl" data-testid="form-conversation-composer">
        <label htmlFor="conversation-note" className="sr-only">Optional note or context for this investigation</label>
        <InputGroup className="min-h-32 flex-col items-stretch rounded-xl bg-background px-1">
          {attachment && <InputGroupAddon align="block-start" className="justify-start border-b border-border px-3 py-2">
            <span className="inline-flex max-w-full items-center gap-2 rounded-md border border-border bg-muted/40 px-2.5 py-1.5 text-xs text-foreground" data-testid="chip-investigation-attachment">
              {attachment.type === 'url' ? <Globe2 className="size-3.5 shrink-0" aria-hidden="true" /> : <FileText className="size-3.5 shrink-0" aria-hidden="true" />}
              <span className="max-w-[min(60vw,24rem)] truncate">{attachment.type === 'url' ? safeUrlLabel(attachment.value) : attachment.file.name}</span>
              {attachment.type === 'email' && <span className="shrink-0 text-muted-foreground">{(attachment.file.size / 1024 / 1024).toFixed(2)} MB</span>}
              <button type="button" aria-label="Remove attachment" onClick={() => onAttachmentChange(null)} disabled={disabled} className="ml-1 inline-flex size-6 items-center justify-center rounded hover:bg-muted disabled:opacity-50" data-testid="button-remove-attachment"><X className="size-3.5" aria-hidden="true" /></button>
            </span>
          </InputGroupAddon>}
          <InputGroupTextarea
            id="conversation-note"
            rows={2}
            maxLength={1200}
            value={message}
            disabled={disabled}
            onChange={(event) => { onMessageChange(event.target.value); onError(''); }}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                event.currentTarget.form?.requestSubmit();
              }
            }}
            placeholder="Add an optional note or question for Lumio. Avoid private details."
            aria-describedby="composer-note-help"
            data-testid="input-conversation-note"
            className="min-h-16 px-3 py-3"
          />
          <InputGroupAddon align="block-end" className="justify-between border-t border-border px-2 py-2">
            <InputGroupButton
              type="button"
              aria-label="Attach one URL or email file"
              title="Attach one public URL or .eml file"
              onClick={() => { setAttachDialogOpen(true); setUrlView(false); }}
              disabled={disabled}
              data-testid="button-open-attachments"
              className="size-10 rounded-lg"
            ><Plus className="size-4" aria-hidden="true" /></InputGroupButton>
            <span className="mr-auto ml-2 text-[11px] text-muted-foreground">One URL or .eml attachment · optional note</span>
            <InputGroupButton
              type="submit"
              aria-label="Send for analysis"
              title="Send for analysis"
              disabled={disabled || !attachment}
              data-testid="button-send-analysis"
              className="size-10 rounded-lg bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-50"
            ><Send className="size-4" aria-hidden="true" /></InputGroupButton>
          </InputGroupAddon>
        </InputGroup>
        <p id="composer-note-help" className="mt-2 px-1 text-xs leading-5 text-muted-foreground">Optional context stays in this tab and is not sent to the scanner. Maximum 1,200 characters.</p>
      </form>
      <input ref={fileInputRef} type="file" accept=".eml" className="sr-only" aria-label="Choose one .eml file" data-testid="input-email-file" onChange={(event) => {
        const file = event.currentTarget.files?.[0];
        event.currentTarget.value = '';
        chooseFile(file);
      }} />
      <Dialog open={attachDialogOpen} onOpenChange={(open) => { setAttachDialogOpen(open); if (!open) { setUrlView(false); setUrlError(''); setFileError(''); } }}>
        <DialogContent aria-describedby="attachment-dialog-copy" data-testid="dialog-attachment-choice">
          <DialogHeader>
            <DialogTitle>{urlView ? 'Attach a public URL' : 'Add one attachment'}</DialogTitle>
            <DialogDescription id="attachment-dialog-copy">{urlView ? 'The URL is scanned separately from your optional chat note. Lumio accepts public HTTP(S) targets only.' : 'Choose exactly one URL or one .eml message. Email attachment contents are never opened.'}</DialogDescription>
          </DialogHeader>
          {urlView ? (
            <form onSubmit={attachUrl} className="space-y-2">
              <label htmlFor="attachment-url" className="text-sm font-medium">Public URL or domain</label>
              <input id="attachment-url" autoFocus type="text" inputMode="url" autoComplete="url" maxLength={2048} value={urlDraft} onChange={(event) => { setUrlDraft(event.target.value); setUrlError(''); }} placeholder="https://example.com/path" className="min-h-11 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring" data-testid="input-attachment-url" />
              {urlError && <p className="text-sm text-destructive" role="alert">{urlError}</p>}
              <DialogFooter><button type="button" onClick={() => setUrlView(false)} className="min-h-11 rounded-md border border-input px-4 text-sm font-medium hover:bg-muted">Back</button><button type="submit" className="min-h-11 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground hover:opacity-90" data-testid="button-confirm-url-attachment">Attach URL</button></DialogFooter>
            </form>
          ) : (
            <>
              <div className="grid gap-3 sm:grid-cols-2">
                <button type="button" onClick={() => { setUrlView(true); setFileError(''); }} className="flex min-h-20 items-center gap-3 rounded-lg border border-border p-4 text-left hover:bg-muted" data-testid="button-choose-url"><Globe2 className="size-5 text-muted-foreground" aria-hidden="true" /><span><span className="block text-sm font-medium">Attach a URL</span><span className="mt-1 block text-xs text-muted-foreground">Public HTTP(S) targets only</span></span></button>
                <button type="button" onClick={() => fileInputRef.current?.click()} className="flex min-h-20 items-center gap-3 rounded-lg border border-border p-4 text-left hover:bg-muted" data-testid="button-choose-eml"><FileText className="size-5 text-muted-foreground" aria-hidden="true" /><span><span className="block text-sm font-medium">Choose an .eml</span><span className="mt-1 block text-xs text-muted-foreground">One message, up to 10 MB</span></span></button>
              </div>
              {fileError && <p className="mt-3 text-sm text-destructive" role="alert">{fileError}</p>}
            </>
          )}
          {!urlView && <DialogFooter><button type="button" onClick={() => setAttachDialogOpen(false)} className="min-h-11 rounded-md border border-input px-4 text-sm font-medium hover:bg-muted">Close</button></DialogFooter>}
        </DialogContent>
      </Dialog>
    </>
  );
}
