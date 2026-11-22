import {
  createContext,
  forwardRef,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type ReactNode,
} from 'react';
import { CheckCircle, Copy, Check, WarningCircle, X, Info } from '@phosphor-icons/react';
import { useI18n } from '../lib/i18n';

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

/* ------------------------------------------------------------------ Button */

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
type ButtonSize = 'sm' | 'md';

const BUTTON_VARIANT: Record<ButtonVariant, string> = {
  primary: 'bg-brand-solid text-brand-on hover:bg-brand-solid/90 border border-transparent',
  secondary: 'bg-surface text-fg border border-line-strong hover:bg-surface-2 hover:border-line-control',
  ghost: 'text-fg-muted border border-transparent hover:bg-surface-3 hover:text-fg',
  danger: 'bg-danger-solid text-white border border-transparent hover:bg-danger-solid/90',
};
const BUTTON_SIZE: Record<ButtonSize, string> = {
  sm: 'h-7 px-2.5 text-xs gap-1.5',
  md: 'h-8 px-3 text-sm gap-2',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', icon, className, children, type = 'button', ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={cx(
        'inline-flex shrink-0 cursor-pointer items-center justify-center whitespace-nowrap rounded font-medium transition-colors motion-safe:active:scale-[0.99]',
        'disabled:pointer-events-none disabled:opacity-45',
        BUTTON_VARIANT[variant],
        BUTTON_SIZE[size],
        className,
      )}
      {...rest}
    >
      {icon && (
        <span aria-hidden="true" className="-ml-0.5 flex">
          {icon}
        </span>
      )}
      {children}
    </button>
  );
});

export function IconButton({
  label,
  icon,
  className,
  pressed,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string; icon: ReactNode; pressed?: boolean }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      aria-pressed={pressed}
      className={cx(
        'inline-flex h-7 w-7 shrink-0 cursor-pointer items-center justify-center rounded text-fg-muted transition-colors',
        'hover:bg-surface-3 hover:text-fg disabled:pointer-events-none disabled:opacity-45',
        pressed && 'bg-surface-3 text-fg',
        className,
      )}
      {...rest}
    >
      <span aria-hidden="true" className="flex">
        {icon}
      </span>
    </button>
  );
}

/* ------------------------------------------------------------------ Switch */

export function Switch({
  checked,
  onChange,
  label,
  disabled,
  describedBy,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  disabled?: boolean;
  describedBy?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      aria-describedby={describedBy}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cx(
        'relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border transition-colors',
        'disabled:cursor-not-allowed disabled:opacity-45',
        checked ? 'border-brand-solid bg-brand-solid' : 'border-line-control bg-surface-3',
      )}
    >
      <span
        aria-hidden="true"
        className={cx(
          'inline-block h-3.5 w-3.5 rounded-full transition-transform',
          checked ? 'translate-x-[17px] bg-brand-on' : 'translate-x-[2px] bg-fg-muted',
        )}
      />
    </button>
  );
}

/* ------------------------------------------------------------------ Segmented control */

/** Fill of the selected segment. Untoned segments read as a raised paper tab. */
export type SegmentTone = 'brand' | 'warn' | 'ink';
const SEGMENT_ACTIVE: Record<SegmentTone | 'plain', string> = {
  plain: 'bg-surface text-fg shadow-[0_0_0_1px_rgb(var(--line-strong))]',
  brand: 'bg-brand-solid text-brand-on',
  warn: 'bg-warn text-brand-on',
  ink: 'bg-fg text-surface',
};

export function Segmented<T extends string>({
  value,
  onChange,
  options,
  label,
  size = 'md',
}: {
  value: T;
  onChange: (v: T) => void;
  options: Array<{ value: T; label: ReactNode; icon?: ReactNode; title?: string; tone?: SegmentTone }>;
  label: string;
  size?: 'sm' | 'md';
}) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const onKey = (e: React.KeyboardEvent, i: number) => {
    const dir = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (!dir) return;
    e.preventDefault();
    const next = (i + dir + options.length) % options.length;
    refs.current[next]?.focus();
    onChange(options[next].value);
  };
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded border border-line-strong bg-surface-2 p-0.5">
      {options.map((opt, i) => {
        const active = opt.value === value;
        return (
          <button
            key={opt.value}
            ref={(el) => (refs.current[i] = el)}
            type="button"
            role="radio"
            aria-checked={active}
            tabIndex={active ? 0 : -1}
            title={opt.title}
            onClick={() => onChange(opt.value)}
            onKeyDown={(e) => onKey(e, i)}
            className={cx(
              'inline-flex cursor-pointer items-center gap-1.5 rounded-sm font-medium transition-colors',
              size === 'sm' ? 'h-6 px-2 text-2xs' : 'h-7 px-2.5 text-xs',
              active ? SEGMENT_ACTIVE[opt.tone ?? 'plain'] : 'text-fg-muted hover:bg-surface/60 hover:text-fg',
            )}
          >
            {opt.icon && (
              <span aria-hidden="true" className="flex">
                {opt.icon}
              </span>
            )}
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------ Badge */

export type Tone = 'brand' | 'warn' | 'danger' | 'info' | 'neutral';
const TONE: Record<Tone, string> = {
  brand: 'text-brand bg-brand/10 border-brand/30',
  warn: 'text-warn bg-warn/10 border-warn/30',
  danger: 'text-danger bg-danger/10 border-danger/30',
  info: 'text-info bg-info/10 border-info/30',
  neutral: 'text-fg-muted bg-surface-3 border-line-strong',
};

export function Badge({ tone = 'neutral', children, className, dot }: { tone?: Tone; children: ReactNode; className?: string; dot?: boolean }) {
  return (
    <span
      className={cx(
        'inline-flex h-5 shrink-0 items-center gap-1 whitespace-nowrap rounded-sm border px-1.5 text-2xs font-medium',
        TONE[tone],
        className,
      )}
    >
      {dot && <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-current" />}
      {children}
    </span>
  );
}

/* ------------------------------------------------------------------ Panel */

export function Panel({
  title,
  description,
  actions,
  children,
  className,
  bodyClassName,
  id,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  id?: string;
}) {
  const headingId = useId();
  return (
    <section aria-labelledby={title ? headingId : undefined} id={id} className={cx('rounded-md border border-line bg-surface', className)}>
      {(title || actions) && (
        <header className="flex min-h-11 items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <div className="min-w-0">
            {title && (
              <h2 id={headingId} className="truncate text-sm font-semibold text-fg">
                {title}
              </h2>
            )}
            {description && <p className="truncate text-xs text-fg-subtle">{description}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-1.5">{actions}</div>}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

/* ------------------------------------------------------------------ Callout */

export function Callout({ tone = 'info', title, children, action }: { tone?: Tone; title: ReactNode; children?: ReactNode; action?: ReactNode }) {
  const Icon = tone === 'danger' || tone === 'warn' ? WarningCircle : tone === 'brand' ? CheckCircle : Info;
  return (
    <div role={tone === 'danger' ? 'alert' : undefined} className={cx('flex gap-3 rounded-md border px-3.5 py-3', TONE[tone])}>
      <Icon aria-hidden="true" size={18} weight="bold" className="mt-px shrink-0" />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold">{title}</p>
        {children && <div className="mt-0.5 text-xs leading-5 text-fg-muted">{children}</div>}
      </div>
      {action && <div className="shrink-0 self-center">{action}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ Empty state / skeleton */

export function EmptyState({ icon, title, children, action }: { icon: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      <span aria-hidden="true" className="mb-3 flex h-10 w-10 items-center justify-center rounded-md border border-line bg-surface-2 text-fg-subtle">
        {icon}
      </span>
      <p className="text-sm font-semibold text-fg">{title}</p>
      {children && <p className="mt-1 max-w-sm text-xs leading-5 text-fg-subtle">{children}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <span aria-hidden="true" className={cx('block animate-pulse rounded-sm bg-surface-3', className)} />;
}

/* ------------------------------------------------------------------ Copy */

export function CopyButton({ text, label, compact }: { text: string; label?: string; compact?: boolean }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const timerRef = useRef<number | undefined>(undefined);
  const toast = useToast();
  const effectiveLabel = label ?? t('common.copy');
  const copiedLabel = t('common.copied');

  useEffect(() => {
    return () => {
      if (timerRef.current !== undefined) window.clearTimeout(timerRef.current);
    };
  }, []);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      if (timerRef.current !== undefined) window.clearTimeout(timerRef.current);
      timerRef.current = window.setTimeout(() => {
        timerRef.current = undefined;
        setCopied(false);
      }, 1500);
    } catch {
      toast.push({
        tone: 'danger',
        title: t('common.copyFailed'),
        body: t('common.copyDenied'),
      });
    }
  }, [text, toast, t]);
  const icon = copied ? <Check size={14} weight="bold" /> : <Copy size={14} />;
  if (compact) return <IconButton label={copied ? copiedLabel : effectiveLabel} icon={icon} onClick={copy} />;
  return (
    <Button size="sm" variant="ghost" icon={icon} onClick={copy}>
      {copied ? copiedLabel : effectiveLabel}
    </Button>
  );
}

/* ------------------------------------------------------------------ Field */

export function Field({
  label,
  hint,
  error,
  children,
  htmlFor,
}: {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  children: ReactNode;
  htmlFor: string;
}) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="block text-xs font-medium text-fg">
        {label}
      </label>
      {children}
      {error ? (
        <p id={`${htmlFor}-error`} className="flex items-center gap-1 text-xs text-danger">
          <WarningCircle aria-hidden="true" size={13} weight="bold" />
          {error}
        </p>
      ) : (
        hint && (
          <p id={`${htmlFor}-hint`} className="text-xs text-fg-subtle">
            {hint}
          </p>
        )
      )}
    </div>
  );
}

/** Shared look of text inputs, selects and textareas; callers set the width. */
export const inputClass =
  'rounded border border-line-control bg-surface px-2.5 text-sm text-fg placeholder:text-fg-subtle transition-colors hover:border-fg-subtle focus-visible:border-focus focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus/30 aria-[invalid=true]:border-danger';

/* ------------------------------------------------------------------ Dialog */

export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  width = 'max-w-lg',
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  const { t } = useI18n();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descId = useId();
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      dialog.showModal();
      const target = dialog.querySelector<HTMLElement>('[data-autofocus], [autofocus]');
      target?.focus();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    const handleClose = () => {
      dialog.returnValue = '';
      onCloseRef.current();
    };

    dialog.addEventListener('close', handleClose);

    // Progressive-enhancement fallback for click-outside light dismiss where `closedby` is unsupported.
    let cleanupOutside: (() => void) | undefined;
    if (!('closedBy' in HTMLDialogElement.prototype)) {
      let pressedOutside = false;
      const isOutside = (e: PointerEvent) => {
        const r = dialog.getBoundingClientRect();
        return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
      };
      const onDown = (e: PointerEvent) => {
        pressedOutside = isOutside(e);
      };
      const onUp = (e: PointerEvent) => {
        if (pressedOutside && isOutside(e)) {
          dialog.close();
        }
        pressedOutside = false;
      };
      dialog.addEventListener('pointerdown', onDown);
      dialog.addEventListener('pointerup', onUp);
      cleanupOutside = () => {
        dialog.removeEventListener('pointerdown', onDown);
        dialog.removeEventListener('pointerup', onUp);
      };
    }

    return () => {
      dialog.removeEventListener('close', handleClose);
      cleanupOutside?.();
    };
  }, []);

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby={titleId}
      aria-describedby={description ? descId : undefined}
      {...({ closedby: 'any' } as Record<string, unknown>)}
      className={cx(
        'hg-dialog m-auto w-[calc(100vw-3rem)] flex-col overflow-hidden rounded-lg border border-line-strong bg-surface p-0 shadow-overlay open:flex',
        'max-h-[calc(100vh-3rem)]',
        width,
      )}
    >
      <header className="flex shrink-0 items-start justify-between gap-4 border-b border-line px-5 py-4">
        <div>
          <h2 id={titleId} className="text-base font-semibold text-fg">
            {title}
          </h2>
          {description && (
            <div id={descId} className="mt-1 text-xs leading-5 text-fg-muted">
              {description}
            </div>
          )}
        </div>
        <IconButton label={t('common.close')} icon={<X size={16} />} onClick={() => dialogRef.current?.close()} className="-mr-1.5 -mt-0.5" />
      </header>
      {children && <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>}
      {footer && <footer className="flex shrink-0 justify-end gap-2 border-t border-line px-5 py-3">{footer}</footer>}
    </dialog>
  );
}

export function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel,
  busy,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  busy?: boolean;
}) {
  const { t } = useI18n();
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title}
      description={description}
      width="max-w-md"
      footer={
        <>
          <Button onClick={onClose} data-autofocus>
            {t('common.cancel')}
          </Button>
          <Button variant="danger" onClick={onConfirm} disabled={busy}>
            {confirmLabel}
          </Button>
        </>
      }
    />
  );
}

/* ------------------------------------------------------------------ Toasts */

interface ToastItem {
  id: number;
  tone: Tone;
  title: string;
  body?: string;
}

const ToastContext = createContext<{ push: (t: Omit<ToastItem, 'id'>) => void }>({ push: () => {} });

export function useToast() {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const { t } = useI18n();
  const [items, setItems] = useState<ToastItem[]>([]);
  const seq = useRef(0);
  const timersRef = useRef<Map<number, number>>(new Map());

  useEffect(() => {
    const timers = timersRef.current;
    return () => {
      timers.forEach((tid) => window.clearTimeout(tid));
      timers.clear();
    };
  }, []);

  const dismiss = useCallback((id: number) => {
    const tid = timersRef.current.get(id);
    if (tid !== undefined) {
      window.clearTimeout(tid);
      timersRef.current.delete(id);
    }
    setItems((all) => all.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (t: Omit<ToastItem, 'id'>) => {
      const id = ++seq.current;
      setItems((all) => [...all.slice(-3), { ...t, id }]);
      const tid = window.setTimeout(() => {
        timersRef.current.delete(id);
        dismiss(id);
      }, t.tone === 'danger' ? 7000 : 3500);
      timersRef.current.set(id, tid);
    },
    [dismiss],
  );

  const ctxValue = useMemo(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={ctxValue}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2">
        {items.map((item) => {
          const Icon = item.tone === 'danger' || item.tone === 'warn' ? WarningCircle : CheckCircle;
          return (
            <div
              key={item.id}
              role={item.tone === 'danger' ? 'alert' : 'status'}
              className="hg-toast pointer-events-auto flex gap-2.5 rounded-md border border-line-strong bg-surface px-3.5 py-3 shadow-overlay"
            >
              <Icon
                aria-hidden="true"
                size={18}
                weight="fill"
                className={cx('mt-px shrink-0', item.tone === 'danger' ? 'text-danger' : item.tone === 'warn' ? 'text-warn' : 'text-brand')}
              />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-fg">{item.title}</p>
                {item.body && <p className="mt-0.5 break-words text-xs text-fg-muted">{item.body}</p>}
              </div>
              <IconButton label={t('common.dismissNotification')} icon={<X size={14} />} onClick={() => dismiss(item.id)} className="-mr-1 -mt-1 h-6 w-6" />
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

/* ------------------------------------------------------------------ Tabs */

export function Tabs<T extends string>({
  value,
  onChange,
  tabs,
  label,
  idPrefix,
}: {
  value: T;
  onChange: (v: T) => void;
  tabs: Array<{ value: T; label: ReactNode; count?: number }>;
  label: string;
  idPrefix: string;
}) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  return (
    <div role="tablist" aria-label={label} className="flex gap-4 border-b border-line px-4">
      {tabs.map((t, i) => {
        const active = t.value === value;
        return (
          <button
            key={t.value}
            ref={(el) => (refs.current[i] = el)}
            role="tab"
            type="button"
            id={`${idPrefix}-tab-${t.value}`}
            aria-selected={active}
            aria-controls={`${idPrefix}-panel`}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(t.value)}
            onKeyDown={(e) => {
              const dir = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
              if (!dir) return;
              e.preventDefault();
              const next = (i + dir + tabs.length) % tabs.length;
              refs.current[next]?.focus();
              onChange(tabs[next].value);
            }}
            className={cx(
              '-mb-px inline-flex h-10 cursor-pointer items-center gap-1.5 border-b-2 text-xs font-medium transition-colors',
              active ? 'border-brand text-fg' : 'border-transparent text-fg-muted hover:text-fg',
            )}
          >
            {t.label}
            {t.count !== undefined && (
              <span className={cx('tabular rounded-sm px-1 text-2xs', active ? 'bg-brand/15 text-brand' : 'bg-surface-3 text-fg-subtle')}>{t.count}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="rounded-sm border border-line-strong bg-surface-2 px-1 font-mono text-2xs text-fg-muted">{children}</kbd>;
}

/* ------------------------------------------------------------------ Layout Helpers */

export function Section({ index, title, description, children }: { index: string; title: string; description?: ReactNode; children: ReactNode }) {
  return (
    <section className="grid grid-cols-1 gap-x-10 gap-y-4 border-b border-line py-7 last:border-b-0 lg:grid-cols-[260px_minmax(0,1fr)]">
      <div>
        <p className="tabular font-mono text-2xs text-fg-subtle">{index}</p>
        <h2 className="mt-1 text-sm font-semibold text-fg">{title}</h2>
        {description && <div className="mt-1.5 text-xs leading-5 text-fg-subtle">{description}</div>}
      </div>
      <div className="min-w-0">{children}</div>
    </section>
  );
}

export function RadioCard<T extends string>({
  name,
  value,
  current,
  onSelect,
  title,
  description,
  children,
  badge,
}: {
  name: string;
  value: T;
  current: T;
  onSelect: (v: T) => void;
  title: string;
  description: ReactNode;
  children?: ReactNode;
  badge?: ReactNode;
}) {
  const selected = value === current;
  const id = useId();
  return (
    <label
      htmlFor={id}
      className={cx(
        'block cursor-pointer rounded-md border px-4 py-3.5 transition-colors',
        selected ? 'border-brand bg-brand/[0.06]' : 'border-line bg-surface hover:border-line-strong',
      )}
    >
      <div className="flex items-start gap-3">
        <input id={id} type="radio" name={name} value={value} checked={selected} onChange={() => onSelect(value)} className="peer sr-only" />
        <span
          aria-hidden="true"
          className={cx(
            'mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-focus',
            selected ? 'border-brand' : 'border-line-control',
          )}
        >
          {selected && <span className="h-2 w-2 rounded-full bg-brand" />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-fg">{title}</span>
            {badge}
          </div>
          <div className="mt-0.5 text-xs leading-5 text-fg-muted">{description}</div>
          {children}
        </div>
      </div>
    </label>
  );
}
