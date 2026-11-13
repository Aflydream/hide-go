import {
  createContext,
  forwardRef,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type ReactNode,
} from 'react';
import { CheckCircle, Copy, Check, WarningCircle, X, Info } from '@phosphor-icons/react';

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
        'inline-flex shrink-0 items-center justify-center whitespace-nowrap rounded font-medium transition-colors',
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
        'inline-flex h-7 w-7 shrink-0 items-center justify-center rounded text-fg-muted transition-colors',
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
        'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors',
        'disabled:cursor-not-allowed disabled:opacity-45',
        checked ? 'border-brand-solid bg-brand-solid' : 'border-line-control bg-surface-3',
      )}
    >
      <span
        aria-hidden="true"
        className={cx(
          'inline-block h-3.5 w-3.5 rounded-full transition-transform',
          checked ? 'translate-x-[18px] bg-brand-on' : 'translate-x-[2px] bg-fg-muted',
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
              'inline-flex items-center gap-1.5 rounded-sm font-medium transition-colors',
              size === 'sm' ? 'h-6 px-2 text-2xs' : 'h-7 px-2.5 text-xs',
              active ? SEGMENT_ACTIVE[opt.tone ?? 'plain'] : 'text-fg-muted hover:text-fg',
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
        <header className="flex min-h-11 items-center justify-between gap-3 border-b border-line px-4 py-2">
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

export function CopyButton({ text, label = '复制', compact }: { text: string; label?: string; compact?: boolean }) {
  const [copied, setCopied] = useState(false);
  const toast = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.push({ tone: 'danger', title: '复制失败', body: '浏览器拒绝了剪贴板访问' });
    }
  };
  const icon = copied ? <Check size={14} weight="bold" /> : <Copy size={14} />;
  if (compact) return <IconButton label={copied ? '已复制' : label} icon={icon} onClick={copy} />;
  return (
    <Button size="sm" variant="ghost" icon={icon} onClick={copy}>
      {copied ? '已复制' : label}
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
  const panel = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const descId = useId();
  // Callers pass inline closures that change on every poll-driven render; reading the latest
  // one through a ref keeps the focus trap from re-running (and stealing focus) each time.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const focusables = () =>
      Array.from(
        panel.current?.querySelectorAll<HTMLElement>('button:not([disabled]), [href], input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])') ?? [],
      );
    (panel.current?.querySelector<HTMLElement>('[data-autofocus]') ?? focusables()[0])?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onCloseRef.current();
      } else if (e.key === 'Tab') {
        const items = focusables();
        if (!items.length) return;
        const first = items[0];
        const last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', onKey, true);
    return () => {
      document.removeEventListener('keydown', onKey, true);
      previous?.focus();
    };
  }, [open]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-6">
      <div aria-hidden="true" className="absolute inset-0 bg-fg/45" onClick={onClose} />
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descId : undefined}
        className={cx('relative flex max-h-full w-full flex-col rounded-lg bg-surface shadow-overlay', width)}
      >
        <header className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
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
          <IconButton label="关闭" icon={<X size={16} />} onClick={onClose} className="-mr-1.5 -mt-0.5" />
        </header>
        {children && <div className="min-h-0 overflow-y-auto px-5 py-4">{children}</div>}
        {footer && <footer className="flex justify-end gap-2 border-t border-line px-5 py-3">{footer}</footer>}
      </div>
    </div>
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
            取消
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
  const [items, setItems] = useState<ToastItem[]>([]);
  const seq = useRef(0);
  const dismiss = useCallback((id: number) => setItems((all) => all.filter((t) => t.id !== id)), []);
  const push = useCallback(
    (t: Omit<ToastItem, 'id'>) => {
      const id = ++seq.current;
      setItems((all) => [...all.slice(-3), { ...t, id }]);
      window.setTimeout(() => dismiss(id), t.tone === 'danger' ? 7000 : 3500);
    },
    [dismiss],
  );
  return (
    <ToastContext.Provider value={{ push }}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2">
        {items.map((t) => {
          const Icon = t.tone === 'danger' || t.tone === 'warn' ? WarningCircle : CheckCircle;
          return (
            <div
              key={t.id}
              role={t.tone === 'danger' ? 'alert' : 'status'}
              className="pointer-events-auto flex gap-2.5 rounded-md bg-surface px-3.5 py-3 shadow-overlay"
            >
              <Icon
                aria-hidden="true"
                size={18}
                weight="fill"
                className={cx('mt-px shrink-0', t.tone === 'danger' ? 'text-danger' : t.tone === 'warn' ? 'text-warn' : 'text-brand')}
              />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-fg">{t.title}</p>
                {t.body && <p className="mt-0.5 break-words text-xs text-fg-muted">{t.body}</p>}
              </div>
              <IconButton label="关闭通知" icon={<X size={14} />} onClick={() => dismiss(t.id)} className="-mr-1 -mt-1 h-6 w-6" />
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
              '-mb-px inline-flex h-10 items-center gap-1.5 border-b-2 text-xs font-medium transition-colors',
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
