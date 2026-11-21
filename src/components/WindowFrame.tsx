import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Desktop, Minus, Moon, Square, SquaresFour, Sun, X } from '@phosphor-icons/react';
import logoMark from '../assets/logo-mark.png';

type ResizeDir = 'n' | 's' | 'e' | 'w' | 'nw' | 'ne' | 'sw' | 'se';

export type ColorSchemePref = 'system' | 'light' | 'dark';

declare global {
  interface Window {
    __HIDE_GO_NATIVE__?: boolean;
    __hideGoMaximized?: boolean;
    __hideGoWin?: {
      isNative: boolean;
      drag: () => void;
      minimize: () => void;
      toggleMaximize: () => void;
      close: () => void;
      resize: (dir: ResizeDir) => void;
    };
  }
}

const STORAGE_KEY = 'hide-go-color-scheme';

function readStoredScheme(): ColorSchemePref {
  try {
    const val = localStorage.getItem(STORAGE_KEY);
    if (val === 'light' || val === 'dark') return val;
  } catch {
    /* ignore */
  }
  return 'system';
}

function applySchemeMeta(pref: ColorSchemePref) {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="color-scheme"]');
  if (meta) {
    meta.content = pref === 'system' ? 'light dark' : pref;
  }
}

export function useColorScheme(): {
  pref: ColorSchemePref;
  resolved: 'light' | 'dark';
  toggle: () => void;
  setPref: (next: ColorSchemePref) => void;
} {
  const [pref, setPrefState] = useState<ColorSchemePref>(readStoredScheme);
  const [sysDark, setSysDark] = useState<boolean>(() =>
    typeof window !== 'undefined' ? window.matchMedia('(prefers-color-scheme: dark)').matches : false,
  );

  useEffect(() => {
    applySchemeMeta(pref);
  }, [pref]);

  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onMq = (e: MediaQueryListEvent) => setSysDark(e.matches);
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY) {
        setPrefState(readStoredScheme());
      }
    };
    mq.addEventListener('change', onMq);
    window.addEventListener('storage', onStorage);
    return () => {
      mq.removeEventListener('change', onMq);
      window.removeEventListener('storage', onStorage);
    };
  }, []);

  const resolved: 'light' | 'dark' = pref === 'system' ? (sysDark ? 'dark' : 'light') : pref;

  const setPref = useCallback((next: ColorSchemePref) => {
    setPrefState(next);
    try {
      if (next === 'system') {
        localStorage.removeItem(STORAGE_KEY);
      } else {
        localStorage.setItem(STORAGE_KEY, next);
      }
    } catch {
      /* ignore */
    }
  }, []);

  // Two-state space-constrained toggle matching modern-web-guidance `dark-mode-toggle`:
  // toggles between rendered scheme inverse (stored literally) and reverting to System when target matches OS.
  const toggle = useCallback(() => {
    const target: 'light' | 'dark' = resolved === 'dark' ? 'light' : 'dark';
    const currentSys: 'light' | 'dark' = sysDark ? 'dark' : 'light';
    setPref(target === currentSys ? 'system' : target);
  }, [resolved, sysDark, setPref]);

  return { pref, resolved, toggle, setPref };
}

export function ThemeToggle() {
  const { pref, resolved, toggle } = useColorScheme();
  const label =
    pref === 'system'
      ? `跟随系统（当前${resolved === 'dark' ? '深色' : '浅色'}），点击切换主题`
      : pref === 'dark'
        ? '当前深色主题，点击切换'
        : '当前浅色主题，点击切换';

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={label}
      title={label}
      className="inline-flex h-7 cursor-pointer items-center gap-1.5 rounded px-2 text-2xs font-medium text-fg-muted transition-colors hover:bg-surface-3 hover:text-fg"
    >
      <span aria-hidden="true" className="flex text-fg">
        {pref === 'system' ? (
          <Desktop size={13} weight="duotone" />
        ) : resolved === 'dark' ? (
          <Moon size={13} weight="fill" />
        ) : (
          <Sun size={13} weight="fill" />
        )}
      </span>
      <span className="max-[1020px]:hidden">
        {pref === 'system' ? '自动' : pref === 'dark' ? '深色' : '浅色'}
      </span>
    </button>
  );
}

const RESIZE_EDGES: Array<{ dir: ResizeDir; className: string }> = [
  { dir: 'n', className: 'inset-x-2 top-0 h-1 cursor-ns-resize' },
  { dir: 's', className: 'inset-x-2 bottom-0 h-1 cursor-ns-resize' },
  { dir: 'w', className: 'inset-y-2 left-0 w-1 cursor-ew-resize' },
  { dir: 'e', className: 'inset-y-2 right-0 w-1 cursor-ew-resize' },
  { dir: 'nw', className: 'left-0 top-0 h-2.5 w-2.5 cursor-nwse-resize' },
  { dir: 'ne', className: 'right-0 top-0 h-2.5 w-2.5 cursor-nesw-resize' },
  { dir: 'sw', className: 'bottom-0 left-0 h-2.5 w-2.5 cursor-nesw-resize' },
  { dir: 'se', className: 'bottom-0 right-0 h-2.5 w-2.5 cursor-nwse-resize' },
];

export function WindowFrame({
  title,
  badge,
  resizable = true,
  minWidthClass = 'min-w-[820px]',
  statusSlot,
  children,
}: {
  title: string;
  badge?: string;
  resizable?: boolean;
  minWidthClass?: string;
  statusSlot?: ReactNode;
  children: ReactNode;
}) {
  const win = typeof window !== 'undefined' ? window.__hideGoWin : undefined;
  const isNative = Boolean(win?.isNative);
  const [maximized, setMaximized] = useState<boolean>(() => Boolean(typeof window !== 'undefined' && window.__hideGoMaximized));

  useEffect(() => {
    const onMax = (e: Event) => {
      const custom = e as CustomEvent<boolean>;
      setMaximized(Boolean(custom.detail));
    };
    window.addEventListener('hidego-maximized', onMax);
    return () => window.removeEventListener('hidego-maximized', onMax);
  }, []);

  const handleDragStart = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!isNative || e.button !== 0) return;
    if ((e.target as HTMLElement).closest('button, a, input, select, [data-no-drag="true"]')) return;
    if (e.detail === 2 && resizable) {
      win?.toggleMaximize();
      return;
    }
    win?.drag();
  };

  return (
    <div
      className={`hg-window-frame relative flex h-full w-full flex-col overflow-hidden bg-bg text-fg ${minWidthClass} ${
        !maximized ? 'border border-line-strong' : ''
      }`}
    >
      {/* Frameless edge/corner resize grips when running in native desktop WebView */}
      {isNative && resizable && !maximized && (
        <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-[80]">
          {RESIZE_EDGES.map((edge) => (
            <div
              key={edge.dir}
              onPointerDown={(e) => {
                if (e.button !== 0) return;
                e.preventDefault();
                e.stopPropagation();
                win?.resize(edge.dir);
              }}
              className={`pointer-events-auto absolute ${edge.className}`}
            />
          ))}
        </div>
      )}

      {/* Custom Native-Style Window Chrome */}
      <div
        onPointerDown={handleDragStart}
        className="flex h-10 shrink-0 select-none items-center justify-between gap-3 border-b border-line bg-surface/95 pl-3.5 pr-0 backdrop-blur-sm"
      >
        <div className="flex min-w-0 items-center gap-2.5">
          <img src={logoMark} alt="" className="h-[18px] w-[18px] shrink-0" />
          <span className="truncate text-xs font-semibold tracking-tight text-fg">{title}</span>
          {badge && (
            <span className="tabular rounded-sm border border-line bg-surface-2 px-1.5 py-px font-mono text-2xs text-fg-subtle">
              {badge}
            </span>
          )}
          {statusSlot}
        </div>

        {/* Center drag target */}
        <div className="h-full flex-1" />

        <div className="relative z-[85] flex h-full shrink-0 items-center" data-no-drag="true">
          <div className={isNative ? 'mr-1.5 flex items-center' : 'pr-2 flex items-center'}>
            <ThemeToggle />
          </div>
          {isNative && (
            <>
              <span aria-hidden="true" className="h-4 w-px bg-line" />
              <button
                type="button"
                aria-label="最小化窗口"
                title="最小化"
                onClick={() => win?.minimize()}
                className="inline-flex h-full w-11 cursor-pointer items-center justify-center text-fg-muted transition-colors hover:bg-surface-3 hover:text-fg"
              >
                <Minus aria-hidden="true" size={14} weight="bold" />
              </button>
              {resizable && (
                <button
                  type="button"
                  aria-label={maximized ? '还原窗口大小' : '最大化窗口'}
                  title={maximized ? '还原' : '最大化'}
                  onClick={() => win?.toggleMaximize()}
                  className="inline-flex h-full w-11 cursor-pointer items-center justify-center text-fg-muted transition-colors hover:bg-surface-3 hover:text-fg"
                >
                  {maximized ? (
                    <SquaresFour aria-hidden="true" size={13} />
                  ) : (
                    <Square aria-hidden="true" size={12} weight="bold" />
                  )}
                </button>
              )}
              <button
                type="button"
                aria-label="关闭窗口"
                title="关闭"
                onClick={() => win?.close()}
                className="inline-flex h-full w-11 cursor-pointer items-center justify-center text-fg-muted transition-colors hover:bg-danger-solid hover:text-white"
              >
                <X aria-hidden="true" size={14} weight="bold" />
              </button>
            </>
          )}
        </div>
      </div>

      {/* Main viewport container */}
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">{children}</div>
    </div>
  );
}
