import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '../index.css';
import { ColorSchemeProvider } from '../components/WindowFrame';
import { I18nProvider } from '../lib/i18n';
import { SetupApp } from './SetupApp';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <I18nProvider>
      <ColorSchemeProvider>
        <SetupApp />
      </ColorSchemeProvider>
    </I18nProvider>
  </StrictMode>,
);
