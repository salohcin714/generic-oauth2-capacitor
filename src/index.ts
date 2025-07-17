import { registerPlugin } from '@capacitor/core';

import type { GenericOAuth2Plugin } from './definitions.js';

const GenericOAuth2 = registerPlugin<GenericOAuth2Plugin>('GenericOAuth2', {
  web: () => import('./web.js').then(m => new m.GenericOAuth2Web()),
});

export * from './definitions.js';
export { GenericOAuth2 };
