import { registerPlugin } from '@capacitor/core';
const GenericOAuth2 = registerPlugin('GenericOAuth2', {
    web: () => import('./web.js').then(m => new m.GenericOAuth2Web()),
});
export * from './definitions.js';
export { GenericOAuth2 };
//# sourceMappingURL=index.js.map