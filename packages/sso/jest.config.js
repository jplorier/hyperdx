const { createJsWithTsPreset } = require('ts-jest');

/** @type {import("jest").Config} **/
module.exports = {
  ...createJsWithTsPreset({
    // The build keeps `import('openid-client')` native; tests compile it to
    // require() so jest.mock can replace it without --experimental-vm-modules.
    tsconfig: {
      module: 'commonjs',
      moduleResolution: 'node10',
      ignoreDeprecations: '6.0',
    },
  }),
  testEnvironment: 'node',
  verbose: true,
  rootDir: './src',
  testMatch: ['**/__tests__/*.test.ts'],
};
