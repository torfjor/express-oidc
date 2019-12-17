/**
 * Ensures that the input variables are found in the environment. Throws otherwise.
 * @param vars - Environment variables to find
 * @returns The values found in the environment for `vars`
 */
export function ensureEnv(vars: string[]): string[] {
  const values = vars.map(k => {
    const val = process.env[k];

    if (!val) {
      throw new Error(`environment variable ${k} not set`);
    }

    return val;
  });

  return values;
}

/**
 * Is true if running in a development environment.
 */
export const isDev = process.env.NODE_ENV === "development";
