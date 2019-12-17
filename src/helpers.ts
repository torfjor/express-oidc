/**
 * Ensures that the input variables are found in the environment. Throws otherwise.
 * @param vars - Environment variables to find
 * @returns The values found in the environment for `vars`
 */
export function ensureEnv(vars: string[]): string[] {
  vars.forEach(v => {
    if (!process.env[v]) throw new Error(`environment variable ${v} not set`);
  });

  return vars;
}

/**
 * Is true if running in a development environment.
 */
export const isDev = process.env.NODE_ENV === "development";
