const args = process.argv.slice(2);

export const jsonMode =
	args.includes("--json") || (!process.stdout.isTTY && !args.includes("--pretty"));

export function output(data: unknown): void {
	console.log(JSON.stringify(data, null, jsonMode ? undefined : 2));
}

export function outputError(message: string, exitCode = 1): never {
	if (jsonMode) {
		console.error(JSON.stringify({ error: message }));
	} else {
		console.error(`Error: ${message}`);
	}
	process.exit(exitCode);
}

export function log(message: string): void {
	if (!jsonMode) {
		process.stderr.write(`${message}\n`);
	}
}

export function logInline(message: string): void {
	if (!jsonMode) {
		process.stderr.write(message);
	}
}
