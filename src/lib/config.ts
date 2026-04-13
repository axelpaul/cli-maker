import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const CONFIG_DIR = join(homedir(), ".cli-maker");

function ensureDir(): void {
	if (!existsSync(CONFIG_DIR)) {
		mkdirSync(CONFIG_DIR, { recursive: true });
	}
}

export function saveSpec(filename: string, data: unknown): string {
	ensureDir();
	const path = join(CONFIG_DIR, filename);
	writeFileSync(path, JSON.stringify(data, null, 2));
	return path;
}

export function loadSpec<T>(filename: string): T | null {
	const path = join(CONFIG_DIR, filename);
	if (!existsSync(path)) return null;
	return JSON.parse(readFileSync(path, "utf-8")) as T;
}

export function getConfigDir(): string {
	ensureDir();
	return CONFIG_DIR;
}
