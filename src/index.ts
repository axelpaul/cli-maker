#!/usr/bin/env bun

import { authProfile } from "./commands/auth-profile.ts";
import { scanJs } from "./commands/scan-js.ts";
import { sniff } from "./commands/sniff.ts";
import { jsonMode, output, outputError } from "./lib/output.ts";

const COMMANDS = [
	{
		name: "sniff",
		description: "Capture API calls while browsing a website",
		args: [
			{ name: "--url", required: true, description: "Target URL to sniff" },
			{ name: "--capture-bodies", required: false, description: "Capture response bodies" },
			{ name: "--allow-domain", required: false, description: "Only capture from these domains (repeatable)" },
			{ name: "--block-domain", required: false, description: "Block additional domains (repeatable)" },
			{ name: "--output", required: false, description: "Write spec to file instead of stdout" },
			{ name: "--headless", required: false, description: "Run browser in headless mode" },
		],
	},
	{
		name: "auth-profile",
		description: "Analyze a website's authentication mechanism",
		args: [
			{ name: "--url", required: true, description: "Target URL to analyze" },
			{ name: "--output", required: false, description: "Write profile to file instead of stdout" },
			{ name: "--headless", required: false, description: "Run browser in headless mode" },
		],
	},
	{
		name: "scan-js",
		description: "Scan JS bundles for API paths and endpoints",
		args: [
			{ name: "--url", required: true, description: "Target URL to scan" },
			{ name: "--output", required: false, description: "Write results to file instead of stdout" },
		],
	},
];

// ─── Arg parsing helpers ────────────────────────────────────────

const args = process.argv.slice(2);

function getFlag(name: string): string | null {
	const index = args.indexOf(name);
	if (index === -1 || index + 1 >= args.length) return null;
	return args[index + 1]!;
}

function getAllFlags(name: string): string[] {
	const values: string[] = [];
	for (let i = 0; i < args.length; i++) {
		if (args[i] === name && i + 1 < args.length) {
			values.push(args[i + 1]!);
			i++;
		}
	}
	return values;
}

function hasFlag(name: string): boolean {
	return args.includes(name);
}

// ─── Help ───────────────────────────────────────────────────────

function showHelp(): void {
	if (jsonMode) {
		output({ name: "cli-maker", version: "0.1.0", commands: COMMANDS });
		return;
	}

	console.log(`cli-maker v0.1.0 - Reverse-engineer website APIs and generate CLIs

Usage: cli-maker <command> [options]

Commands:
  sniff          Capture API calls while browsing a website
  auth-profile   Analyze a website's authentication mechanism
  scan-js        Scan JS bundles for API paths and endpoints

Global flags:
  --json         Force JSON output
  --pretty       Force human-readable output
  --help, -h     Show this help

Examples:
  cli-maker sniff --url https://example.com
  cli-maker auth-profile --url https://example.com
  cli-maker scan-js --url https://example.com --output spec.json`);
}

// ─── Command routing ────────────────────────────────────────────

const command = args.find((a) => !a.startsWith("-"));

try {
	switch (command) {
		case "sniff":
			await sniff({
				url: getFlag("--url") ?? "",
				captureBodies: hasFlag("--capture-bodies"),
				allowDomains: getAllFlags("--allow-domain"),
				blockDomains: getAllFlags("--block-domain"),
				outputFile: getFlag("--output"),
				headless: hasFlag("--headless"),
			});
			break;

		case "auth-profile":
			await authProfile({
				url: getFlag("--url") ?? "",
				outputFile: getFlag("--output"),
				headless: hasFlag("--headless"),
			});
			break;

		case "scan-js":
			await scanJs({
				url: getFlag("--url") ?? "",
				outputFile: getFlag("--output"),
			});
			break;

		case "help":
		case undefined:
			if (hasFlag("--help") || hasFlag("-h") || !command) {
				showHelp();
			} else {
				showHelp();
			}
			break;

		default:
			outputError(`Unknown command: ${command}. Run 'cli-maker help' for usage.`);
	}
} catch (err) {
	if (err instanceof Error) {
		outputError(err.message);
	}
	outputError(String(err));
}
