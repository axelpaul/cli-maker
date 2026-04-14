import { writeFileSync } from "node:fs";
import { profileAuth } from "../lib/auth-detect.ts";
import { closeBrowser, launchBrowser, navigateTo } from "../lib/browser.ts";
import { attachInterceptor } from "../lib/interceptor.ts";
import { log, logInline, output, outputError } from "../lib/output.ts";

export interface AuthProfileOptions {
	url: string;
	outputFile: string | null;
	headless: boolean;
}

export async function authProfile(opts: AuthProfileOptions): Promise<void> {
	if (!opts.url) {
		outputError("--url is required. Usage: cli-maker auth-profile --url <url>");
	}

	log(`Opening browser at ${opts.url}...`);
	const session = await launchBrowser({ headless: opts.headless });

	// Capture bodies and include all resource types — auth flows rely on
	// document redirects (302 chains through IdPs) and script loads
	const interceptor = attachInterceptor(session.page, {
		captureBodies: true,
		noiseFilter: { includeStaticAssets: true },
	});

	try {
		await navigateTo(session.page, opts.url);
	} catch (err) {
		await closeBrowser(session);
		outputError(`Failed to navigate to ${opts.url}: ${err}`);
	}

	log("Monitoring network traffic...");
	log("Navigate to the login page and authenticate.");
	log("Press Enter when the login is complete (or close the browser).\n");

	// Wait for Enter keypress or browser close
	await new Promise<void>((resolve) => {
		let resolved = false;
		const done = () => {
			if (resolved) return;
			resolved = true;
			resolve();
		};

		process.stdin.setRawMode?.(false);
		process.stdin.resume();
		process.stdin.once("data", done);

		session.page.on("close", done);
		session.context.on("close", done);
	});

	log("Analyzing auth flow...");

	interceptor.stop();
	const exchanges = interceptor.getExchanges();

	await closeBrowser(session);

	const profile = profileAuth(exchanges);

	log(`\nAuth Profile Detected:`);
	log(`  Mechanism:  ${profile.mechanism}`);
	log(`  Confidence: ${profile.confidence}%`);

	if (profile.details.loginUrl) {
		log(`  Login URL:  ${profile.details.loginUrl}`);
	}

	if (profile.mechanism === "jwt-form-login" && profile.details.mechanism === "jwt-form-login") {
		log(`  Fields:     ${profile.details.formFields.join(", ")}`);
		log(`  Token Path: ${profile.details.tokenPath}`);
		log(`  Token Use:  ${profile.details.tokenUsage}`);
	}

	if (opts.outputFile) {
		writeFileSync(opts.outputFile, JSON.stringify(profile, null, 2));
		log(`\nProfile written to ${opts.outputFile}`);
	} else {
		output(profile);
	}
}
