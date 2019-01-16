/*
 *	FridaCov coverage dumper for Frida command line tools (for NodeJS bindings ofc).
 * 	
 *	NOTE: If you prefer to use python bindings see the code at frida_cov.py, from the Lighthouse repo.
 *
 *	Collects basic block information retrieved by the instrumentation code and generates a DRCOV format
 *	coverage file that you can load into Lighthouse.
 *	
 *	Note that you'll need to implement the message handling logic into your Frida tool.
 *
 */
"use strict";

const fs = require('fs');

const modules = [];
const bbs = new Set([]);
const blockSize = 8;

const createHeader = () => {
	let header = '';
	header += `DRCOV VERSION: 2\n`;
	header += `DRCOV FLAVOR: frida\n`;
	header += `Module Table: version 2, count ${modules.length}\n`;
	header += `Columns: id, base, end, entry, checksum, timestamp, path\n`;
	
	const entries = [];

	for (let i = 0; i < modules.length; i++) {
		const m = modules[i];
		const entry = `${m.id}, ${m.base}, ${m.end}, 0, 0, 0, ${m.path}`;
		entries.push(entry);
	}

	header += entries.join('\n') + '\n';

	return Buffer.from(header, 'utf8');
};

const createCoverage = () => {
	let header = `BB Table: ${bbs.size} bbs\n`;
	const octets = [];

	for (let bb of bbs) {
		for (let octet of bb) {
			octets.push(octet);
		}
	}

	const rawBbs = Buffer.from(octets);
	header = Buffer.from(header, 'utf8');
	console.log(rawBbs);
	const covBody = Buffer.concat([header, rawBbs], header.length + rawBbs.length);

	return covBody;
};

/*
 *	Writtes the coverage info into a drcov format file.
 */
const save = () => {
	
	
	const header = createHeader();
	const body = createCoverage();
	const contents = Buffer.concat([header, body], header.length + body.length);

	try {
		fs.writeFileSync('./drcov.log', contents, {flag:'w+'});
	} catch (err) {
		console.error(err);
	}
};

/*
 *	Retrieves coverage data from the instrumented process, removing duplicates.
 */
const collect = (data) => {
	
	let rawData;

	try {
		rawData = new Uint8Array(data);
	} catch (e) {
		//console.error(e);
		return;
	}
	
	console.log(`[COVDUMP]: Collecting ${rawData.length / blockSize} basic blocks.`);
	
	for (let i = 0; i < rawData.length; i += blockSize) {
		bbs.add(rawData.slice(i, i + blockSize));
	}
};

/*
 *	Stores information about the modules loaded by the instrumented process, needed to generate drcov files.
 */
const setModuleInfo = (modulesInfo) => {

	for (let i = 0; i < modulesInfo.length; i++) {
		const m = modulesInfo[i];
		const modEntry = {
			id: m.id,
			path: m.path,
			base: parseInt(m.base, 16),
			end: parseInt(m.end, 16),
			size: m.size
		};

		modules.push(modEntry);
	}
}

exports.save = save;
exports.collect = collect;
exports.setModuleInfo = setModuleInfo;