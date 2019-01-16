/*
 *
 *	Frida coverage module.
 *
 *	Heavily based on frida_cov.py, with some improvements like new thread tracking
 * 	and the possibility to define "custom" modules to cover(e.g. unpacked modules).
 *	
 *	Use it as a module of your JS intrumentation code.
 *
 *	V8's runtime required (session.enableJit()) to use latest JS syntax and features.
 *
 */

"use strict";
// TODO get rid of globals if possible.
let targetModules;
/*
 *	Generates an array with the information about the process's modules. Removes non whitelisted modules.
 *	Also adds custom modules defined by the user.
 */
const makeMaps = (custom, whitelist) => {
	//	TODO Improve that so just whitelisted and custom modules are included in headers.
	let modules = Process.enumerateModulesSync();
	let i = 0;
	
	const maps = modules.filter((mod, index, array) => {
		return whitelist.indexOf('all') >= 0 || whitelist.indexOf(mod.name) >= 0;
	});

	// Add id and end addr to map (drcov file format).
	maps.map((o) => {o.id = i++;});
	maps.map((o) => {o.end = o.base.add(o.size);});

	if (custom.length > 0) {
		for (let entry of custom) {
			//console.log("[COV]: Adding custom module.");
			//console.log(JSON.stringify(entry));
			maps.push({
				id: i++,
				path: entry.path,
				base: entry.base,
				end: entry.base.add(entry.size),
				size: entry.size,
				name: `custom-mod${custom.indexOf(entry) + 1}`
			});
		}
	}

	console.log("[FRCOV]: Collecting coverage data from the following modules:");
	for (let m of maps) {
		console.log(JSON.stringify(m));
	}

	return maps;
};

const drcov_bbs = (bbs) => {
	/*
		DRCOV data structure.
		
		typedef struct _bb_entry_t {
			uint start;
			ushort size;
			ushort mod_id;
		} bb_entry_t;
	*/
	console.log(`[FRCOV]: ${bbs.length} blocks received.`);
	const entry_size = 8;
	const bb = new ArrayBuffer(entry_size * bbs.length);
	let num_entries = 0;

	for( let i = 0; i < bbs.length; i++) {
		const e = bbs[i];
		//console.log(JSON.stringify(e));
		const start = e[0];
		const end = e[1];
		const mod_id = getBbModuleId(start);
		
		if (mod_id < 0) {
			continue;
		}

		const mod_info = targetModules[mod_id];
		const offset = start.sub(mod_info.base).toInt32();
		const size = end.sub(start).toInt32();
		//console.log(`[COV]: Adding bb info: ${offset}, ${size}, ${mod_id}.`);
		const x = new Uint32Array(bb, num_entries * entry_size, 1);
		// bb_entry_t -> start ...
		x[0] = offset;
		const y = new Uint16Array(bb, num_entries * entry_size + 4, 2);
		y[0] = size;
		y[1] = mod_id;

		num_entries++;
	}

	return new Uint8Array(bb, 0, num_entries * entry_size);
};

/**
 *	Main function of the module. Sets everything up to collect coverage information.
 *	@func
 *	@param {array} threadList - List of thread id's to follow.
 *	@param {array} whitelist - List of modules to get coverage from.
 *	@param {boolean} intercetpNew - (Windows only) Set it to true to get coverage info from new threads.
 *	@param {array} customModules - Array of objects representing non ordinary modules you want to retrieve coverage info from, e.g. unpacked code.
 */
const cover = (threadList, whitelist, interceptNew = false, customModules = []) => {
	targetModules = makeMaps(customModules, whitelist);
	send({type: 'mmap', content: targetModules});

	Stalker.trustThreshold = 0;
	console.log("[COV] Starting Stalkers.");

	if (interceptNew) {
		coverNewThreads();
	}

	Process.enumerateThreads({
		onMatch: (thread) => {
			if (threadList.indexOf(thread.id) < 0 &&
				threadList.indexOf('all') < 0) {
				return;
			}
			stalkThread(thread.id);
		},
		onComplete: () => { console.log("[FRCOV] Done stalking threads."); }
	});
};

/*
 *	Adds coverage of new threads.
 *	
 *	TODO Multi OS support?
 */
const coverNewThreads = () => {
	const pCreateThread = Module.findExportByName('kernel32.dll', 'CreateThread');

	Interceptor.attach(pCreateThread, {
		onEnter: (args) => {
			console.log(`[FRCOV]: Waiting for new thread to start at ${args[2]}.`);
			interceptStartAddress(ptr(args[2]));
		},
		onLeave: (retval) => {}
	});
};

/*
 *	Sets a hook that will be triggered by the execution of new threads.
 */
const interceptStartAddress = (addr) => {
	Interceptor.attach(addr, {
		onEnter: (args) => {
			console.log(`[FRCOV]: Thread ${Process.getCurrentThreadId()} started. (${addr})`);
			stalkThread(Process.getCurrentThreadId());
		},
		onLeave: (retval) => {}
	});
};

/*
 *	Sets a stalker to collect coverage information from a thread.
 */
const stalkThread = (tid) => {
	console.log(`[FRCOV]: Stalking thread ${tid}.`);
	
	Stalker.follow(tid, {
		events: {
			compile: true
		},

		onReceive: (event) => {
			const bb_events = Stalker.parse(event, {stringify: false, annotate: false});
			const bbs = drcov_bbs(bb_events);
			send({type: 'bbs'}, bbs);
		}
	});
};

/**
 *	Receives an address, if the module this address belongs to needs to be covered returns module's id.
 *	Otherwise returns -1.
 */
const getBbModuleId = (startAddress) => {
	for (let mod of targetModules) {
		if (mod.base.toInt32() <= startAddress.toInt32() && mod.end.toInt32() >= startAddress) {
			//console.log(`[FRCOV]: ${mod.name}, start ${mod.base}, end ${mod.end}, evaluated address ${startAddress}`);
			return mod.id;
		}
	}
	return -1;
};

exports.cover = cover;