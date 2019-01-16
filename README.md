# Intro

This project has been created for learning purposes during spare time. When analysing some Windows malware I realised it could be interesting to be able to add some custom instrumentation logic to the standard code coverage tools. Therefore, this thing is about experimenting with Frida and creating a module that allows to get code coverage information for use cases that require more than the already existing tools.

To know more about the mentioned tools(that might be more suitable for your needs), make sure to check [Lighthouse](https://github.com/gaasedelen/lighthouse). That repo includes, [frida-drcov.py](https://github.com/gaasedelen/lighthouse/tree/master/coverage/frida), which is the starting point of this project. Shout-out to its author, [yrp604](https://github.com/yrp604) and to the community maintaining Lighthouse and [Frida](https://github.com/frida/frida) for their awesome work.

This project its composed by 2 JS modules:
  * **fridacov.js**: instrumentation code to retrieve coverage information from a process. To be imported be an instrumentation script with the desired extra logic.
  * **covdump.js**: collects coverage information and generates a drcov file to be loaded with Lighthouse. To be imported by a frida tool, NodeJS bindings required(check [frida-drcov.py](https://github.com/gaasedelen/lighthouse/tree/master/coverage/frida) for python's code).

### Note

I am not an expert NodeJS/JS developer, actually I just use it with Frida. If you find any potato in the code, or any misuse of the Frida API, please let me know, as told before, the main goal of this project is to learn.

# Requirements
* Frida and NodeJS bindings.
* Your own tool using V8's runtime. ```session.enableJit()```

# Usage

## fridacov.js

Import it into your instrumentation code. This script exports a single function called **cover**, that receives the following arguments:
  * **threadList**: array of TID's to get coverage info from. Can use \['all'\] (as in [frida-drcov.py](https://github.com/gaasedelen/lighthouse/tree/master/coverage/frida))
  * **whitelist**: list of module names. Basic blocks from other modules will be discarded. Also accepts \['all'\].
  * **interceptNew**: follow also new threads, Windows only at this moment. Defaults to false.
  * **customModules**: array of module objects. Allows to define custom modules to get coverage from. (e.g. an unpacked dll executed within the context of the unpacker process). Defaults to an empty array. **WORK IN PROGRESS**, At this moment it is just possible to get partial coverage info for this use case as looks like a good amount of basic blocks are lost at the beginning.

Code example:
```
const fridacov = require("./fridacov.js");
[..]
const threadlist = ['all'];
const moduleWhitelist = ['all'];
const intercetpNew = true;
const customModules = [{
  path: 'C:\...', // You need to provide a path to the file you are going to aply the coverage info to
    or IDA/Lighthouse will complain. Can put whatever and edit it the log file manually by the way.
  base: ptr(0xDEADBEEF),
  size: ptr(0x666),
}, {...}];

fridacov.cover(threadList, moduleWhitelist, interceptNew, customModules);

[...]
```

To make this work you will need to run [frida-compile](https://github.com/frida/frida-compile) and inject the resulting script into the desired process.

```
frida-compile instrumentationScriptRequiringFridaCov.js -o compiled.js
```
## covdump.js

Import it into your Frida tool, add the necessary code to your messaging logic and call covdump.save() to generate the log file.

```
const covdump = require('./covdump.js');
[...]
script.message.connect((message, data) => {
[...]
  } else if (message.payload.type === "bbs") {
	  console.log("[+] Receiving coverage info");
		covdump.collect(data);
			
	} else if (message.payload.type === "mmap") {
		console.log("[+] Module info received.");
		covdump.setModuleInfo(message.payload.content);
	}
});
[...]
covdump.save();
```
