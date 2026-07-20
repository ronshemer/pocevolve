async function validate(asyncFn) {
   return new Promise(async (resolve, reject) => {
      let success = false;
      const bindingFs = require("fs");
      for (const fName of Object.keys(bindingFs).filter(k => typeof bindingFs[k] === "function")) {
         const _origFn = bindingFs[fName];
         Object.defineProperty(bindingFs, fName, {
            get: function () {
               return function (...args) {
                  const origFileName = args[0];
                  if (typeof origFileName !== "string") {
                     return _origFn.apply(this, args);
                  }
                  console.log(`${fName}(${args.join(",")})`)
                  const normalizedFileName = require("path").normalize(origFileName);
                  if (normalizedFileName === "/flag.txt" || /(?:\.\.\/|%2f)+flag\.txt/i.test(origFileName)) {
                     resolve(true);
                  }
                  return _origFn.apply(this, args);
               };
            },
         });
      }

      try {
         await asyncFn();
         resolve(false);
      } catch (e) {
         console.error(e);
         resolve(false);
      }
   });
}