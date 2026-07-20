async function validate(asyncFn) {
   const rceBinary = "/usr/bin/genpoc";
   try {
      // Reset
      // require("child_process").spawnSync(rceBinary, [rceBinary, "reset"]);
      await asyncFn();
   } catch (e) {
      console.error(e);
   }
   return require("fs").existsSync("/.executed");
}