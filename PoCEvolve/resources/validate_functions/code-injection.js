async function validate(asyncFn) {
   let success = false;
   process.seteuid = (uid) => {
      if (uid == 42) {
         success = true;
      }
   };
   try {
      await asyncFn();
   } catch (e) {
      console.error(e);
   }
   return success;
}