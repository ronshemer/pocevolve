async function validate(exploit) {
   try {
      delete Object.prototype.exploited;
      await exploit();
   } catch (e) {
      console.error(e);
   }
   return "exploited" in Object.prototype;
}