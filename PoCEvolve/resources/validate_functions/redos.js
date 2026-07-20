async function validate(asyncFn) {
   const start = process.hrtime();
   try {
      await asyncFn();
      const end = process.hrtime(start);
      return end[0] * 1_000 + end[1] / 1_000_000 > 1500;
   } catch (e) {
      return e === "illegal access";
   }
}