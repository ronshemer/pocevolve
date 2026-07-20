import {readFileSync} from "node:fs";
import {PipelineRunner} from "./pipeline.js";

export class VfcPipelineRunner extends PipelineRunner {
   #vfcRecords;

   /**
    * @param {object} opts
    * @param {string} opts.vfcDataPath - Path to vfcs.predicted.json
    * @param {string[]} [opts.advisoryIds] - Advisory IDs to filter by; if empty, all records are run
    */
   constructor(opts) {
      super(opts);
      this.#vfcRecords = JSON.parse(readFileSync(opts.vfcDataPath, "utf-8"));
   }

   #resolveAdvisoryId(record) {
      return record.ids?.[0] ?? null;
   }

   #matchesFilter(record) {
      if (!this.advisoryIds?.length) return true;
      return record.ids?.some(id => this.advisoryIds.includes(id)) ?? false;
   }

   async start() {
      const records = this.#vfcRecords
         .filter(record => this.#matchesFilter(record))
         .slice(this.offset, this.offset + this.limit);

      const total = records.filter(r => this.#resolveAdvisoryId(r)).length;
      console.log(`Running ${total} VFC records`);
      let i = 0;
      for (const record of records) {
         const advisoryId = this.#resolveAdvisoryId(record);
         if (!advisoryId) {
            console.warn(`Skipping ${record.vulnerable_package}@${record.vulnerable_version}: no ids field`);
            continue;
         }
         console.log(`[${++i}/${total}] ${record.vulnerable_package}@${record.vulnerable_version} → ${advisoryId}`);
         await super.spawn({
            ...this.opts,
            advisoryId,
            vfcRecord: record,
            packageName: `${record.vulnerable_package}@${record.vulnerable_version}`,
            description: record.generated?.potential_vulnerability?.vulnerability_description ?? record.advisory_descriptions.join("\n\n"),
            vulnerabilityTypeLabel: record.generated?.potential_vulnerability?.potential_vulnerability_type ?? null,
         });
      }
      this.onFinish();
   }
}
