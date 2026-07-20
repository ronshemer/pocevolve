import {OpenAI} from "openai";
import OpenAIModel from "./openai.js";

export default class OpenRouterModel extends OpenAIModel {
   constructor(modelName, modelOptions) {
      super(modelName, modelOptions);
      this.openai = new OpenAI({
         baseURL: "https://openrouter.ai/api/v1",
         apiKey: process.env.OPENROUTER_API_KEY,
      });
   }
}
