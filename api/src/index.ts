import express from "express";
import cors from "cors";
import { ApolloServer } from "@apollo/server";
import { expressMiddleware } from "@apollo/server/express4";
import { typeDefs } from "./graphql/schema.js";
import { resolvers } from "./graphql/resolvers.js";
import { authMiddleware, proxyToDetection, proxyToVault } from "./middleware.js";

const DETECTION_URL = process.env.DETECTION_URL ?? "http://localhost:8000";
const VAULT_URL = process.env.VAULT_URL ?? "http://localhost:3000";
const PORT = Number(process.env.PORT) || 4000;

const app = express();
app.use(cors());
app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use(authMiddleware);

app.use("/api/scan", proxyToDetection(DETECTION_URL));
app.use("/api/vault", proxyToVault(VAULT_URL));

const server = new ApolloServer({ typeDefs, resolvers });
await server.start();
app.use("/graphql", expressMiddleware(server));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SecretSentinel API gateway listening on ${PORT}`);
});
