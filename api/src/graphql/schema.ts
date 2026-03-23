export const typeDefs = `#graphql
  type Finding {
    line: Int!
    type: String!
    value: String!
    confidence: Float
  }

  type ScanResult {
    findings: [Finding!]!
  }

  type SecretKeys {
    keys: [String!]!
  }

  type SecretValue {
    value: String!
  }

  type Query {
    health: String
    secretKeys(env: String!): SecretKeys
    secret(env: String!, key: String!): SecretValue
  }

  type ValidationResult {
    live: Boolean
    checkedAt: String!
    error: String
  }

  type Mutation {
    scan(content: String!, filename: String): ScanResult
    setSecret(env: String!, key: String!, value: String!): String
    rotateSecret(env: String!, key: String!): String
    validateSecret(type: String!, value: String!): ValidationResult
  }
`;
