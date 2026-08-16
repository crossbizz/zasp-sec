const generatedClientMessage =
  "Use the generated API client from apps/web/api/client.ts instead of raw Fetch.";
const ambientFetchNames = new Set(["fetch"]);
const ambientGlobalNames = new Set(["globalThis", "window", "self"]);

function unwrapChain(node) {
  return node?.type === "ChainExpression" ? node.expression : node;
}

function staticPropertyName(node) {
  const property = node.type === "Property" ? node.key : node.property;
  if (!node.computed && property.type === "Identifier") {
    return property.name;
  }
  if (node.computed && property.type === "Literal" && typeof property.value === "string") {
    return property.value;
  }
  return undefined;
}

function referenceFor(sourceCode, node) {
  for (let scope = sourceCode.getScope(node); scope; scope = scope.upper) {
    for (const reference of [...scope.references, ...scope.through]) {
      if (reference.identifier === node) {
        return reference;
      }
    }
  }
  return undefined;
}

function isAmbientIdentifier(sourceCode, value, names) {
  const node = unwrapChain(value);
  if (node?.type !== "Identifier" || !names.has(node.name)) {
    return false;
  }
  const reference = referenceFor(sourceCode, node);
  return Boolean(reference && (!reference.resolved || reference.resolved.defs.length === 0));
}

function isAmbientFetchMember(sourceCode, node) {
  return (
    staticPropertyName(node) === "fetch" &&
    isAmbientIdentifier(sourceCode, node.object, ambientGlobalNames)
  );
}

function destructuresAmbientFetch(sourceCode, pattern, value) {
  const node = unwrapChain(value);
  return (
    pattern?.type === "ObjectPattern" &&
    isAmbientIdentifier(sourceCode, node, ambientGlobalNames) &&
    pattern.properties.some(
      (property) => property.type === "Property" && staticPropertyName(property) === "fetch",
    )
  );
}

const noRawFetchRule = {
  meta: {
    type: "problem",
    docs: {
      description: "Require normal frontend requests to use the generated API client.",
    },
    schema: [],
    messages: {
      useGeneratedClient: generatedClientMessage,
    },
  },
  create(context) {
    const { sourceCode } = context;
    return {
      Identifier(node) {
        if (isAmbientIdentifier(sourceCode, node, ambientFetchNames)) {
          context.report({ node, messageId: "useGeneratedClient" });
        }
      },
      MemberExpression(node) {
        if (isAmbientFetchMember(sourceCode, node)) {
          context.report({ node, messageId: "useGeneratedClient" });
        }
      },
      VariableDeclarator(node) {
        if (destructuresAmbientFetch(sourceCode, node.id, node.init)) {
          context.report({ node, messageId: "useGeneratedClient" });
        }
      },
      AssignmentExpression(node) {
        if (destructuresAmbientFetch(sourceCode, node.left, node.right)) {
          context.report({ node, messageId: "useGeneratedClient" });
        }
      },
    };
  },
};

export default noRawFetchRule;
