const generatedClientMessage =
  "Use the generated API client from apps/web/api/client.ts instead of raw Fetch.";

function unwrapChain(node) {
  return node?.type === "ChainExpression" ? node.expression : node;
}

function staticPropertyName(node) {
  if (!node.computed && node.property.type === "Identifier") {
    return node.property.name;
  }
  if (node.computed && node.property.type === "Literal" && typeof node.property.value === "string") {
    return node.property.value;
  }
  return undefined;
}

function isFetchReference(value) {
  const node = unwrapChain(value);
  if (!node) {
    return false;
  }
  if (node.type === "Identifier") {
    return node.name === "fetch";
  }
  if (node.type !== "MemberExpression") {
    return false;
  }

  const property = staticPropertyName(node);
  if (property === "call" || property === "apply" || property === "bind") {
    return isFetchReference(node.object);
  }

  const object = unwrapChain(node.object);
  return (
    property === "fetch" &&
    object?.type === "Identifier" &&
    (object.name === "globalThis" || object.name === "window" || object.name === "self")
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
    return {
      CallExpression(node) {
        if (isFetchReference(node.callee)) {
          context.report({ node, messageId: "useGeneratedClient" });
        }
      },
    };
  },
};

export default noRawFetchRule;
