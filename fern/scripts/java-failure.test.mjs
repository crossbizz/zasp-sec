import assert from "node:assert/strict";
import test from "node:test";
import { javaFailure } from "./java-failure.mjs";

test("diagnoses Maven transfer errors without publishing repository URLs", () => {
  assert.equal(javaFailure("Could not transfer artifact from https://private.example: status code: 503"),
    "Maven artifact transfer HTTP 503");
  assert.equal(javaFailure("Could not transfer artifact: connection reset"), "Maven artifact transfer");
  assert.equal(javaFailure("Could not find artifact example:library:jar:1.0"), "Maven artifact unavailable");
  assert.equal(javaFailure("maven-exceptions/PluginResolutionException"), "Maven dependency resolution");
});

test("identifies compiler and JUnit locations without publishing local paths or payloads", () => {
  assert.equal(javaFailure("[ERROR] /private/runner/src/main/java/Finding.java:[102,18] incompatible types"),
    "compiler Finding.java:102");
  assert.equal(javaFailure("<<< FAILURE!\n at ai.zasp.api.SmokeTest.listsFindings(SmokeTest.java:144)"),
    "JUnit SmokeTest.java:144");
  assert.equal(javaFailure("\x1b[31m[ERROR]\x1b[0m There are test failures"), "JUnit failure");
  assert.equal(javaFailure("Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.13.0:compile"),
    "Maven compiler compile");
  assert.equal(javaFailure("No space left on device"), "disk full");
  assert.equal(javaFailure("java.lang.OutOfMemoryError: Java heap space"), "memory exhausted");
});

test("only reports diagnostics from the Java step", () => {
  assert.equal(javaFailure("Could not transfer artifact\n== java: compile and test\nUnable to start mvn: ENOENT"),
    "Maven executable missing");
  assert.equal(javaFailure("Unknown private build failure"), "see Maven output");
});
