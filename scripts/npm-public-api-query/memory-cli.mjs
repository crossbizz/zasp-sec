import { observeHostedMemory } from '../hosted-memory-observation.mjs';
try { const value=await observeHostedMemory(); process.stdout.write(JSON.stringify(value)+'\n'); } catch { process.stderr.write('host memory observation refused\n'); process.exitCode=1; }
