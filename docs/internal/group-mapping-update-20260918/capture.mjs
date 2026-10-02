import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
const root='/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917';
const names=execFileSync('git',['ls-files','--cached','--others','--exclude-standard','services/platform/apiserver','services/platform/agentsec-api','services/platform/migrations'],{cwd:root,encoding:'utf8'}).trim().split('\n');
process.stdout.write(execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}));
for(const name of [...new Set(names)].sort())process.stdout.write(crypto.createHash('sha256').update(fs.readFileSync(path.join(root,name))).digest('hex')+'  '+name+'\n');
