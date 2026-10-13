// Analysis helper: evaluate each fixture's recover_* result inside an empty vm
// context (no require/process/network) to obtain the parsed descriptor object.
const vm=require('vm'), fs=require('fs'), path=require('path');
const out={};
for (const f of process.argv.slice(2)) {
  try {
    const ctx=vm.createContext({});
    vm.runInContext(fs.readFileSync(f,'utf8'),ctx,{timeout:2000});
    const name=Object.keys(ctx).find(k=>k.startsWith('recover_'));
    out[path.basename(f)]=vm.runInContext('eval("("+'+name+'()+")")',ctx,{timeout:2000});
  } catch(e){ out[path.basename(f)]={__error:String(e)}; }
}
process.stdout.write(JSON.stringify(out));
