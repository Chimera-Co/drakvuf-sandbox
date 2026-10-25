import csv,json,sys,collections,hashlib,os
from pathlib import Path
os.environ['PYTHONDONTWRITEBYTECODE']='1'
sys.path.insert(0,str(Path.cwd()/'classifier/deploy'))
import model,featurize as fz
import sys
root=Path(sys.argv[1])  # e.g. /var/lib/chimera-dataset-benign-v3 (or a read-only copy)
rows=list(csv.DictReader((root/'index.csv').open()))
print('index_rows',len(rows),'os',dict(collections.Counter(r['guest_os'] for r in rows)),'status',dict(collections.Counter(r['status'] for r in rows)))
print('unique_sha',len(set(r['sha256'] for r in rows)),'unique_family',len(set(r['family'] for r in rows)))
meta=json.loads(Path('classifier/deploy/meta.json').read_text()); vocab=meta['api_vocabulary']
print('meta', {k:meta[k] for k in ['training','thresholds','min_hooked_calls']})
stats=collections.Counter(); dup=collections.defaultdict(list); examples=[]; preds=collections.Counter()
for row in rows:
 p=root/row['path']/'features.json'
 if not p.exists(): stats['missing_features']+=1;continue
 f=json.loads(p.read_text()); osname=row['guest_os']; stats[osname+'_features']+=1
 raw=fz.hooked_call_count(f); used=fz.hooked_call_count(f,vocab)
 for key,flag in [('raw_lt10',raw<10),('used_lt10',used<10),('raw_ge10_used_zero',raw>=10 and used==0),('incomplete',not f.get('run',{}).get('complete',True))]:
  if flag:stats[osname+'_'+key]+=1
 vector=fz.vectorize(f,meta['feature_names'],vocab); dup[hashlib.sha256(json.dumps(vector).encode()).hexdigest()].append((row['family'],row['guest_os']))
 if osname=='windows':
  v=model.classify(f,str(p.parent));preds[v['label']]+=1
  if raw>=10 and used==0:examples.append({'path':str(p.relative_to(root)),'raw':raw,'used':used,'verdict':v})
print('feature_stats',dict(stats));print('windows_predictions',dict(preds))
print('duplicate_vector_clusters', [v for v in dup.values() if len(v)>1])
print('zero_examples',json.dumps(examples))
f=json.loads(Path('classifier/fixtures/bginfo-96f7ee81-features.json').read_text()); f['api_calls']={'LdrLoadDll':10};f['api_sequence']=['LdrLoadDll']*10
print('synthetic_loader_only',json.dumps(model.classify(f,'.')))
print('training_data_present',Path('classifier/data').exists())
