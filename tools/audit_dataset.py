#!/usr/bin/env python3
import argparse, collections, hashlib, json, re, sys, zipfile
from pathlib import Path
def sha256(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
def norm(s): return re.sub(r"\s+"," ",s.strip()).casefold() if isinstance(s,str) else None
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--archive",required=True);ap.add_argument("--out",default="audit-output");a=ap.parse_args()
 archive=Path(a.archive);out=Path(a.out);out.mkdir(parents=True,exist_ok=True);root=out/"extracted";root.mkdir(exist_ok=True)
 r={"archive":archive.name,"archive_bytes":archive.stat().st_size,"archive_sha256":sha256(archive),"checks":{},"metrics":{},"warnings":[],"errors":[],"files":[]}
 try:
  with zipfile.ZipFile(archive) as z:
   bad=z.testzip();r["checks"]["zip_crc"]="PASS" if bad is None else "FAIL"
   if bad:r["errors"].append("ZIP CRC failure: "+bad)
   names=z.namelist();r["metrics"]["zip_member_count"]=len(names);r["metrics"]["zip_uncompressed_bytes"]=sum(x.file_size for x in z.infolist())
   for n in names:
    p=Path(n)
    if p.is_absolute() or ".." in p.parts:r["errors"].append("Unsafe ZIP path: "+n)
   if not r["errors"]:z.extractall(root)
 except Exception as e:r["checks"]["zip_crc"]="FAIL";r["errors"].append("ZIP extraction failed: "+repr(e))
 files=sorted(p for p in root.rglob("*") if p.is_file());r["files"]=[str(p.relative_to(root)) for p in files];r["metrics"]["extracted_file_count"]=len(files)
 candidates=[p for p in files if p.name=="kandoo_intent_dataset_v0.2.jsonl"]
 if not candidates:candidates=[p for p in files if p.suffix==".jsonl" and "batch" not in str(p).lower()]
 dataset=candidates[0] if len(candidates)==1 else None
 if dataset is None:r["errors"].append("Expected one final JSONL; found "+str(len(candidates)))
 records=[]
 if dataset:
  bad=[];raw=dataset.read_text(encoding="utf-8-sig").splitlines()
  for n,line in enumerate(raw,1):
   if line.strip():
    try:
     x=json.loads(line)
     if not isinstance(x,dict):raise ValueError("record is not object")
     records.append(x)
    except Exception as e:bad.append({"line":n,"error":str(e)})
  r["metrics"].update({"dataset_path":str(dataset.relative_to(root)),"dataset_nonempty_lines":sum(bool(x.strip()) for x in raw),"record_count":len(records),"jsonl_parse_errors":len(bad)})
  r["checks"]["jsonl_parse"]="PASS" if not bad else "FAIL"
  if bad:r["errors"].append("JSONL parse errors: "+json.dumps(bad[:10],ensure_ascii=False))
 schemas=[p for p in files if p.name.endswith(".schema.json") or ("schema" in p.parts and p.suffix==".json")]
 if records and schemas:
  try:
   import jsonschema
   s=json.loads(schemas[0].read_text(encoding="utf-8"));cls=jsonschema.validators.validator_for(s);cls.check_schema(s);v=cls(s);fail=[]
   for i,x in enumerate(records,1):
    e=next(v.iter_errors(x),None)
    if e:fail.append({"line":i,"path":list(e.absolute_path),"message":e.message})
   r["metrics"]["schema_validation"]={"schema":str(schemas[0].relative_to(root)),"records":len(records),"errors":len(fail),"sample":fail[:10]}
   r["checks"]["json_schema"]="PASS" if not fail else "FAIL"
   if fail:r["errors"].append("Schema validation failures: "+str(len(fail)))
  except Exception as e:r["checks"]["json_schema"]="ERROR";r["warnings"].append("Schema validation error: "+repr(e))
 else:r["checks"]["json_schema"]="NOT_RUN";r["warnings"].append("No schema or parsed records.")
 if records:
  ids=[];texts=collections.defaultdict(set);st=collections.defaultdict(set);intents=collections.Counter();splits=collections.Counter();reviews=collections.Counter();clarify=collections.Counter();multi=0
  def strings(o):
   if isinstance(o,dict):
    for k,v in o.items():
     if isinstance(v,str):yield k,v
     else:yield from strings(v)
   elif isinstance(o,list):
    for v in o:yield from strings(v)
  for i,x in enumerate(records,1):
   rid=x.get("id",x.get("record_id"))
   if rid is not None:ids.append(str(rid))
   sp=str(x.get("split",x.get("dataset_split","UNSPECIFIED"))).upper();splits[sp]+=1;reviews[str(x.get("review_status","MISSING"))]+=1;clarify[str(x.get("needs_clarification","MISSING"))]+=1
   arr=x.get("intents")
   if isinstance(arr,list):
    ns=[y.get("intent") or y.get("name") for y in arr if isinstance(y,dict)];multi+=len(ns)>1;intents.update(y for y in ns if y)
   elif x.get("intent"):intents[str(x["intent"])]+=1
   for k,val in strings(x):
    if k.lower() in {"text","utterance","message","query","user_input"} and norm(val):texts[norm(val)].add(i);st[norm(val)].add(sp)
  dupid=len(ids)-len(set(ids));leak=sum(len(v)>1 for v in st.values())
  r["metrics"].update({"unique_ids":len(set(ids)),"duplicate_ids":dupid,"duplicate_normalized_utterances":sum(len(v)>1 for v in texts.values()),"cross_split_exact_utterance_leakage":leak,"split_counts":dict(splits),"intent_counts":dict(intents),"review_status_counts":dict(reviews),"clarification_counts":dict(clarify),"multi_intent_records":multi})
  r["checks"]["record_ids_unique"]="PASS" if ids and not dupid else "FAIL";r["checks"]["cross_split_exact_text_leakage"]="PASS" if not leak else "FAIL"
  if dupid:r["errors"].append("Duplicate record IDs: "+str(dupid))
  if leak:r["errors"].append("Cross-split exact utterance leakage: "+str(leak))
  if "seed_needs_review" in reviews:r["warnings"].append("Records marked seed_needs_review; automated checks are not human approval.")
  if len(records)!=398:r["warnings"].append("Record count differs from stated 398: "+str(len(records)))
 manifests=[p for p in files if p.name.lower() in {"manifest-sha256.txt","manifest.sha256","sha256sums.txt"}]
 if manifests:
  checked=0;missing=[];mismatch=[];malformed=[]
  for line in manifests[0].read_text(encoding="utf-8-sig").splitlines():
   line=line.strip()
   if not line or line.startswith("#"):continue
   m=re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$",line)
   if not m:malformed.append(line);continue
   expected,rel=m.groups();target=root/rel
   if not target.is_file():
    matches=list(root.rglob(Path(rel).name));target=matches[0] if len(matches)==1 else target
   if not target.is_file():missing.append(rel)
   elif sha256(target).lower()!=expected.lower():mismatch.append(rel)
   else:checked+=1
  r["metrics"]["manifest"]={"checked":checked,"missing":missing,"mismatched":mismatch,"malformed":malformed};r["checks"]["sha256_manifest"]="PASS" if checked and not missing and not mismatch and not malformed else "FAIL"
  if missing or mismatch or malformed:r["errors"].append("SHA-256 manifest verification failed.")
 else:r["checks"]["sha256_manifest"]="NOT_FOUND";r["warnings"].append("SHA-256 manifest not found.")
 batches=sorted(p for p in files if any(part.lower().startswith("batch") for part in p.parts) and p.suffix==".jsonl")
 if dataset and batches:
  exact=b"".join(p.read_bytes() for p in batches)==dataset.read_bytes();r["metrics"]["batch_file_count"]=len(batches);r["checks"]["batch_reconstruction_byte_exact"]="PASS" if exact else "FAIL"
  if not exact:
   try:
    br=[]
    for p in batches:br.extend(json.loads(x) for x in p.read_text(encoding="utf-8-sig").splitlines() if x.strip())
    r["metrics"]["batch_record_equivalent"]=br==records
   except Exception as e:r["metrics"]["batch_record_equivalent"]=repr(e)
 else:r["checks"]["batch_reconstruction_byte_exact"]="NOT_RUN";r["warnings"].append("Dataset or batch files not found.")
 r["overall"]="FAIL" if r["errors"] or "FAIL" in r["checks"].values() else ("PASS_WITH_WARNINGS" if r["warnings"] or any(v!="PASS" for v in r["checks"].values()) else "PASS")
 (out/"audit-report.json").write_text(json.dumps(r,ensure_ascii=False,indent=2),encoding="utf-8")
 lines=["# Independent Kandoo Dataset v0.2 Audit","","Overall: "+r["overall"],"","Archive SHA-256: "+r["archive_sha256"],"Extracted files: "+str(len(files)),"Records: "+str(r["metrics"].get("record_count","N/A")),"","## Checks",""]+[f"- {k}: **{v}**" for k,v in r["checks"].items()]
 lines+=["","## Metrics","",json.dumps(r["metrics"],ensure_ascii=False,indent=2),"","## Warnings",""]+["- "+x for x in r["warnings"]]+["","## Errors",""]+["- "+x for x in r["errors"]]+["","## Files",""]+["- "+x for x in r["files"]]
 (out/"audit-report.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
 print(json.dumps({"overall":r["overall"],"checks":r["checks"],"metrics":r["metrics"],"warnings":r["warnings"],"errors":r["errors"]},ensure_ascii=False,indent=2))
 sys.exit(1 if r["overall"]=="FAIL" else 0)
if __name__=="__main__":main()
