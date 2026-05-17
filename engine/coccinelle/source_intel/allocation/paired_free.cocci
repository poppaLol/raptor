// paired_free.cocci — fire when an allocator return is freed within
// the SAME function (alloc-then-free pairing).
//
// Pattern:
//   E = alloc_fn(...);
//   ... when != E = ...
//   free_fn(E);
//
// Where the cocci `when != E = ...` excludes intervening
// reassignment (which would make the free target a different
// allocation).
//
// INFORMATIONAL only: emits `alloc_paired:<allocator>:<free_fn>`
// at the alloc-site location. Stage D LLM reads as
// "this allocation IS freed in-function". Useful negative
// signal for CodeQL cpp/memory-leak findings — when the same
// alloc-site IS paired, the leak claim is suspect.
//
// Why not verdict-active for memory-leak suppression: a paired
// free in cocci means "we found A free in the function" — not
// "every error path frees correctly". Real leak detection
// requires CFG-level all-paths-covered reasoning. Cocci can
// detect SOME pairing; absence isn't necessarily a leak (could
// be ownership-transfer via return / out-param / global store).

@paired_alloc_kfree@
expression E;
identifier alloc_fn = {
    kmalloc, kzalloc, kmalloc_array, kcalloc, krealloc,
    kvmalloc, kvzalloc, vmalloc, vzalloc,
    kstrdup, kstrdup_const, kstrndup,
    kmemdup, kmemdup_nul, kmalloc_node, kzalloc_node
};
position p;
@@
E = alloc_fn@p(...);
... when != E = ...
kfree(E);

@script:python@
p << paired_alloc_kfree.p;
alloc_fn << paired_alloc_kfree.alloc_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "paired_free",
        "message": "alloc_paired:" + str(alloc_fn) + ":kfree",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@paired_alloc_vfree@
expression E;
identifier alloc_fn = { vmalloc, vzalloc };
position p;
@@
E = alloc_fn@p(...);
... when != E = ...
vfree(E);

@script:python@
p << paired_alloc_vfree.p;
alloc_fn << paired_alloc_vfree.alloc_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "paired_free",
        "message": "alloc_paired:" + str(alloc_fn) + ":vfree",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@paired_alloc_kvfree@
expression E;
identifier alloc_fn = { kvmalloc, kvzalloc };
position p;
@@
E = alloc_fn@p(...);
... when != E = ...
kvfree(E);

@script:python@
p << paired_alloc_kvfree.p;
alloc_fn << paired_alloc_kvfree.alloc_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "paired_free",
        "message": "alloc_paired:" + str(alloc_fn) + ":kvfree",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")


@paired_alloc_free@
expression E;
identifier alloc_fn = { malloc, calloc, realloc, strdup, strndup };
position p;
@@
E = alloc_fn@p(...);
... when != E = ...
free(E);

@script:python@
p << paired_alloc_free.p;
alloc_fn << paired_alloc_free.alloc_fn;
@@
import json, sys
for _p in p:
    _m = {
        "file": _p.file,
        "line": int(_p.line),
        "rule": "paired_free",
        "message": "alloc_paired:" + str(alloc_fn) + ":free",
    }
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
